"""MCP Graylog Server — read-access to Lalafo Graylog via captured oauth2-proxy cookie.

See spec: docs/superpowers/specs/2026-05-10-mcp-graylog-design.md
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import csv as csv_module
import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlparse

import httpx

# Defaults (overridable via env)
DEFAULT_PORT = int(os.environ.get("GRAYLOG_MCP_PORT", "4001"))
GRAYLOG_BASE_URL = os.environ.get("GRAYLOG_BASE_URL", "https://graylog.yallasvc.net")
GRAYLOG_STATE_DIR = Path(os.environ.get("GRAYLOG_STATE_DIR", "/zeroclaw-data/mcp_graylog"))
GRAYLOG_SESSION_COOKIE_B64 = os.environ.get("GRAYLOG_SESSION_COOKIE", "")
# Graylog API token (Basic auth, username=token, password="token"). Independent
# of oauth2-proxy session cookie — both are required in this deployment because
# oauth2-proxy gates the reverse-proxy and Graylog itself authenticates the API.
GRAYLOG_API_TOKEN = os.environ.get("GRAYLOG_API_TOKEN", "")


def _api_token_header() -> dict[str, str]:
    """Return Authorization header for Graylog API token, or empty dict."""
    if not GRAYLOG_API_TOKEN:
        return {}
    encoded = base64.b64encode(f"{GRAYLOG_API_TOKEN}:token".encode()).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


class CookieAuth:
    """Single-identity cookie-based auth for oauth2-proxy in front of Graylog.

    See spec: docs/superpowers/specs/2026-05-10-mcp-graylog-design.md §4.1
    """

    def __init__(self, state_path: Path, env_cookie_b64: str):
        self._state_path = Path(state_path)
        self._env_cookie_b64 = env_cookie_b64 or ""
        self._env_fingerprint = (
            hashlib.sha256(self._env_cookie_b64.encode()).hexdigest()[:16]
            if self._env_cookie_b64 else ""
        )
        self._lock_path = self._state_path.with_suffix(".lock")
        self._cached: dict[str, str] | None = None

    def _decode_env(self) -> dict[str, str]:
        if not self._env_cookie_b64:
            return {}
        try:
            return json.loads(base64.b64decode(self._env_cookie_b64))
        except Exception:
            return {}

    def _load_or_initialize(self) -> dict[str, str]:
        """Resolve cookies source-of-truth at startup or cache miss.

        Priority (no TTL — state always wins when fingerprint matches):
        1. state.json + bootstrap_fingerprint == current env_fingerprint → use state
        2. state.json + fingerprint differs → env was rotated, delete state, use env
        3. state.json missing OR corrupt → use env, write fresh state
        4. env empty AND state missing → return {}
        """
        env_cookies = self._decode_env()

        if self._state_path.exists():
            try:
                saved = json.loads(self._state_path.read_text())
                if saved.get("bootstrap_fingerprint") == self._env_fingerprint:
                    return saved.get("cookies", {})
                # Fingerprint differs — env rotated by user
                self._state_path.unlink(missing_ok=True)
            except Exception:
                # Corrupt — fall back to env
                pass

        if not env_cookies:
            return {}

        # Bootstrap fresh state from env
        self._write_state_atomic(env_cookies, source="env_bootstrap")
        return env_cookies

    def _cookies_snapshot(self) -> dict[str, str]:
        """Return current cookies snapshot (copy, no lock needed for reads)."""
        if self._cached is None:
            self._cached = self._load_or_initialize()
        return dict(self._cached)

    def headers(self) -> dict[str, str]:
        """Return HTTP headers to inject into Graylog requests."""
        snap = self._cookies_snapshot()
        if not snap:
            return {}
        cookie_str = "; ".join(f"{k}={v}" for k, v in snap.items())
        return {"Cookie": cookie_str}

    def _write_state_atomic(self, cookies: dict[str, str], source: str) -> None:
        """Write state.json atomically (temp + rename) under fcntl.flock."""
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cookies": cookies,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "bootstrap_fingerprint": self._env_fingerprint,
            "source": source,
        }
        # Lock file (separate from data file — flock semantics on Linux)
        with open(self._lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            try:
                tmp = self._state_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(payload, indent=2))
                tmp.replace(self._state_path)
            finally:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _is_expired(cookie_morsel) -> bool:
        """True if Set-Cookie has Expires in the past (oauth2-proxy clearing cookie)."""
        expires = cookie_morsel.get("expires", "") or ""
        if not expires:
            return False
        try:
            dt = parsedate_to_datetime(expires)
            return dt < datetime.now(timezone.utc)
        except Exception:
            return False

    def absorb(self, set_cookie_headers: list[str]) -> bool:
        """Parse Set-Cookie headers; persist any oauth2-proxy* refresh.

        Last-write-wins under flock — no timestamp comparison (cookie body is
        opaque encrypted blob).
        """
        if not set_cookie_headers:
            return False

        new_cookies: dict[str, str] = {}
        for raw in set_cookie_headers:
            jar = SimpleCookie()
            try:
                jar.load(raw)
            except Exception:
                continue
            for name, morsel in jar.items():
                if not name.startswith("_oauth2_proxy"):
                    continue
                if self._is_expired(morsel):
                    continue  # oauth2-proxy clearing — don't persist
                new_cookies[name] = morsel.value

        if not new_cookies:
            return False

        # Merge with existing snapshot — keep cookies not present in this response
        current = self._cookies_snapshot()
        merged = {**current, **new_cookies}
        self._write_state_atomic(merged, source="set_cookie_capture")
        self._cached = merged
        try:
            get_audit().log_event(
                "cookie_refreshed", source="set_cookie_capture"
            )
        except Exception:
            pass  # don't break absorb on audit failures
        return True

    def write_cookies(self, cookies: dict[str, str]) -> None:
        """Atomically write a full cookie dict from silent SSO refresh.

        Unlike absorb(), which parses raw Set-Cookie headers from oauth2-proxy
        callback responses, this method accepts an already-parsed cookie dict
        (the harvest output of silent_sso_refresh). REPLACES all _oauth2_proxy*
        shards with the new set — does not preserve stale shards from previous
        session shape.
        """
        if not cookies:
            return
        current = self._cookies_snapshot()
        # Drop any existing _oauth2_proxy* shards — silent SSO's harvest is authoritative
        merged = {k: v for k, v in current.items() if not k.startswith("_oauth2_proxy")}
        merged.update(cookies)
        self._write_state_atomic(merged, source="silent_sso_write")
        self._cached = merged
        try:
            get_audit().log_event("cookie_refreshed", source="silent_sso_write")
        except Exception:
            pass


class SessionExpired(Exception):
    """Raised when oauth2-proxy returns sign-in HTML response."""


class MSSessionAuth:
    """Microsoft Entra session cookies for silent SSO refresh.

    Mirrors CookieAuth pattern: env blob bootstraps state file at first run,
    rolling refresh (via absorb()) updates the file on every successful silent SSO.

    Bootstrap fingerprint logic:
    - self._bootstrap_fingerprint = sha256(env_blob)[:16], set ONCE in __init__.
    - State file records this fingerprint. On startup, fingerprint match → use state.
    - Fingerprint mismatch → operator re-bootstrapped → drop state, use env.

    CRITICAL: absorb() must NOT mutate self._bootstrap_fingerprint. The fingerprint
    identifies the bootstrap secret, not the current persistent-cookie value.
    Rotating ESTSAUTHPERSISTENT via absorb() does NOT trigger re-bootstrap on next start.
    """

    STATUS_DEGRADED = "degraded"
    STATUS_HEALTHY = "healthy"
    STATUS_EXPIRED = "expired"

    def __init__(self, state_path: Path, env_cookie_b64: str):
        self._state_path = Path(state_path)
        self._env_cookie_b64 = env_cookie_b64 or ""
        self._bootstrap_fingerprint = (
            hashlib.sha256(self._env_cookie_b64.encode()).hexdigest()[:16]
            if self._env_cookie_b64 else ""
        )
        self._lock_path = self._state_path.with_suffix(".lock")
        self._cookies: dict[str, str] = {}
        self.status = self.STATUS_DEGRADED  # set below by _load_or_initialize
        self._last_diagnosis: str | None = None
        self._load_or_initialize()

    @property
    def bootstrap_fingerprint(self) -> str:
        """Immutable fingerprint of the bootstrap env blob (NOT current persistent cookie)."""
        return self._bootstrap_fingerprint

    @property
    def current_persistent_fingerprint(self) -> str:
        """Fingerprint of the CURRENT ESTSAUTHPERSISTENT value (changes on absorb)."""
        val = self._cookies.get("ESTSAUTHPERSISTENT", "")
        return hashlib.sha256(val[:128].encode()).hexdigest()[:16] if val else ""

    @property
    def last_diagnosis(self) -> str | None:
        return self._last_diagnosis

    def cookies(self) -> dict[str, str]:
        """Return a copy of current cookies (read-only snapshot)."""
        return dict(self._cookies)

    def _decode_env(self) -> dict[str, str]:
        if not self._env_cookie_b64:
            return {}
        try:
            decoded = json.loads(base64.b64decode(self._env_cookie_b64))
        except Exception:
            return {}
        flat: dict[str, str] = {}
        for domain_map in decoded.get("microsoft_session", {}).values():
            for name, info in domain_map.items():
                value = info["value"] if isinstance(info, dict) else info
                if value:
                    flat[name] = value
        return flat

    def _load_or_initialize(self) -> None:
        env_cookies = self._decode_env()

        if self._state_path.exists():
            try:
                saved = json.loads(self._state_path.read_text())
                if saved.get("bootstrap_fingerprint") == self._bootstrap_fingerprint:
                    self._cookies = saved.get("cookies", {})
                    if self._cookies:
                        self.status = self.STATUS_HEALTHY
                        return
                else:
                    # operator re-bootstrapped → ignore stale state
                    self._state_path.unlink(missing_ok=True)
            except Exception:
                pass  # corrupt → fall through to env

        if env_cookies:
            self._cookies = env_cookies
            self.status = self.STATUS_HEALTHY
            self._write_state_atomic(source="env_bootstrap")
            return

        self._cookies = {}
        self.status = self.STATUS_DEGRADED
        try:
            get_audit().log_event("ms_session_missing", reason="no_env_no_state")
        except Exception:
            pass

    def absorb(self, refreshed: dict[str, str]) -> None:
        """Merge refreshed cookies from Microsoft Set-Cookie headers.

        Bootstrap fingerprint MUST NOT change here (see class docstring).
        """
        if not refreshed:
            return
        merged = {**self._cookies, **refreshed}
        self._cookies = merged
        self._write_state_atomic(source="absorb")

    def mark_expired(self, diagnosis: str) -> None:
        self.status = self.STATUS_EXPIRED
        self._last_diagnosis = diagnosis
        try:
            get_audit().log_event("ms_session_expired", diagnosis=diagnosis)
        except Exception:
            pass

    def mark_healthy(self) -> None:
        """Recovery transition called after a successful refresh on previously-expired state."""
        self.status = self.STATUS_HEALTHY
        self._last_diagnosis = None

    def _write_state_atomic(self, source: str) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cookies": self._cookies,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "bootstrap_fingerprint": self._bootstrap_fingerprint,
            "source": source,
        }
        with open(self._lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            try:
                tmp = self._state_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(payload, indent=2))
                tmp.replace(self._state_path)
            finally:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)


class MSSessionExpired(Exception):
    """Raised when Microsoft silent SSO returns sign-in HTML instead of redirect."""


class SilentSSOFailure(Exception):
    """Raised on network/protocol errors during silent SSO that are not session expiry."""


_SILENT_SSO_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

# Cookies Microsoft refreshes on every silent SSO (verified empirically 2026-05-11).
_MS_REFRESHED_COOKIE_NAMES = {
    "ESTSAUTH", "ESTSAUTHLIGHT", "ESTSAUTHPERSISTENT", "CCState",
    "SignInStateCookie", "buid", "fpc", "x-ms-gateway-slice",
    "AADSSO", "MSFPC", "esctx",
}


def _diagnose_microsoft_html(text: str) -> str:
    low = text.lower()
    title_start = low.find("<title>")
    title_end = low.find("</title>")
    title = text[title_start + 7:title_end].strip() if 0 <= title_start < title_end else "?"
    if "verify" in low or "authenticator" in low or "mfa" in low or "code from" in low:
        hint = "MFA challenge triggered (Conditional Access likely)"
    elif "consent" in low or "permissions requested" in low:
        hint = "Consent screen forced UI flow"
    elif "sign in" in low or "signin" in low:
        hint = "Microsoft session expired or invalid"
    else:
        hint = "Unexpected HTML response from Microsoft"
    return f"<title>{title}</title>  {hint}"


async def silent_sso_refresh(
    *, graylog_base: str, ms_session: "MSSessionAuth", cookie_auth: "CookieAuth",
) -> dict:
    """Perform 4-step silent SSO and persist results to ms_session + cookie_auth.

    Returns: dict with keys ``oauth2_proxy_cookies`` (dict[str, str]),
                            ``refreshed_ms_count`` (int).

    Raises:
        MSSessionExpired: Microsoft returned HTML instead of redirect at step 2.
                          Caller should NOT retry; ms_session.status is set to expired.
        SilentSSOFailure: Protocol violation (no Location, no code=, no _oauth2_proxy,
                          MS session has no cookies).
    """
    ms_cookies = ms_session.cookies()
    if not ms_cookies:
        raise SilentSSOFailure("ms_session has no cookies — bootstrap required")

    async with httpx.AsyncClient(
        follow_redirects=False, timeout=30, headers=_SILENT_SSO_HEADERS,
    ) as client:
        # STEP 1: trigger oauth2-proxy login
        r = await client.get(f"{graylog_base}/oauth2/start", params={"rd": "/"})
        if r.status_code != 302:
            raise SilentSSOFailure(f"step1: expected 302, got {r.status_code}")
        authorize_url = r.headers.get("location", "")
        if not authorize_url:
            raise SilentSSOFailure("step1: no Location header")

        # STEP 2: Microsoft authorize with stored cookies
        # Set cookies on the host extracted from authorize_url (works for both
        # login.microsoftonline.com in prod AND 127.0.0.1 in tests).
        ms_host = urlparse(authorize_url).hostname or "login.microsoftonline.com"
        for name, value in ms_cookies.items():
            client.cookies.set(name, value, domain=ms_host)
            # Also set on the leading-dot domain for matching real Microsoft subdomains
            if not ms_host[0].isdigit():
                client.cookies.set(name, value, domain="." + ms_host.split(".", 1)[-1])

        r = await client.get(authorize_url, headers={**_SILENT_SSO_HEADERS,
                                                       "Referer": f"{graylog_base}/"})
        if r.status_code != 302:
            diagnosis = _diagnose_microsoft_html(r.text) if r.text.startswith("<") else \
                        f"non-redirect status={r.status_code}"
            ms_session.mark_expired(diagnosis)
            raise MSSessionExpired(diagnosis)
        callback_url = r.headers.get("location", "")
        if "code=" not in callback_url:
            raise SilentSSOFailure(f"step2: no code= in redirect: {callback_url[:200]}")

        # Harvest refreshed MS cookies from Set-Cookie headers on step 2 response.
        refreshed_ms: dict[str, str] = {}
        for raw in r.headers.get_list("set-cookie"):
            if "=" not in raw:
                continue
            name, _, rest = raw.partition("=")
            value = rest.split(";", 1)[0]
            if name in _MS_REFRESHED_COOKIE_NAMES:
                refreshed_ms[name] = value

        # STEP 3: follow callback chain into oauth2-proxy
        hops = 0
        loc = callback_url
        while hops < 10:
            if loc.startswith("/"):
                loc = f"{graylog_base}{loc}"
            r = await client.get(loc)
            if r.status_code not in (301, 302, 303, 307, 308):
                break
            loc = r.headers.get("location", "")
            if not loc:
                break
            hops += 1

        # STEP 4: harvest _oauth2_proxy* cookies
        oauth2_proxy: dict[str, str] = {}
        for cookie in client.cookies.jar:
            if cookie.name.startswith("_oauth2_proxy"):
                oauth2_proxy[cookie.name] = cookie.value
        if "_oauth2_proxy" not in oauth2_proxy:
            raise SilentSSOFailure(
                f"step4: no _oauth2_proxy cookie (final status={r.status_code})"
            )

        # Persist outputs
        if refreshed_ms:
            ms_session.absorb(refreshed_ms)
        if ms_session.status == MSSessionAuth.STATUS_EXPIRED:
            ms_session.mark_healthy()
        cookie_auth.write_cookies(oauth2_proxy)

        return {"oauth2_proxy_cookies": oauth2_proxy,
                "refreshed_ms_count": len(refreshed_ms)}


class SilentSSORefresh:
    """Long-running refresher: silent SSO every interval_s seconds.

    On healthy iteration → ms_session.absorb() + cookie_auth.write_cookies().
    On expired iteration → post Telegram alert (once, idempotent until recovery).
    On network error → log, retry on next tick.

    Designed to run in a daemon thread with its own asyncio loop (see main()).
    """

    def __init__(self, *, graylog_base: str, ms_session: "MSSessionAuth",
                 cookie_auth: "CookieAuth", interval_s: int,
                 notify_url: str | None, notify_secret: str | None,
                 operator_telegram_user_id: str | None) -> None:
        self.graylog_base = graylog_base
        self.ms_session = ms_session
        self.cookie_auth = cookie_auth
        self.interval_s = max(60, min(3600, interval_s))
        self.notify_url = notify_url
        self.notify_secret = notify_secret
        self.operator_telegram_user_id = operator_telegram_user_id
        self.status: str = "pending"  # pending | healthy | expired | network_error
        self.last_refresh_at: datetime | None = None
        self.last_error: str | None = None
        self.refresh_count: int = 0
        self._expiry_alert_sent: bool = False
        self._stop_event: asyncio.Event | None = None

    async def refresh_now(self) -> None:
        """Run one iteration. Used by tests and by run_forever()."""
        # Early-return on degraded/expired state (don't hammer Microsoft).
        if self.ms_session.status == MSSessionAuth.STATUS_DEGRADED:
            self.status = "degraded"
            return
        if self.ms_session.status == MSSessionAuth.STATUS_EXPIRED:
            # Source of truth is ms_session.status; the task-level self.status is just a mirror.
            # Retry the alert each tick — _maybe_alert is idempotent on _expiry_alert_sent latch,
            # so if a previous POST failed, we'll keep retrying until it succeeds.
            self.status = "expired"
            await self._maybe_alert(self.ms_session.last_diagnosis or self.last_error or "session expired")
            return

        try:
            result = await silent_sso_refresh(
                graylog_base=self.graylog_base,
                ms_session=self.ms_session, cookie_auth=self.cookie_auth,
            )
        except MSSessionExpired as exc:
            self.status = "expired"
            self.last_error = str(exc)
            await self._maybe_alert(str(exc))
            return
        except SilentSSOFailure as exc:
            self.status = "network_error"
            self.last_error = str(exc)
            try:
                get_audit().log_event("silent_sso_failure", error=str(exc))
            except Exception:
                pass
            return
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as exc:
            self.status = "network_error"
            self.last_error = f"network: {exc}"
            try:
                get_audit().log_event("silent_sso_network_error", error=str(exc))
            except Exception:
                pass
            return

        # Success path
        self.status = "healthy"
        self.last_refresh_at = datetime.now(timezone.utc)
        self.last_error = None
        self.refresh_count += 1
        self._expiry_alert_sent = False  # latch reset on recovery
        try:
            get_audit().log_event(
                "silent_sso_refresh", result="ok",
                refreshed_ms=result["refreshed_ms_count"],
                refresh_count=self.refresh_count,
            )
        except Exception:
            pass

    async def _maybe_alert(self, diagnosis: str) -> None:
        if self._expiry_alert_sent:
            return
        if not (self.notify_url and self.notify_secret and self.operator_telegram_user_id):
            return
        last_refresh = (self.last_refresh_at.isoformat() if self.last_refresh_at else "never")
        text = (
            "MCP Graylog: silent SSO expired\n\n"
            f"Diagnosis: {diagnosis}\n"
            f"Last successful refresh: {last_refresh}\n\n"
            "To recover:\n"
            "1. Open https://graylog.yallasvc.net/ in Chrome, log in via SSO\n"
            "2. Run: python3 scripts/extract_ms_cookies.py\n"
            "3. Run: BLOB=$(python3 scripts/extract_ms_cookies.py --pack)\n"
            "4. Run: make graylog-set-ms-cookies COOKIES_B64=$BLOB"
        )
        payload = {"user_id": int(self.operator_telegram_user_id), "message": text}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.notify_url, json=payload,
                    headers={"X-Webhook-Secret": self.notify_secret},
                )
            if resp.status_code < 300:
                self._expiry_alert_sent = True
                try:
                    get_audit().log_event("silent_sso_expiry_alert_sent")
                except Exception:
                    pass
            else:
                try:
                    get_audit().log_event("silent_sso_alert_failed",
                                          status=resp.status_code, body=resp.text[:200])
                except Exception:
                    pass
        except Exception as exc:
            try:
                get_audit().log_event("silent_sso_alert_failed", error=str(exc))
            except Exception:
                pass

    async def run_forever(self) -> None:
        """Loop body for daemon thread. Construct stop_event inside running loop."""
        self._stop_event = asyncio.Event()
        await self.refresh_now()
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_s)
            except asyncio.TimeoutError:
                pass
            if self._stop_event.is_set():
                break
            await self.refresh_now()


def _is_signin_redirect(response) -> bool:
    """Detect oauth2-proxy sign-in HTML response (returns 200, not 401).

    Uses cumulative signal: not JSON + is HTML + at least one marker.
    Spec §5.5.
    """
    ct = (response.headers.get("Content-Type", "") or "").lower()
    if ct.startswith("application/json"):
        return False
    if not ct.startswith("text/html"):
        return False
    body = (response.content or b"")[:2048].lower()
    markers = (
        b"sign in",
        b"oauth2-proxy",
        b"microsoftonline.com",
        b"login.microsoftonline",
        b"/oauth2/start",
    )
    return any(m in body for m in markers)


def _extract_set_cookies(response: httpx.Response) -> list[str]:
    """Pull all Set-Cookie response headers as a list (handles split shards correctly)."""
    if hasattr(response.headers, "get_list"):
        return response.headers.get_list("Set-Cookie")
    return [
        v.decode("latin-1")
        for k, v in response.headers.raw
        if k.lower() == b"set-cookie"
    ]


# Backwards-compat alias used by all non-streaming tools
async def _call_graylog(
    method: str,
    path: str,
    auth: CookieAuth,
    params: dict | None = None,
    json_body: dict | None = None,
    accept: str = "application/json",
    timeout: float = 30.0,
) -> httpx.Response:
    """Non-streaming Graylog API call. For streaming see _call_graylog_stream()."""
    return await _call_graylog_json(
        method,
        path,
        auth,
        params=params,
        json_body=json_body,
        accept=accept,
        timeout=timeout,
    )


async def _call_graylog_json(
    method: str,
    path: str,
    auth: CookieAuth,
    params: dict | None = None,
    json_body: dict | None = None,
    accept: str = "application/json",
    timeout: float = 30.0,
) -> httpx.Response:
    """Non-streaming: full body loaded, client closed before return."""
    url = f"{GRAYLOG_BASE_URL.rstrip('/')}{path}"
    headers = {
        "Accept": accept,
        "X-Requested-By": "zeroclaw-mcp",
        **auth.headers(),
        **_api_token_header(),
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(
            method, url, params=params, json=json_body, headers=headers,
        )
    # response.content is fully buffered, safe to use after client close
    if _is_signin_redirect(response):
        raise SessionExpired(
            "oauth2-proxy returned sign-in HTML — silent SSO refresh likely failed. "
            "Check /health for ms_session.status; re-bootstrap via "
            "scripts/extract_ms_cookies.py + make graylog-set-ms-cookies if needed."
        )
    return response


@contextlib.asynccontextmanager
async def _call_graylog_stream(
    method: str,
    path: str,
    auth: CookieAuth,
    params: dict | None = None,
    json_body: dict | None = None,
    accept: str = "text/csv",
    timeout: float = 60.0,
) -> AsyncIterator[httpx.Response]:
    """Streaming: yields open response inside async-context. Caller must consume body
    BEFORE exiting the ``async with`` block. After exit, client+response are closed.

    Used by tool_search_to_file for chunked CSV download.
    """
    url = f"{GRAYLOG_BASE_URL.rstrip('/')}{path}"
    headers = {
        "Accept": accept,
        "X-Requested-By": "zeroclaw-mcp",
        **auth.headers(),
        **_api_token_header(),
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream(
            method, url, params=params, json=json_body, headers=headers,
        ) as response:
            yield response


_AUTH: CookieAuth | None = None


def get_auth() -> CookieAuth:
    global _AUTH
    if _AUTH is None:
        _AUTH = CookieAuth(
            state_path=GRAYLOG_STATE_DIR / "session.json",
            env_cookie_b64=GRAYLOG_SESSION_COOKIE_B64,
        )
    return _AUTH


def _ms_session_block() -> dict:
    """Return ms_session info for /health + tool_health responses."""
    ms = get_ms_session()
    silent_sso = get_silent_sso()
    return {
        "status": ms.status,
        "bootstrap_fingerprint": ms.bootstrap_fingerprint,
        "current_persistent_fingerprint": ms.current_persistent_fingerprint,
        "refresh_count_since_boot": silent_sso.refresh_count,
        "last_refresh_at": (silent_sso.last_refresh_at.isoformat()
                            if silent_sso.last_refresh_at else None),
        "last_diagnosis": ms.last_diagnosis,
    }


def health_status() -> dict:
    """Return current MCP Graylog health snapshot."""
    auth = get_auth()
    ms_block = _ms_session_block()
    base: dict[str, Any] = {
        "graylog_base_url": GRAYLOG_BASE_URL,
        "cookie_present": bool(auth._cookies_snapshot()),
        "ms_session": ms_block,
    }
    if ms_block["status"] == MSSessionAuth.STATUS_DEGRADED:
        base.update({"status": "degraded", "reason": "ms_cookies_missing",
                      "action": "run scripts/extract_ms_cookies.py + "
                                "make graylog-set-ms-cookies COOKIES_B64=..."})
        return base
    if ms_block["status"] == MSSessionAuth.STATUS_EXPIRED:
        base.update({"status": "expired", "reason": "ms_session_expired"})
        return base
    if not auth._cookies_snapshot():
        # Silent SSO running but hasn't yet produced first cookie
        base.update({"status": "pending", "reason": "awaiting_first_refresh"})
        return base
    base["status"] = "healthy"
    return base


# --- AuditLog (Task 10, spec §4.5) ---

AUDIT_MAX_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


class AuditLog:
    """Append-only JSONL audit log with size-based rotation.

    Spec §4.5. Single rolling file: when current size > max_size_bytes,
    rename to ``<path>.1`` (overwriting any previous .1) before next write.

    All writes serialised under fcntl.flock on a sibling .lock file.
    Audit failures must NEVER fail tool calls — broad-except in helpers.
    """

    def __init__(self, path: Path, max_size_bytes: int = AUDIT_MAX_SIZE_BYTES):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_size = max_size_bytes
        self._lock_path = self._path.with_suffix(".lock")

    def _maybe_rotate(self) -> None:
        try:
            if self._path.exists() and self._path.stat().st_size > self._max_size:
                rotated = self._path.with_suffix(self._path.suffix + ".1")
                rotated.unlink(missing_ok=True)
                self._path.rename(rotated)
        except Exception:
            pass  # never fail tool calls due to audit issues

    def _write(self, record: dict) -> None:
        record.setdefault(
            "ts", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with open(self._lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            try:
                self._maybe_rotate()
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            finally:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)

    def log_tool_call(self, *, tool: str, status: str, **fields: Any) -> None:
        self._write(
            {"event": "tool_call", "tool": tool, "status": status, **fields}
        )

    def log_event(self, event: str, **fields: Any) -> None:
        self._write({"event": event, **fields})


_AUDIT: AuditLog | None = None


def get_audit() -> AuditLog:
    global _AUDIT
    if _AUDIT is None:
        _AUDIT = AuditLog(GRAYLOG_STATE_DIR / "audit.log")
    return _AUDIT


_MS_SESSION: MSSessionAuth | None = None


def get_ms_session() -> MSSessionAuth:
    global _MS_SESSION
    if _MS_SESSION is None:
        _MS_SESSION = MSSessionAuth(
            state_path=GRAYLOG_STATE_DIR / "ms_session.json",
            env_cookie_b64=os.environ.get("MICROSOFT_SESSION_COOKIES", ""),
        )
    return _MS_SESSION


_SILENT_SSO: SilentSSORefresh | None = None


def get_silent_sso() -> SilentSSORefresh:
    global _SILENT_SSO
    if _SILENT_SSO is None:
        _SILENT_SSO = SilentSSORefresh(
            graylog_base=GRAYLOG_BASE_URL,
            ms_session=get_ms_session(),
            cookie_auth=get_auth(),
            interval_s=int(os.environ.get(
                "GRAYLOG_REFRESH_INTERVAL_S",
                os.environ.get("GRAYLOG_KEEPALIVE_INTERVAL_S", "1500"),
            )),
            notify_url=os.environ.get("NOTIFY_URL") or None,
            notify_secret=os.environ.get("NOTIFY_SECRET") or None,
            operator_telegram_user_id=os.environ.get("GRAYLOG_OPERATOR_TELEGRAM_USER_ID") or None,
        )
    return _SILENT_SSO


def _audit_tool(tool_name: str, started_at: float, **fields: Any) -> None:
    """Helper: write audit record with consistent shape. Never raises."""
    try:
        get_audit().log_tool_call(
            tool=tool_name,
            duration_ms=int((time.monotonic() - started_at) * 1000),
            **fields,
        )
    except Exception:
        pass  # never let audit break tools


# --- Range parser (Task 6, spec §4.3) ---

_RANGE_RE = re.compile(r"^(\d+)([smhdw])$")
_RANGE_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_RANGE_HARD_CAP_S = 90 * 86400  # 90 days


def _range_to_seconds(value: str) -> int:
    """Parse '1h', '24h', '7d' → seconds. Hard cap 90d. Raises ValueError."""
    if not value or not isinstance(value, str):
        raise ValueError(f"Invalid range: {value!r}")
    m = _RANGE_RE.match(value.strip())
    if not m:
        raise ValueError(
            f"Invalid range format: {value!r} (expected e.g. '1h', '5m', '7d')"
        )
    n, unit = int(m.group(1)), m.group(2)
    if n <= 0:
        raise ValueError(f"Range must be positive: {value!r}")
    seconds = n * _RANGE_UNITS[unit]
    if seconds > _RANGE_HARD_CAP_S:
        raise ValueError(f"Range exceeds hard cap 90d: {value!r}")
    return seconds


KEEPALIVE_INTERVAL_S = int(os.environ.get("GRAYLOG_KEEPALIVE_INTERVAL_S", "1500"))
_KEEPALIVE_INTERVAL_MIN = 60
_KEEPALIVE_INTERVAL_MAX = 3600


# --- KeepaliveTask (Task 9, spec §4.2) ---


async def _keepalive_iteration(auth: CookieAuth) -> None:
    """One probe iteration. Raises SessionExpired on sign-in HTML; swallows other errors.

    `_call_graylog` already raises SessionExpired on sign-in detection. Other
    HTTP errors (5xx, network failures) are not raised here — caller decides.
    """
    # lbstatus returns text/plain "ALIVE" — accept anything to avoid 406.
    await _call_graylog("GET", "/api/system/lbstatus", auth=auth, accept="*/*", timeout=10)


async def keepalive_loop(auth: CookieAuth, interval_s: int = KEEPALIVE_INTERVAL_S) -> None:
    """Background loop. Stops only on SessionExpired."""
    interval = max(_KEEPALIVE_INTERVAL_MIN, min(_KEEPALIVE_INTERVAL_MAX, interval_s))
    log = logging.getLogger("mcp_graylog.keepalive")
    while True:
        try:
            await asyncio.sleep(interval)
            await _keepalive_iteration(auth)
            log.info("keepalive_ok")
        except SessionExpired:
            log.warning(
                "keepalive_failed: cookie_expired — stopping loop, manual restart needed"
            )
            break
        except Exception as e:
            log.warning("keepalive_error: %s — continuing", e)


# --- Tools (Task 6, spec §4.3.1, §4.3.3) ---


async def tool_health(_user_id: int | str | None = None) -> str:
    """Return MCP Graylog health snapshot as JSON string.

    Returns all fields per spec §4.3.3 / §6.2:
      status, cookie_present, cookie_age_s, last_refresh_ts,
      keepalive_next_s (best-effort), graylog_version (if probe ok),
      last_probe_ts, last_probe_status, reason/action (on degraded/expired).
    """
    started = time.monotonic()
    auth = get_auth()
    snap = auth._cookies_snapshot()
    state_path = auth._state_path
    base: dict[str, Any] = {
        "status": "unknown",
        "graylog_base_url": GRAYLOG_BASE_URL,
        "cookie_present": bool(snap),
    }
    base["ms_session"] = _ms_session_block()
    # Cookie age + last refresh from state.json mtime (proxy for last absorb)
    if snap and state_path.exists():
        try:
            saved = json.loads(state_path.read_text())
            last_refresh_iso = saved.get("updated_at")
            base["last_refresh_ts"] = last_refresh_iso
            if last_refresh_iso:
                # Parse ISO-8601 with Z
                ts = datetime.fromisoformat(
                    last_refresh_iso.replace("Z", "+00:00")
                )
                base["cookie_age_s"] = int(
                    (datetime.now(timezone.utc) - ts).total_seconds()
                )
        except Exception:
            pass
    base["silent_sso_interval_s"] = get_silent_sso().interval_s

    if not snap:
        base.update({"status": "unhealthy", "reason": "cookie_missing"})
        _audit_tool(
            "health",
            started,
            status="unhealthy",
            reason="cookie_missing",
            user_id=_user_id,
        )
        return json.dumps(base)
    try:
        response = await _call_graylog(
            "GET", "/api/system/lbstatus", auth=auth, accept="*/*", timeout=10
        )
        if response.status_code == 200:
            base.update({"status": "healthy", "last_probe_status": "ok"})
        else:
            base.update(
                {
                    "status": "degraded",
                    "last_probe_status": str(response.status_code),
                }
            )
        _audit_tool(
            "health",
            started,
            status=base["status"],
            cookie_age_s=base.get("cookie_age_s"),
            last_probe_status=base.get("last_probe_status"),
            user_id=_user_id,
        )
    except SessionExpired as e:
        base.update(
            {"status": "expired", "reason": "sign_in_redirect", "action": str(e)}
        )
        _audit_tool(
            "health",
            started,
            status="expired",
            reason="sign_in_redirect",
            user_id=_user_id,
        )
    except Exception as e:
        base.update({"status": "degraded", "reason": str(e)})
        _audit_tool(
            "health",
            started,
            status="degraded",
            reason=str(e),
            user_id=_user_id,
        )
    base["last_probe_ts"] = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return json.dumps(base)


async def tool_count(
    query: str,
    range: str = "1h",
    streams: str | None = None,
    _user_id: int | str | None = None,
) -> str:
    """Count messages matching query."""
    started = time.monotonic()
    auth = get_auth()
    try:
        range_secs = _range_to_seconds(range)
    except ValueError as e:
        _audit_tool(
            "count", started, status="error",
            error_code="invalid_range", query=query, range=range, user_id=_user_id,
        )
        return json.dumps({"error": "invalid_range", "detail": str(e)})
    params: dict[str, str] = {
        "query": query,
        "range": str(range_secs),
        "limit": "1",
    }
    streams_filter = _build_streams_filter(streams)
    if streams_filter:
        params["filter"] = streams_filter
    try:
        response = await _call_graylog(
            "GET", _SEARCH_UNIVERSAL, auth=auth, params=params
        )
    except SessionExpired:
        _audit_tool(
            "count",
            started,
            status="error",
            error_code="session_expired",
            query=query,
            range=range,
            user_id=_user_id,
        )
        return json.dumps({"error": "graylog_session_expired", "tool": "count"})
    if response.status_code != 200:
        _audit_tool(
            "count",
            started,
            status="error",
            error_code=f"graylog_http_{response.status_code}",
            query=query,
            range=range,
            user_id=_user_id,
        )
        return json.dumps(
            {
                "error": f"graylog_http_{response.status_code}",
                "body": response.text[:500],
            }
        )
    data = response.json()
    _audit_tool(
        "count",
        started,
        status="ok",
        row_count=data.get("total_results", 0),
        query=query,
        range=range,
        user_id=_user_id,
    )
    return json.dumps(
        {
            "total_results": data.get("total_results", 0),
            "time_range": data.get("time_range"),
        }
    )


# --- Tools (Task 7, spec §4.3.1, §4.3.4, §4.3.5) ---

# Inline tool output cap. Production logs are wide (~30 fields × 200-800 bytes),
# 50-message search trivially busts 32 KB. Main agent runs on a 1M-context model,
# so we can afford a much larger inline payload before falling back to file export.
MAX_STDOUT_BYTES = 256 * 1024  # 256 KB
HARD_LIMIT_SEARCH = 1000

# Graylog 6.x search endpoints. The Views API (POST /api/search/messages)
# returns a different shape (schema/datarows) and does not honor `size:0` for
# count-only queries. The legacy "universal" endpoints return the classic
# shape ({messages, total_results, time_range}) and `/export` streams CSV.
_SEARCH_UNIVERSAL = "/api/search/universal/relative"
_SEARCH_UNIVERSAL_CSV = "/api/search/universal/relative/export"


def _build_streams_filter(streams: str | None) -> str | None:
    """Convert comma-separated stream IDs into Graylog universal filter syntax.

    Single stream → "streams:<id>". Multiple → "streams:<id1> OR streams:<id2>".
    """
    if not streams:
        return None
    ids = [s.strip() for s in streams.split(",") if s.strip()]
    if not ids:
        return None
    return " OR ".join(f"streams:{sid}" for sid in ids)


def _flatten_universal_messages(data: dict[str, Any]) -> dict[str, Any]:
    """Convert universal-search response into a flat shape consumable downstream.

    Universal API wraps each hit: ``[{"message": {...}, "highlight_ranges": {...}}, ...]``.
    Returns ``{"messages": [...flat dicts...], "total_results": N, "time_range": {...}}``.
    """
    messages = data.get("messages", []) or []
    flat: list[dict[str, Any]] = []
    for m in messages:
        if isinstance(m, dict) and isinstance(m.get("message"), dict):
            flat.append(m["message"])
        elif isinstance(m, dict):
            flat.append(m)
    return {
        "messages": flat,
        "total_results": data.get("total_results", len(flat)),
        "time_range": data.get("time_range"),
    }


def _escape_lucene_phrase(value: str) -> str:
    """Escape Lucene reserved chars for safe inclusion in phrase query.

    Order matters: backslash first, then quote.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _maybe_truncate(payload: dict, original_total: int | None = None) -> str:
    """Serialize payload; if > MAX_STDOUT_BYTES, replace with truncation hint."""
    encoded = json.dumps(payload)
    if len(encoded.encode("utf-8")) <= MAX_STDOUT_BYTES:
        return encoded
    return json.dumps({
        "warning": "response_too_big",
        "row_count": original_total or payload.get("total_results"),
        "shown_count": len(payload.get("messages", [])),
        "hint": "Use graylog__search_to_file для full результата",
    })


async def tool_search(
    query: str,
    range: str = "1h",
    limit: int = 50,
    fields: str | None = None,
    streams: str | None = None,
    _user_id: int | str | None = None,
) -> str:
    """Search Graylog messages; returns JSON, truncated if too big."""
    started = time.monotonic()
    auth = get_auth()
    if limit > HARD_LIMIT_SEARCH:
        _audit_tool(
            "search",
            started,
            status="error",
            error_code="limit_too_high",
            query=query,
            range=range,
            limit=limit,
            user_id=_user_id,
        )
        return json.dumps({"error": f"limit cap is {HARD_LIMIT_SEARCH}"})
    try:
        range_secs = _range_to_seconds(range)
    except ValueError as e:
        _audit_tool(
            "search", started, status="error",
            error_code="invalid_range", query=query, range=range, limit=limit, user_id=_user_id,
        )
        return json.dumps({"error": "invalid_range", "detail": str(e)})
    params: dict[str, str] = {
        "query": query,
        "range": str(range_secs),
        "limit": str(int(limit)),
    }
    if fields:
        params["fields"] = ",".join(f.strip() for f in fields.split(",") if f.strip())
    streams_filter = _build_streams_filter(streams)
    if streams_filter:
        params["filter"] = streams_filter
    try:
        response = await _call_graylog(
            "GET", _SEARCH_UNIVERSAL, auth=auth, params=params
        )
    except SessionExpired:
        _audit_tool(
            "search",
            started,
            status="error",
            error_code="session_expired",
            query=query,
            range=range,
            limit=limit,
            user_id=_user_id,
        )
        return json.dumps({"error": "graylog_session_expired", "tool": "search"})
    if response.status_code != 200:
        _audit_tool(
            "search",
            started,
            status="error",
            error_code=f"graylog_http_{response.status_code}",
            query=query,
            range=range,
            limit=limit,
            user_id=_user_id,
        )
        return json.dumps(
            {
                "error": f"graylog_http_{response.status_code}",
                "body": response.text[:500],
            }
        )
    result_str = _maybe_truncate(_flatten_universal_messages(response.json()))
    parsed = json.loads(result_str)
    _audit_tool(
        "search",
        started,
        status="ok",
        query=query,
        range=range,
        limit=limit,
        row_count=parsed.get("total_results"),
        truncated="warning" in parsed,
        user_id=_user_id,
    )
    return result_str


async def tool_by_request_id(
    request_id: str,
    range: str = "24h",
    _user_id: int | str | None = None,
) -> str:
    """Find log entries by request_id or trace_id (Lucene-escaped)."""
    started = time.monotonic()
    safe = _escape_lucene_phrase(str(request_id))
    query = f'request_id:"{safe}" OR trace_id:"{safe}"'
    result_str = await tool_search(
        query=query, range=range, limit=200, _user_id=_user_id
    )
    try:
        parsed = json.loads(result_str)
    except Exception:
        parsed = {}
    if "error" in parsed:
        _audit_tool(
            "by_request_id",
            started,
            status="error",
            error_code=parsed.get("error"),
            request_id=str(request_id),
            range=range,
            user_id=_user_id,
        )
    else:
        _audit_tool(
            "by_request_id",
            started,
            status="ok",
            request_id=str(request_id),
            range=range,
            row_count=parsed.get("total_results"),
            truncated="warning" in parsed,
            user_id=_user_id,
        )
    return result_str


async def tool_by_user(
    user_id,
    query: str = "",
    range: str = "24h",
    _user_id: int | str | None = None,
) -> str:
    """Find log entries by numeric user_id, optional extra query."""
    started = time.monotonic()
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        _audit_tool(
            "by_user",
            started,
            status="error",
            error_code="invalid_user_id",
            received=str(user_id),
            range=range,
            user_id=_user_id,
        )
        return json.dumps(
            {"error": "user_id must be numeric", "received": str(user_id)}
        )
    base = f"user_id:{uid}"
    full = f"{base} AND ({query})" if query else base
    result_str = await tool_search(
        query=full, range=range, limit=500, _user_id=_user_id
    )
    try:
        parsed = json.loads(result_str)
    except Exception:
        parsed = {}
    if "error" in parsed:
        _audit_tool(
            "by_user",
            started,
            status="error",
            error_code=parsed.get("error"),
            target_user_id=uid,
            range=range,
            user_id=_user_id,
        )
    else:
        _audit_tool(
            "by_user",
            started,
            status="ok",
            target_user_id=uid,
            range=range,
            row_count=parsed.get("total_results"),
            truncated="warning" in parsed,
            user_id=_user_id,
        )
    return result_str


# --- Tool: graylog__search_to_file (Task 8, spec §4.3.6, §4.4) ---

EXPORT_HARD_CAP_ROWS = 500_000
EXPORT_HARD_CAP_BYTES = 500 * 1024 * 1024  # 500 MB
EXPORT_DEFAULT_TIMEOUT_S = 120
EXPORT_HARD_TIMEOUT_S = 300
_OUT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_out_name(name: str) -> str:
    if not _OUT_NAME_RE.match(name or ""):
        raise ValueError(
            f"out_name must match [A-Za-z0-9_-]{{1,64}}: {name!r}"
        )
    return name


def _resolve_upload_path(workspace: str, out_name: str, fmt: str) -> Path:
    """Return absolute path inside <workspace>/uploads/graylog/. Validates no escape."""
    out = _validate_out_name(out_name)
    fmt_clean = {"parquet": "parquet", "csv": "csv", "json": "json"}.get(fmt)
    if not fmt_clean:
        raise ValueError(f"Unsupported format: {fmt!r}")
    ws = Path(workspace).resolve()
    target_dir = (ws / "uploads" / "graylog").resolve()
    # Path traversal check BEFORE mkdir — never create dirs outside workspace
    if not str(target_dir).startswith(str(ws)):
        raise ValueError(f"workspace path resolves outside itself: {workspace}")
    # Auto-create on first export — bootstrap workspace doesn't pre-create this
    target_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex[:8]}__{out}.{fmt_clean}"
    return target_dir / filename


async def _stream_csv_to_tempfile(
    auth: CookieAuth, params: dict[str, str], max_bytes: int, timeout_s: int
) -> tuple[Path, bool]:
    """GET /api/search/universal/relative/export with Accept: text/csv, stream to tempfile.

    Returns (tempfile_path, truncated). Aborts on byte/timeout caps; row-count
    enforcement happens via Graylog's ``limit`` query param.

    NOTE: We intentionally do NOT count rows by ``chunk.count(b"\\n")`` — CSV cells
    with embedded newlines (log messages) would skew the count. Final row_count
    comes from pyarrow.Table.num_rows after conversion (caller).
    """
    tmp = Path(tempfile.gettempdir()) / f"graylog_export_{uuid.uuid4().hex[:8]}.csv"
    bytes_written = 0
    truncated = False
    start = time.monotonic()
    async with _call_graylog_stream(
        "GET", _SEARCH_UNIVERSAL_CSV, auth=auth, params=params,
        accept="text/csv", timeout=timeout_s,
    ) as response:
        # If proxy fed us sign-in HTML on stream — detect on first chunk
        ct = (response.headers.get("Content-Type", "") or "").lower()
        if ct.startswith("text/html"):
            raise SessionExpired(
                "oauth2-proxy returned sign-in HTML — silent SSO refresh likely failed. "
                "Check /health for ms_session.status; re-bootstrap via "
                "scripts/extract_ms_cookies.py + make graylog-set-ms-cookies if needed."
            )
        with tmp.open("wb") as fh:
            async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                if time.monotonic() - start > timeout_s:
                    truncated = True
                    raise asyncio.TimeoutError("export timeout")
                fh.write(chunk)
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    truncated = True
                    raise OSError(f"export exceeded {max_bytes} bytes")
    return tmp, truncated


def _convert_csv_to_target(
    tmp_path: Path, out_path: Path, fmt: str
) -> tuple[Path, str | None]:
    """Convert tempfile CSV to target format at out_path.

    Returns (final_path, fallback_warning):
    - final_path: actual file written (may differ from out_path if parquet→csv fallback)
    - fallback_warning: None on clean success; string describing fallback if parquet failed

    NEVER raises on conversion failure for parquet — fallback to CSV is silent-but-warned.

    Uses ``shutil.move`` (not ``Path.replace``) because ``tempfile.gettempdir()`` and the
    workspace upload dir live on different filesystems on Fly (`/tmp` is memfs, the Fly
    volume is mounted at ``/zeroclaw-data``); ``Path.replace`` raises
    ``OSError: [Errno 18] Invalid cross-device link`` in that scenario.
    """
    if fmt == "csv":
        shutil.move(str(tmp_path), str(out_path))
        return out_path, None
    if fmt == "json":
        try:
            with tmp_path.open("r", newline="") as fh, out_path.open("w") as out:
                reader = csv_module.DictReader(fh)
                for row in reader:
                    out.write(json.dumps(row) + "\n")
        finally:
            tmp_path.unlink(missing_ok=True)
        return out_path, None
    if fmt == "parquet":
        try:
            import pyarrow.csv as pa_csv
            import pyarrow.parquet as pa_pq
            table = pa_csv.read_csv(tmp_path)
            pa_pq.write_table(table, out_path, compression="snappy")
            tmp_path.unlink(missing_ok=True)
            return out_path, None
        except Exception as e:
            csv_fallback = out_path.with_suffix(".csv")
            shutil.move(str(tmp_path), str(csv_fallback))
            return csv_fallback, f"parquet_conversion_failed: {e}; saved as csv"
    raise ValueError(f"Unsupported format: {fmt}")


def _count_rows(path: Path, fmt: str) -> int:
    """Return authoritative row count from converted file."""
    if fmt == "csv":
        with path.open("r", newline="") as fh:
            return sum(1 for _ in csv_module.reader(fh)) - 1  # subtract header
    if fmt == "json":
        return sum(1 for _ in path.open("r"))
    if fmt == "parquet":
        import pyarrow.parquet as pa_pq
        return pa_pq.read_metadata(path).num_rows
    return -1


def _json_safe(value: Any) -> Any:
    """Coerce pyarrow scalars (datetime, Decimal, bytes, etc.) to JSON-safe types."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8")
        except Exception:
            return value.hex()
    # datetime, Decimal, UUID, etc. → string fallback
    return str(value)


def _read_preview(out_path: Path, fmt: str, limit: int = 5) -> list[dict]:
    if fmt == "csv":
        with out_path.open("r", newline="") as fh:
            reader = csv_module.DictReader(fh)
            return [row for _, row in zip(range(limit), reader)]
    if fmt == "json":
        rows: list[dict] = []
        with out_path.open("r") as fh:
            for line in fh:
                if len(rows) >= limit:
                    break
                rows.append(json.loads(line))
        return rows
    if fmt == "parquet":
        import pyarrow.parquet as pa_pq
        table = pa_pq.read_table(out_path)
        return [_json_safe(row) for row in table.slice(0, limit).to_pylist()]
    return []


async def tool_search_to_file(
    query: str,
    workspace: str,
    out_name: str,
    range: str = "24h",
    fields: str | None = None,
    streams: str | None = None,
    max_rows: int = 100_000,
    format: str = "csv",
    timeout_secs: int = EXPORT_DEFAULT_TIMEOUT_S,
    _user_id: int | str | None = None,
) -> str:
    """Stream search results to file. Default ``format='csv'`` — pandas reads it
    natively, no pyarrow conversion to fail on mixed-type columns. Pass
    ``format='parquet'`` explicitly when a typed column store is actually needed.
    """
    started = time.monotonic()
    auth = get_auth()
    capped_rows = min(int(max_rows), EXPORT_HARD_CAP_ROWS)
    capped_timeout = min(int(timeout_secs), EXPORT_HARD_TIMEOUT_S)
    try:
        out_path = _resolve_upload_path(workspace, out_name, format)
    except ValueError as e:
        _audit_tool(
            "search_to_file",
            started,
            status="error",
            error_code="invalid_path",
            query=query,
            range=range,
            max_rows=capped_rows,
            user_id=_user_id,
        )
        return json.dumps(
            {"error": "invalid_out_name_or_workspace", "detail": str(e)}
        )

    try:
        range_secs = _range_to_seconds(range)
    except ValueError as e:
        _audit_tool(
            "search_to_file", started, status="error",
            error_code="invalid_range", query=query, range=range,
            max_rows=capped_rows, user_id=_user_id,
        )
        return json.dumps({"error": "invalid_range", "detail": str(e)})

    # Universal /export REQUIRES `fields` (returns 400 "must not be empty"
    # if absent). When the caller didn't specify, pass a sane default that
    # captures most of what an ops engineer needs from a log line.
    fields_param = (
        ",".join(f.strip() for f in fields.split(",") if f.strip())
        if fields else "timestamp,source,message"
    )
    params: dict[str, str] = {
        "query": query,
        "range": str(range_secs),
        "limit": str(capped_rows),
        "fields": fields_param,
    }
    streams_filter = _build_streams_filter(streams)
    if streams_filter:
        params["filter"] = streams_filter

    try:
        tmp, truncated = await _stream_csv_to_tempfile(
            auth, params, max_bytes=EXPORT_HARD_CAP_BYTES, timeout_s=capped_timeout,
        )
    except SessionExpired:
        _audit_tool(
            "search_to_file",
            started,
            status="error",
            error_code="session_expired",
            query=query,
            range=range,
            max_rows=capped_rows,
            user_id=_user_id,
        )
        return json.dumps(
            {"error": "graylog_session_expired", "tool": "search_to_file"}
        )
    except (asyncio.TimeoutError, OSError) as e:
        _audit_tool(
            "search_to_file",
            started,
            status="error",
            error_code=str(e),
            query=query,
            range=range,
            max_rows=capped_rows,
            user_id=_user_id,
        )
        return json.dumps({"error": str(e), "tool": "search_to_file"})

    try:
        actual_path, fallback_warning = _convert_csv_to_target(
            tmp, out_path, format
        )
        actual_format = "csv" if fallback_warning else format
        preview = _read_preview(actual_path, actual_format)
        row_count = _count_rows(actual_path, actual_format)
        ws_root = Path(workspace).resolve()
        rel_path = actual_path.relative_to(ws_root)
        size_bytes = actual_path.stat().st_size

        meta = {
            "query": query,
            "range": range,
            "fields": fields,
            "streams": streams,
            "row_count": row_count,
            "size_bytes": size_bytes,
            "format": actual_format,
            "requested_format": format,
            "truncated": truncated,
            "fallback_warning": fallback_warning,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        meta_path = actual_path.with_suffix(actual_path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2))

        _audit_tool(
            "search_to_file",
            started,
            status="ok",
            query=query,
            range=range,
            max_rows=capped_rows,
            format=actual_format,
            row_count=row_count,
            size_bytes=size_bytes,
            file=str(rel_path),
            truncated=truncated,
            fallback_warning=fallback_warning,
            user_id=_user_id,
        )
        return json.dumps({
            "path": str(rel_path),
            "absolute_path": str(actual_path),
            "row_count": row_count,
            "column_names": list(preview[0].keys()) if preview else [],
            "size_bytes": size_bytes,
            "duration_ms": meta["duration_ms"],
            "truncated": truncated,
            "format": actual_format,
            "fallback_warning": fallback_warning,
            "preview": preview,
        })
    except Exception as e:
        out_path.unlink(missing_ok=True)
        out_path.with_suffix(".csv").unlink(missing_ok=True)
        _audit_tool(
            "search_to_file",
            started,
            status="error",
            error_code="conversion_failed",
            query=query,
            range=range,
            max_rows=capped_rows,
            user_id=_user_id,
        )
        return json.dumps({"error": "conversion_failed", "detail": str(e)})


# --- MCP JSON-RPC dispatch (Task 6) ---

# IMPORTANT: TOOLS keys are BARE tool names (no `graylog__` prefix).
# The Rust ZeroClaw MCP client at mcp_client.rs:230 prefixes each tool with
# the server's config name: `format!("{}__{}", config.name, tool.name)`.
# Since the daemon config has `name = "graylog"`, the agent sees them as
# `graylog__health`, `graylog__count`, etc. Adding the prefix here would
# produce double-prefixed names like `graylog__graylog__health`.
TOOLS: dict[str, tuple[Any, dict[str, Any], str]] = {
    "health": (
        tool_health,
        {},
        "Check MCP Graylog server status (cookie validity, last refresh, probe).",
    ),
    "count": (
        tool_count,
        {"query": str, "range": str, "streams": (str, type(None))},
        "Count messages matching a Lucene query without returning bodies.",
    ),
    "search": (
        tool_search,
        {
            "query": str,
            "range": str,
            "limit": int,
            "fields": (str, type(None)),
            "streams": (str, type(None)),
        },
        "Search Graylog messages; returns up to `limit` records, truncates >32KB.",
    ),
    "by_request_id": (
        tool_by_request_id,
        {"request_id": str, "range": str},
        "Trace one API request by request_id/trace_id across services.",
    ),
    "by_user": (
        tool_by_user,
        {"user_id": (int, str), "query": str, "range": str},
        "Get all log entries for a numeric user_id, optional extra Lucene query.",
    ),
    "search_to_file": (
        tool_search_to_file,
        {
            "query": str,
            "workspace": str,
            "out_name": str,
            "range": str,
            "fields": (str, type(None)),
            "streams": (str, type(None)),
            "max_rows": int,
            "format": str,
            "timeout_secs": int,
        },
        "Stream search results to <workspace>/uploads/graylog/ as parquet/csv/json.",
    ),
}


def _python_type_to_json_type(py_type: Any) -> str:
    """Map Python type to JSON Schema type string."""
    if py_type is str:
        return "string"
    if py_type is int:
        return "integer"
    if py_type is float:
        return "number"
    if py_type is bool:
        return "boolean"
    return "string"  # fallback for unknown


def _build_input_schema(arg_schema: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON Schema for tools/list inputSchema field from our internal schema."""
    properties: dict[str, dict[str, Any]] = {}
    required: list[str] = []
    for arg_name, arg_type in arg_schema.items():
        if isinstance(arg_type, tuple):
            # Optional — type union with NoneType
            non_none = [t for t in arg_type if t is not type(None)]
            primary = non_none[0] if non_none else str
            properties[arg_name] = {"type": _python_type_to_json_type(primary)}
        else:
            properties[arg_name] = {"type": _python_type_to_json_type(arg_type)}
            required.append(arg_name)
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


def _build_tools_list_response() -> dict[str, Any]:
    """Build the `tools/list` response per MCP spec."""
    tools_list = []
    for name, (_fn, arg_schema, description) in TOOLS.items():
        tools_list.append(
            {
                "name": name,
                "description": description,
                "inputSchema": _build_input_schema(arg_schema),
            }
        )
    return {"tools": tools_list}


def _dispatch_tool_sync(name: str, args: dict) -> str:
    fn, _schema, _desc = TOOLS[name]
    return asyncio.run(fn(**args))


# MCP protocol version we support (matches what zeroclaw-tools client sends)
MCP_PROTOCOL_VERSION = "2024-11-05"


class MCPHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            body = json.dumps(health_status()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length))
        except Exception:
            self.send_response(400)
            self.end_headers()
            return
        # MCP JSON-RPC protocol
        method = payload.get("method", "")
        params = payload.get("params", {}) or {}
        request_id = payload.get("id")
        is_notification = request_id is None

        if method == "initialize":
            # MCP handshake — see work/zeroclaw-source/crates/zeroclaw-tools/src/mcp_client.rs:54
            result = {
                "protocolVersion": params.get("protocolVersion", MCP_PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "mcp-graylog",
                    "version": "0.1.0",
                },
            }
        elif method == "notifications/initialized":
            # Client done with init; per JSON-RPC spec notifications expect no response.
            # ZeroClaw's send_and_recv is best-effort, so we still return 200 with empty
            # body to avoid blocking on the receive side.
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif method == "tools/list":
            result = _build_tools_list_response()
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {}) or {}
            # Lift _meta.user_id from MCP context if daemon passes it
            meta = params.get("_meta", {}) or {}
            if "user_id" in meta and "_user_id" not in tool_args:
                tool_args["_user_id"] = meta["user_id"]
            if tool_name not in TOOLS:
                self._respond_jsonrpc(
                    request_id,
                    error={
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}",
                    },
                )
                return
            try:
                output = _dispatch_tool_sync(tool_name, tool_args)
                result = {"content": [{"type": "text", "text": output}]}
            except Exception as e:
                self._respond_jsonrpc(
                    request_id, error={"code": -32000, "message": str(e)}
                )
                return
        else:
            if is_notification:
                # Unknown notification — silently accept (per JSON-RPC spec, notifications
                # never get error responses from the server).
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._respond_jsonrpc(
                request_id,
                error={"code": -32601, "message": f"Unknown method: {method}"},
            )
            return

        self._respond_jsonrpc(request_id, result=result)

    def _respond_jsonrpc(self, request_id, result=None, error=None) -> None:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            body["error"] = error
        else:
            body["result"] = result
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # quiet logger
        return


def create_http_server(port: int = DEFAULT_PORT) -> HTTPServer:
    """Create (but don't start) HTTP server. Used by tests + main()."""
    GRAYLOG_STATE_DIR.mkdir(parents=True, exist_ok=True)
    return HTTPServer(("0.0.0.0", port), MCPHandler)


def main() -> None:
    server = create_http_server(DEFAULT_PORT)
    print(f"[mcp_graylog] listening on http://0.0.0.0:{server.server_address[1]}")

    ms_session = get_ms_session()
    if ms_session.status == MSSessionAuth.STATUS_DEGRADED:
        print("[mcp_graylog] MS session cookies not provisioned — silent SSO disabled",
              flush=True)
    else:
        silent_sso = get_silent_sso()

        def _run_silent_sso_loop() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(silent_sso.run_forever())
            finally:
                loop.close()

        threading.Thread(target=_run_silent_sso_loop, daemon=True, name="silent_sso").start()

    server.serve_forever()


if __name__ == "__main__":
    main()
