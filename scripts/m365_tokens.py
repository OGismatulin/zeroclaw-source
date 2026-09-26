"""Per-user Microsoft 365 token store for the m365 MCP shim and the manager.

Tokens belong to the claude.ai Microsoft 365 connector app (public client,
device code flow). One JSON file per user under M365_TOKEN_DIR, mode 0600,
written atomically under an exclusive flock. Both writers (the per-turn MCP
shim and the manager's M365Refresher) read-modify-write inside the lock, so a
rotated refresh token is never lost. Nothing here prints token material.
Spec: docs/superpowers/specs/2026-09-25-m365-teams-read-mcp-design.md
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Mapping

CLIENT_ID = "08ad6f98-a4f8-4635-bb8d-f1a3044760f0"
SCOPE = "api://07c030f6-5743-41b7-ba00-0a6e85f37c17/.default offline_access openid"
AUTHORITY = "https://login.microsoftonline.com/organizations/oauth2/v2.0"
MCP_URL = "https://microsoft365.mcp.claude.com/mcp"
DEFAULT_TOKEN_DIR = "/zeroclaw-data/m365/tokens"

# Read-only tools the tenant has scopes for (spec §4.3). teams_list_teams is out:
# Team.ReadBasic.All is not granted, it always returns 403.
READ_ALLOWLIST = (
    "read_resource", "sharepoint_search", "sharepoint_folder_search",
    "outlook_email_search", "outlook_calendar_search", "find_meeting_availability",
    "outlook_find_available_time", "chat_message_search", "teams_list_chats",
    "get_me", "search_people", "teams_list_channels", "teams_list_channel_messages",
    "get_granted_scopes",
)

# Cloudflare answers 403/1010 to the default urllib User-Agent.
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) zeroclaw-m365/1"
HTTP_TIMEOUT_SECS = 15
UPSTREAM_TIMEOUT_SECS = 35
# Worst tools/call path: wait for a peer's refresh under flock, own refresh, upstream,
# 401 -> forced refresh, upstream retry. Must stay below the server's tool_timeout_secs
# (120 in config; the fork client kills and respawns the child on timeout).
WORST_CASE_CALL_SECS = 3 * HTTP_TIMEOUT_SECS + 2 * UPSTREAM_TIMEOUT_SECS
ACCESS_SKEW_SECS = 300
SNAPSHOT_PATH = Path(__file__).with_name("m365_tools_snapshot.json")
_USER_KEY_RE = re.compile(r"^tg_[0-9]+$")


class NeedsLogin(Exception):
    """The user must (re)connect: no record, not ok, or the grant was revoked."""


class TransientError(Exception):
    """Network, timeout, 429 or 5xx. The token record is left untouched."""


def _authority() -> str:
    return os.environ.get("M365_AUTHORITY", AUTHORITY)


def mcp_url() -> str:
    return os.environ.get("M365_MCP_URL", MCP_URL)


def _token_dir() -> Path:
    return Path(os.environ.get("M365_TOKEN_DIR", DEFAULT_TOKEN_DIR))


def user_key_from_env(env: Mapping[str, str]) -> str:
    workspace = env.get("ZEROCLAW_WORKSPACE", "")
    key = Path(workspace).parent.name if workspace else ""
    if not _USER_KEY_RE.fullmatch(key):
        raise ValueError(f"not a per-user workspace: {workspace!r}")
    return key


@contextlib.contextmanager
def _locked(key: str) -> Iterator[None]:
    directory = _token_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    fd = os.open(directory / f"{key}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read(key: str) -> dict[str, Any] | None:
    try:
        data = json.loads((_token_dir() / f"{key}.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write(key: str, record: dict[str, Any]) -> None:
    path = _token_dir() / f"{key}.json"
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    os.replace(tmp, path)


def _post_form(url: str, fields: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        method="POST",
        headers={"User-Agent": USER_AGENT,
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECS) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"{}")
        except ValueError:
            body = {}
        return exc.code, body if isinstance(body, dict) else {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise TransientError(f"network: {type(exc).__name__}") from None


def _apply_tokens(record: dict[str, Any], body: Mapping[str, Any], now: float) -> None:
    record["access_token"] = body["access_token"]
    record["access_expires_at"] = now + int(body.get("expires_in", 3600))
    record["refresh_token"] = body.get("refresh_token", record.get("refresh_token"))
    record["refreshed_at"] = now
    record["state"] = "ok"
    record.pop("error", None)
    record.pop("needs_login_alerted", None)


def _oauth_error(code: int, body: Mapping[str, Any]) -> str:
    """The OAuth error of a final 4xx, else TransientError (record left untouched).

    Only a string OAuth `error` (other than temporarily_unavailable) proves the
    grant itself was refused; a proxy page or empty body must not log the user out.
    """
    error = body.get("error")
    if code >= 500 or code == 429 or not isinstance(error, str) \
            or error == "temporarily_unavailable":
        raise TransientError(f"token http {code}")
    return error


def status(key: str) -> dict[str, Any]:
    with _locked(key):
        record = _read(key)
    if record is None:
        return {"state": "not_connected", "device": None, "error": None}
    device = record.get("device")
    public_device = None
    if device:
        public_device = {k: device[k] for k in ("verification_uri", "user_code", "expires_at")}
    return {"state": record.get("state", "not_connected"), "device": public_device,
            "error": record.get("error")}


def start_device_login(key: str, *, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    code, body = _post_form(f"{_authority()}/devicecode",
                            {"client_id": CLIENT_ID, "scope": SCOPE})
    if code != 200 or "device_code" not in body:
        raise TransientError(f"devicecode http {code} {body.get('error', '')}")
    with _locked(key):
        record = _read(key) or {}
        record["device"] = {
            "device_code": body["device_code"],
            "user_code": body["user_code"],
            "verification_uri": body["verification_uri"],
            "expires_at": now + int(body.get("expires_in", 900)),
            "interval": int(body.get("interval", 5)),
        }
        if record.get("state") != "ok":
            record["state"] = "pending"
        _write(key, record)
    return {"verification_uri": body["verification_uri"], "user_code": body["user_code"],
            "expires_in": int(body.get("expires_in", 900))}


def poll_device_login(key: str, *, now: float | None = None) -> str:
    now = time.time() if now is None else now
    with _locked(key):
        record = _read(key) or {}
        device = record.get("device")
        if not device:
            return str(record.get("state", "not_connected"))
        code, body = _post_form(f"{_authority()}/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT_ID,
            "device_code": device["device_code"],
        })
        if code == 200 and "access_token" in body:
            _apply_tokens(record, body, now)
            record.pop("device", None)
            _write(key, record)
            return "ok"
        error = _oauth_error(code, body)
        if error in ("authorization_pending", "slow_down") and now < device["expires_at"]:
            return "pending"
        outcome = "expired" if error in ("expired_token", "authorization_pending", "slow_down") else "denied"
        record.pop("device", None)
        if record.get("state") != "ok":
            record["state"] = "expired" if outcome == "expired" else "needs_login"
            record["error"] = error
        _write(key, record)
        return outcome


def _refresh_locked(key: str, record: dict[str, Any], now: float) -> str:
    code, body = _post_form(f"{_authority()}/token", {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": record["refresh_token"],
        "scope": SCOPE,
    })
    if code == 200 and "access_token" in body:
        _apply_tokens(record, body, now)
        _write(key, record)
        return str(record["access_token"])
    error = _oauth_error(code, body)
    record["state"] = "needs_login"
    record["error"] = f"{error}: {str(body.get('error_description', ''))[:160]}"
    _write(key, record)
    raise NeedsLogin(record["error"])


def _connected(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record or record.get("state") != "ok" or not record.get("refresh_token"):
        raise NeedsLogin(str((record or {}).get("error") or "not connected"))
    return record


def refresh(key: str, *, now: float | None = None) -> str:
    now = time.time() if now is None else now
    with _locked(key):
        return _refresh_locked(key, _connected(_read(key)), now)


def access_token(key: str, *, now: float | None = None, force_refresh: bool = False) -> str:
    now = time.time() if now is None else now
    with _locked(key):
        record = _connected(_read(key))
        fresh = float(record.get("access_expires_at", 0)) - now > ACCESS_SKEW_SECS
        if fresh and not force_refresh:
            return str(record["access_token"])
        return _refresh_locked(key, record, now)


def _user_keys() -> list[str]:
    directory = _token_dir()
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("tg_*.json") if _USER_KEY_RE.fullmatch(p.stem))


def refresh_all(*, now: float | None = None, min_age_secs: float = 72000.0) -> dict[str, Any]:
    now = time.time() if now is None else now
    report: dict[str, Any] = {"refreshed": 0, "needs_login": 0, "transient": 0,
                              "skipped": 0, "errors": 0, "new_needs_login": []}
    for key in _user_keys():
        try:
            with _locked(key):
                record = _read(key)
                if not record:
                    if (_token_dir() / f"{key}.json").exists():
                        report["errors"] += 1  # corrupt or non-object JSON
                    continue
                if record.get("state") == "ok" and not record.get("refresh_token"):
                    report["errors"] += 1
                    continue
                if record.get("state") == "ok":
                    if now - float(record.get("refreshed_at", 0)) < min_age_secs:
                        report["skipped"] += 1
                    else:
                        try:
                            _refresh_locked(key, record, now)
                            report["refreshed"] += 1
                        except NeedsLogin:
                            report["needs_login"] += 1
                if record.get("state") == "needs_login" and not record.get("needs_login_alerted"):
                    report["new_needs_login"].append((key, str(record.get("error", ""))))
        except TransientError:
            report["transient"] += 1
        except Exception:  # one broken record must not stop the sweep for everyone
            report["errors"] += 1
    return report


def mark_alerted(key: str) -> None:
    with _locked(key):
        record = _read(key)
        if record and record.get("state") == "needs_login":
            record["needs_login_alerted"] = True
            _write(key, record)


def fingerprint(key: str) -> str:
    """Sanitized rotation proof: state, refreshed_at, sha256(refresh_token)[:12]."""
    with _locked(key):
        record = _read(key) or {}
    digest = hashlib.sha256(str(record.get("refresh_token", "")).encode()).hexdigest()[:12]
    return f"{record.get('state', 'not_connected')} {int(record.get('refreshed_at', 0))} {digest}"


def _parse_rpc(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("{"):
        return json.loads(text)
    last: dict[str, Any] | None = None
    for line in text.splitlines():
        if line.startswith("data:") and line[5:].strip():
            message = json.loads(line[5:].strip())
            if "result" in message or "error" in message:
                last = message
    if last is None:
        raise ValueError("no JSON-RPC message in upstream response")
    return last


def upstream_rpc(
    token: str, method: str, params: dict[str, Any], rid: int | str = 1
) -> tuple[int, dict[str, Any] | None]:
    req = urllib.request.Request(
        mcp_url(),
        data=json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                         "params": params}).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/json, text/event-stream",
                 "Content-Type": "application/json",
                 "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT_SECS) as resp:
            return resp.status, _parse_rpc(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise TransientError(f"upstream: {type(exc).__name__}") from None


def _schema(tool: Mapping[str, Any]) -> str:
    return json.dumps(tool.get("inputSchema"), sort_keys=True)


def upstream_drift(snapshot_path: Path | None = None) -> list[str]:
    """Allowlisted tools whose upstream name or inputSchema differs from the snapshot.

    Uses the first connected user's token; with nobody connected it reports nothing.
    """
    data = json.loads((snapshot_path or SNAPSHOT_PATH).read_text(encoding="utf-8"))
    baked = {t["name"]: _schema(t) for t in data["tools"]}
    for key in _user_keys():
        try:
            token = access_token(key)
        except NeedsLogin:
            continue
        code, message = upstream_rpc(token, "tools/list", {})
        if code != 200 or message is None or "result" not in message:
            raise TransientError(f"tools/list http {code}")
        live = {t.get("name"): _schema(t) for t in message["result"].get("tools", [])}
        drift = []
        for name in READ_ALLOWLIST:
            if name not in live:
                drift.append(f"{name}: missing")
            elif live[name] != baked.get(name):
                drift.append(f"{name}: schema")
        return drift
    return []


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "fingerprint":
        print(fingerprint(sys.argv[2]))
        sys.exit(0)
    print("usage: m365_tokens.py fingerprint <user_key>", file=sys.stderr)
    sys.exit(2)
