from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
import email.parser
import email.policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, TextIO, TypedDict
from urllib import error, request


PAIRING_CODE_PATTERN = re.compile(r"^\d{6}$")


class DaemonSpawnError(RuntimeError):
    """Child daemon failed to start or become healthy."""


class DaemonCapacityError(RuntimeError):
    """Max daemon instances reached."""
REQUEST_CONTEXT_USER_ID_PATTERN = re.compile(r"(?m)^- user_id:\s*(\d+)\s*$")

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB — Telegram Bot API getFile limit

# Bumped whenever the per-user config layout changes so existing on-disk
# configs are cut over to the latest template on next spawn. v3-1 = native
# schema_version=3 template (Phase 1). v3-2 = fix-forward: the first v3-disk
# deploy cut per-user configs over from a STALE V1 volume template (the
# entrypoint's first-boot-only `[ ! -f ]` gate skipped re-seeding the template
# to V3 on the existing volume). The entrypoint now re-seeds the template
# unconditionally; bump the marker so cutover re-runs against the now-V3
# template. backup-only-if-not-exists keeps the original pre-V3 backup intact.
# v3-3 = + MICROSOFT_SESSION_COOKIES passthrough (admin SSO perimeter)
# v3-4 = runtime_profiles.{default,agent_default}: max_actions_per_hour=1_000_000
#        (was absent → schema default 20, throttled heavy cron digests + at/after
#        jobs once patch #17 lifted the iteration cap) + max_tool_iterations=200.
# v3-5 = + [providers.models.custom.neuralwatt] alias (neuralwatt custom-URL
#        provider, reached via bot /model override; fork patch #19). Spec
#        2026-06-19-neuralwatt-custom-provider-model-switching-design.md.
# v3-6 = neuralwatt alias native_tools=true (custom family disables native tools
#        by default -> glm-5.2-fast leaked malformed <tool_call> text; prod
#        incident 2026-06-20). neuralwatt verified to support native tool-calling.
# v3-7 = neuralwatt alias `fallback = ["opencode.go"]` — alias build path
#        ignores global model_fallbacks; per-alias fallback degrades a
#        neuralwatt 429 (rate-limit) to deepseek-v4-flash instead of error.
# v3-8 = analyst_glm bumped glm-5.1 -> glm-5.2 (zai) + new subagent
#        analyst_glm_nwt on pinned alias [providers.models.custom.neuralwatt_glm]
#        (glm-5.2 via neuralwatt, native_tools + per-alias fallback).
# v3-9 = 5 analyst subagents pinned to neutral persona workspace
#        ([agents.analyst_*.workspace] path -> template personas/analyst;
#        replaces the main-user identity in analyst system prompts).
# v3-10 = D1 fix: [mcp_bundles.all] + mcp_bundles=["all"] restored to all agents
#         (v0.8.2 secure-by-default regression — context7/lalafo-db/graylog).
# v3-11 = + codemap remote HTTP MCP (bundle grant + allowed_tools codemap__* +
#         Bearer header via __CODEMAP_API_KEY__ placeholder).
# v3-12 = + codemap-semantic remote HTTP MCP (claude-context semantic search;
#         bundle grant + allowed_tools codemap-semantic__{search_code,get_indexing_status}
#         + Bearer via __CODEMAP_SEMANTIC_API_KEY__ placeholder).
# v3-14 = + GPT-5.6 codex family (gpt-5.6-sol/terra/luna) in reliability.model_fallbacks
#         + both runtime_profile model_windows (400_000). OpenAI GA on Codex 2026-07-09;
#         bot /model buttons cdx/gpt-5.6-{sol,terra,luna}.
# v3-15 = drop gpt-5.6-luna (Fly smoke 2026-07-10: Codex OAuth backend returns
#         404 invalid_request_error for it — cheap tier is API-only, not on Codex).
#         Keeps gpt-5.6-sol + gpt-5.6-terra (both verified answering via codex).
# v3-16 = re-add gpt-5.6-luna. Root cause of the v3-15 404 is GA rollout lag, NOT a
#         bad id: id is confirmed correct (OpenAI docs) and luna shares terra's Codex
#         SKU (terra works on our account). Codex backend just hadn't rolled luna to
#         our endpoint during the 24h GA window. Dormant → self-heals; degrades to
#         deepseek-v4-flash until live. Re-smoke to confirm flip.
# v3-17 = [gateway] request_timeout_secs=1800 + long_running_request_timeout_secs=600
#         pinned in the template. Retires fork patch #8 (env-first timeout shim in
#         the Rust gateway): the shim only existed because per-user configs lacked
#         the field, so env delivered 1800. Now the typed field carries it and the
#         Rust side reads cfg.request_timeout_secs directly. Cutover re-seeds
#         existing per-user configs from the template before the next daemon spawn,
#         so there is no 30s-default window.
CURRENT_CONFIG_MARKER = "v3-18"


def sanitize_filename(filename: str) -> str:
    """Strip path components and replace unsafe characters."""
    name = Path(filename).name
    stem = Path(name).stem
    suffix = Path(name).suffix
    cleaned = re.sub(r"[^\w\-.]", "_", stem)
    if not cleaned or cleaned == "_":
        cleaned = "upload"
    return f"{cleaned}{suffix}" if suffix else cleaned


def parse_multipart(body: bytes, content_type: str) -> dict[str, object] | None:
    """Parse multipart/form-data body. Return file data and metadata, or None."""
    parser = email.parser.BytesParser(policy=email.policy.HTTP)
    headers_bytes = f"Content-Type: {content_type}\r\n\r\n".encode()
    msg = parser.parsebytes(headers_bytes + body)

    file_data: bytes | None = None
    filename: str | None = None
    mime_type: str = "application/octet-stream"
    fields: dict[str, str] = {}

    for part in msg.iter_parts():
        cd = part.get("Content-Disposition", "")
        name_match = re.search(r'name="([^"]*)"', cd)
        part_name = name_match.group(1) if name_match else ""

        if part_name == "file":
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                file_data = payload
            fn_match = re.search(r'filename="([^"]*)"', cd)
            if fn_match:
                filename = fn_match.group(1)
            ct = part.get_content_type()
            if ct and ct != "application/octet-stream":
                mime_type = ct
        else:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                fields[part_name] = payload.decode("utf-8", errors="replace")

    if file_data is None:
        return None

    if "filename" in fields:
        filename = fields["filename"]
    if "mime_type" in fields:
        mime_type = fields["mime_type"]

    return {
        "file_data": file_data,
        "filename": filename or "upload",
        "mime_type": mime_type,
    }


def _now() -> float:
    return time.time()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(slots=True)
class ManagerSettings:
    data_root: Path
    webhook_secret: str | None = None
    manager_host: str = "0.0.0.0"
    manager_port: int = 3000
    manager_base_port: int = 3001
    child_host: str = "127.0.0.1"
    request_timeout_secs: float = 30.0
    max_instances: int = 10

    @classmethod
    def from_env(cls) -> ManagerSettings:
        request_timeout = os.getenv("ZEROCLAW_MANAGER_REQUEST_TIMEOUT_SECS")
        if request_timeout is None:
            request_timeout = os.getenv("ZEROCLAW_GATEWAY_TIMEOUT_SECS", "30")
        return cls(
            data_root=Path(os.getenv("ZEROCLAW_DATA_ROOT", "/zeroclaw-data")),
            webhook_secret=os.getenv("ZEROCLAW_WEBHOOK_SECRET"),
            manager_host=os.getenv("ZEROCLAW_MANAGER_HOST", "0.0.0.0"),
            manager_port=int(os.getenv("ZEROCLAW_MANAGER_PORT", "3000")),
            manager_base_port=int(os.getenv("ZEROCLAW_MANAGER_BASE_PORT", "3001")),
            child_host=os.getenv("ZEROCLAW_CHILD_HOST", "127.0.0.1"),
            request_timeout_secs=float(request_timeout),
            max_instances=int(
                os.getenv("ZEROCLAW_MANAGER_MAX_INSTANCES", "10")
            ),
        )

    @property
    def manager_root(self) -> Path:
        return self.data_root / "manager"

    @property
    def template_root(self) -> Path:
        return self.data_root / "template"

    @property
    def shared_auth_root(self) -> Path:
        return self.data_root / "shared-auth"

    @property
    def workspaces_root(self) -> Path:
        return self.data_root / "workspaces"


@dataclass(slots=True)
class DaemonInstance:
    user_key: str
    port: int
    pid: int
    workspace_root: Path
    started_at: float
    last_used_at: float
    process: subprocess.Popen[str] | None = None


class PairingState:
    def __init__(
        self,
        state_dir: Path,
        *,
        seed_tokens: Iterable[str] | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.tokens_path = self.state_dir / "bearer_tokens.json"
        self._tokens = self._load_tokens()
        self._import_seed_tokens(seed_tokens or ())
        self.pairing_code = f"{secrets.randbelow(1_000_000):06d}"
        self.startup_log_line = (
            f"[gateway-manager] Pair now with header X-Pairing-Code: {self.pairing_code}"
        )

    def _load_tokens(self) -> set[str]:
        if not self.tokens_path.exists():
            return set()
        try:
            payload = json.loads(self.tokens_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return set()
        if not isinstance(payload, list):
            return set()
        return {token for token in payload if isinstance(token, str) and token}

    def _persist_tokens(self) -> None:
        self.tokens_path.write_text(
            json.dumps(sorted(self._tokens), indent=2) + "\n",
            encoding="utf-8",
        )

    def _import_seed_tokens(self, seed_tokens: Iterable[str]) -> None:
        changed = False
        for token in seed_tokens:
            normalized = token.strip()
            if not normalized or normalized in self._tokens:
                continue
            self._tokens.add(normalized)
            changed = True
        if changed:
            self._persist_tokens()

    def pair(self, pairing_code: str) -> dict[str, object]:
        if pairing_code != self.pairing_code:
            raise ValueError("invalid pairing code")

        token = f"zc_{secrets.token_urlsafe(24)}"
        self._tokens.add(token)
        self._persist_tokens()
        return {
            "paired": True,
            "persisted": True,
            "token": token,
            "message": "Pairing successful.",
        }

    def is_authorized(self, authorization: str | None) -> bool:
        if not authorization or not authorization.startswith("Bearer "):
            return False
        token = authorization.removeprefix("Bearer ").strip()
        return token in self._tokens


class WorkspaceBootstrapper:
    def __init__(self, settings: ManagerSettings) -> None:
        self.settings = settings

    def ensure_workspace(self, user_key: str, port: int) -> Path:
        workspace_root = self.settings.workspaces_root / user_key
        config_dir = workspace_root / ".zeroclaw"
        workspace_dir = workspace_root / "workspace"
        template_config_dir = self.settings.template_root / ".zeroclaw"
        template_workspace_dir = self.settings.template_root / "workspace"
        shared_auth_dir = self.settings.shared_auth_root

        config_dir.mkdir(parents=True, exist_ok=True)
        workspace_root.mkdir(parents=True, exist_ok=True)

        if not workspace_dir.exists():
            shutil.copytree(
                template_workspace_dir,
                workspace_dir,
                ignore=shutil.ignore_patterns(
                    "memory", "state", "logs", "cron", "uploads", "personas",
                    "*.db", "*.db-shm", "*.db-wal", "MEMORY_SNAPSHOT.md",
                ),
            )
        else:
            self._sync_missing_from_template(template_workspace_dir, workspace_dir)

        for runtime_dir in ("memory", "state", "logs", "cron", "uploads"):
            (workspace_dir / runtime_dir).mkdir(exist_ok=True)

        template_config = template_config_dir / "config.toml"
        child_config = config_dir / "config.toml"
        if not child_config.exists():
            config_text = template_config.read_text(encoding="utf-8")
            config_text = self._rewrite_gateway_config(
                config_text,
                host=self.settings.child_host,
                port=port,
            )
            config_text = config_text.rstrip("\n") + (
                f"\n\n# config-gen = {CURRENT_CONFIG_MARKER}\n"
            )
            tmp = child_config.with_suffix(".toml.tmp")
            tmp.write_text(config_text, encoding="utf-8")
            os.replace(tmp, child_config)
        else:
            # Cut an existing per-user config over to the current template
            # (no-op once the marker matches). Preserves the unique port.
            self.cutover_peruser_config(
                child_config,
                template_config,
                port,
                CURRENT_CONFIG_MARKER,
                host=self.settings.child_host,
            )

        for name in ("auth-profiles.json", ".secret_key"):
            source = shared_auth_dir / name
            target = config_dir / name
            if not source.exists():
                continue
            # Re-point drifted targets: earlier bootstraps could leave a real
            # file (from a one-off cp) or a symlink aimed at a legacy path.
            # Either way the per-user daemon then misses later auth pushes.
            if target.is_symlink():
                try:
                    if Path(os.readlink(target)).resolve() == source.resolve():
                        continue
                except OSError:
                    pass
                target.unlink()
            elif target.exists():
                target.unlink()
            target.symlink_to(source)

        return workspace_root

    _RUNTIME_DIRS = {"memory", "state", "logs", "cron", "uploads"}
    _RUNTIME_EXTS = {".db", ".db-shm", ".db-wal"}
    # Per-user runtime artifacts at workspace root that must never propagate
    # from template → user (one user's Core-memory "soul" is private).
    _RUNTIME_NAMES = {"MEMORY_SNAPSHOT.md"}
    # Template-only content: per-user configs point at the shared template
    # path (agents.analyst_*.workspace.path); never copy into user workspaces.
    _TEMPLATE_ONLY_DIRS = {"personas"}

    @classmethod
    def _sync_missing_from_template(
        cls, template_dir: Path, workspace_dir: Path
    ) -> None:
        """Copy files/dirs present in template but missing in user workspace.

        Never overwrites existing user files. Skips runtime dirs and db files.
        """
        for item in template_dir.iterdir():
            if item.name in cls._RUNTIME_DIRS:
                continue
            if item.name in cls._TEMPLATE_ONLY_DIRS:
                continue
            if item.name in cls._RUNTIME_NAMES:
                continue
            if any(item.name.endswith(ext) for ext in cls._RUNTIME_EXTS):
                continue
            if item.name == "__pycache__":
                continue
            target = workspace_dir / item.name
            if target.exists():
                if item.is_dir():
                    cls._sync_missing_from_template(item, target)
                continue
            if item.is_dir():
                shutil.copytree(
                    item,
                    target,
                    ignore=shutil.ignore_patterns(
                        "memory", "state", "logs", "cron", "uploads",
                        "*.db", "*.db-shm", "*.db-wal", "__pycache__",
                        "MEMORY_SNAPSHOT.md", "personas",
                    ),
                )
            else:
                shutil.copy2(item, target)

    @staticmethod
    def _rewrite_gateway_config(
        config_text: str,
        *,
        host: str,
        port: int,
    ) -> str:
        lines = config_text.splitlines()
        output: list[str] = []
        in_gateway = False
        in_webhook = False
        saw_gateway = False
        saw_host = False
        saw_port = False
        saw_require_pairing = False
        saw_webhook_port = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if in_gateway:
                    if not saw_host:
                        output.append(f'host = "{host}"')
                    if not saw_port:
                        output.append(f"port = {port}")
                    if not saw_require_pairing:
                        output.append("require_pairing = false")
                if in_webhook and not saw_webhook_port:
                    output.append(f"port = {port}")
                in_gateway = stripped == "[gateway]"
                in_webhook = stripped == "[channels_config.webhook]"
                if in_gateway:
                    saw_gateway = True
                    saw_host = False
                    saw_port = False
                    saw_require_pairing = False
                if in_webhook:
                    saw_webhook_port = False
                output.append(line)
                continue

            if in_gateway and stripped.startswith("host ="):
                output.append(f'host = "{host}"')
                saw_host = True
                continue

            if in_gateway and stripped.startswith("port ="):
                output.append(f"port = {port}")
                saw_port = True
                continue

            if in_gateway and stripped.startswith("require_pairing ="):
                output.append("require_pairing = false")
                saw_require_pairing = True
                continue

            if in_webhook and stripped.startswith("port ="):
                output.append(f"port = {port}")
                saw_webhook_port = True
                continue

            output.append(line)

        if in_gateway:
            if not saw_host:
                output.append(f'host = "{host}"')
            if not saw_port:
                output.append(f"port = {port}")
            if not saw_require_pairing:
                output.append("require_pairing = false")
        if in_webhook and not saw_webhook_port:
            output.append(f"port = {port}")

        if not saw_gateway:
            if output and output[-1] != "":
                output.append("")
            output.extend(
                [
                    "[gateway]",
                    f'host = "{host}"',
                    f"port = {port}",
                    "require_pairing = false",
                ]
            )

        if "[channels_config.webhook]" not in config_text:
            if output and output[-1] != "":
                output.append("")
            output.extend(
                [
                    "[channels_config.webhook]",
                    f"port = {port}",
                ]
            )

        return "\n".join(output).rstrip() + "\n"

    @staticmethod
    def cutover_peruser_config(
        cfg: Path,
        template: Path,
        port: int,
        marker: str,
        host: str,
    ) -> bool:
        """Cut an existing per-user config.toml over to the current V3 template,
        preserving the user's unique gateway port.

        The per-user config's only meaningful delta vs the (already
        secret-substituted) on-volume template is the gateway/webhook port, so
        cutover = copy template + re-inject port via _rewrite_gateway_config.

        Idempotent: a config already carrying `# config-gen = {marker}` is left
        untouched and returns False. The ORIGINAL pre-V3 config is preserved in
        `config.toml.backup` for rollback — never overwritten by a later
        cutover. Returns True when the config was (re)written.
        """
        if cfg.exists() and f"# config-gen = {marker}" in cfg.read_text(
            encoding="utf-8"
        ):
            return False

        backup = cfg.parent / "config.toml.backup"
        if not backup.exists():
            shutil.copy2(cfg, backup)

        rendered = WorkspaceBootstrapper._rewrite_gateway_config(
            template.read_text(encoding="utf-8"),
            host=host,
            port=port,
        )
        rendered = rendered.rstrip("\n") + f"\n\n# config-gen = {marker}\n"

        tmp = cfg.with_suffix(".toml.tmp")
        tmp.write_text(rendered, encoding="utf-8")
        os.replace(tmp, cfg)
        return True


SpawnProcess = Callable[[str, int, Path], subprocess.Popen[str]]
WaitUntilHealthy = Callable[[int], None]
ForwardWebhook = Callable[[DaemonInstance], tuple[int, dict[str, object]]]


class GatewayRegistry:
    def __init__(
        self,
        *,
        settings: ManagerSettings,
        bootstrapper: WorkspaceBootstrapper,
        spawn_process: SpawnProcess | None = None,
        wait_until_healthy: WaitUntilHealthy | None = None,
        clock: Callable[[], float] = _now,
    ) -> None:
        self.settings = settings
        self.bootstrapper = bootstrapper
        self.spawn_process = spawn_process or self._spawn_process
        self.wait_until_healthy = wait_until_healthy or self._wait_until_healthy
        self.clock = clock
        self._instances: dict[str, DaemonInstance] = {}
        self._next_port = settings.manager_base_port
        self._global_lock = threading.Lock()
        self._user_locks: dict[str, threading.Lock] = {}

    def _get_user_lock(self, user_key: str) -> threading.Lock:
        with self._global_lock:
            if user_key not in self._user_locks:
                self._user_locks[user_key] = threading.Lock()
            return self._user_locks[user_key]

    def ensure_instance(self, user_key: str) -> DaemonInstance:
        lock = self._get_user_lock(user_key)
        with lock:
            return self._ensure_instance_unlocked(user_key)

    def _ensure_instance_unlocked(self, user_key: str) -> DaemonInstance:
        existing = self._instances.get(user_key)
        if existing is not None:
            if self._is_alive(existing):
                existing.last_used_at = self.clock()
                return existing
            print(
                f"[gateway-manager] daemon for {user_key} (pid={existing.pid}, port={existing.port}) is dead, respawning",
                flush=True,
            )
            old_instance = existing
        else:
            old_instance = None

        if old_instance is None:
            with self._global_lock:
                if len(self._instances) >= self.settings.max_instances:
                    raise DaemonCapacityError(
                        f"max instances reached ({self.settings.max_instances})"
                    )

        # Port resolution: read from existing config, or allocate new
        existing_port = self._read_port_from_config(user_key)
        if existing_port is not None:
            with self._global_lock:
                port_owner = next(
                    (
                        i.user_key
                        for i in self._instances.values()
                        if i.port == existing_port and i.user_key != user_key
                    ),
                    None,
                )
            if port_owner is not None:
                print(
                    f"[gateway-manager] port {existing_port} held by {port_owner},"
                    f" reassigning for {user_key}",
                    flush=True,
                )
                port = self._allocate_port()
                config_path = (
                    self.settings.workspaces_root
                    / user_key
                    / ".zeroclaw"
                    / "config.toml"
                )
                self._rewrite_port_in_config(config_path, port)
            else:
                port = existing_port
                # On-demand reattach: probe configured port before spawning
                if old_instance is None and self._probe_port_health(port):
                    print(
                        f"[gateway-manager] reattaching to live daemon"
                        f" for {user_key} on port {port}",
                        flush=True,
                    )
                    now = self.clock()
                    workspace_root = self.bootstrapper.ensure_workspace(
                        user_key, port
                    )
                    instance = DaemonInstance(
                        user_key=user_key,
                        port=port,
                        pid=0,
                        workspace_root=workspace_root,
                        started_at=now,
                        last_used_at=now,
                        process=None,
                    )
                    self._instances[user_key] = instance
                    return instance
        else:
            port = self._allocate_port()

        workspace_root = self.bootstrapper.ensure_workspace(user_key, port)
        config_dir = workspace_root / ".zeroclaw"

        try:
            proc = self.spawn_process(user_key, port, config_dir)
            self.wait_until_healthy(port)
        except Exception as exc:
            if "proc" in locals() and hasattr(proc, "terminate"):
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            raise DaemonSpawnError(
                f"child daemon on port {port} did not become healthy"
            ) from exc

        self._ensure_default_cron_jobs(user_key)

        # Success: terminate old process, replace entry
        if old_instance is not None:
            self._terminate_process(old_instance)

        now = self.clock()
        pid = proc.pid if hasattr(proc, "pid") else proc
        process = proc if hasattr(proc, "terminate") else None
        instance = DaemonInstance(
            user_key=user_key,
            port=port,
            pid=pid,
            workspace_root=workspace_root,
            started_at=now,
            last_used_at=now,
            process=process,
        )
        self._instances[user_key] = instance
        return instance

    def _ensure_default_cron_jobs(self, user_key: str) -> None:
        """Best-effort: bootstrap default cron jobs (e.g. nightly retro)
        in the freshly spawned daemon's workspace. Idempotent — skips
        users who already have the job. Failures are logged and
        swallowed; they must never break daemon spawn."""
        script = (
            Path(__file__).resolve().parent / "bootstrap_default_cron_jobs.py"
        )
        if not script.is_file():
            return
        if not user_key.startswith("tg_"):
            return
        user_id = user_key[len("tg_"):]
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--workspaces-root",
                    str(self.settings.workspaces_root),
                    "--user",
                    user_id,
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                print(
                    f"[gateway-manager] cron bootstrap for {user_key} "
                    f"returned {result.returncode}: {result.stderr.strip()}",
                    file=sys.stderr,
                )
            elif result.stdout.strip():
                print(
                    f"[gateway-manager] cron bootstrap for {user_key}: "
                    f"{result.stdout.strip()}"
                )
        except Exception as exc:
            print(
                f"[gateway-manager] cron bootstrap for {user_key} failed: {exc}",
                file=sys.stderr,
            )

    def get_instance(self, user_key: str) -> DaemonInstance | None:
        return self._instances.get(user_key)

    def list_instances(self) -> list[DaemonInstance]:
        return list(self._instances.values())

    def stop_instance(self, user_key: str) -> None:
        lock = self._get_user_lock(user_key)
        with lock:
            self._stop_instance_unlocked(user_key)

    def _stop_instance_unlocked(self, user_key: str) -> None:
        """Internal — caller must hold per-user lock."""
        instance = self._instances.pop(user_key, None)
        if instance is None:
            return
        self._terminate_process(instance)

    @staticmethod
    def _terminate_process(instance: DaemonInstance) -> None:
        """Terminate a daemon process and wait for cleanup."""
        if instance.process is not None:
            try:
                instance.process.terminate()
                instance.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                instance.process.kill()
                instance.process.wait(timeout=2)
            except OSError:
                pass
        else:
            try:
                os.kill(instance.pid, signal.SIGTERM)
            except OSError:
                pass

    def stop_all(self) -> None:
        for user_key in list(self._instances):
            lock = self._get_user_lock(user_key)
            with lock:
                self._stop_instance_unlocked(user_key)

    def active_instances(self) -> int:
        return len(self._instances)

    @staticmethod
    def _is_alive(instance: DaemonInstance) -> bool:
        """Check that daemon process exists and its HTTP port responds."""
        try:
            os.kill(instance.pid, 0)
        except OSError:
            return False
        if not instance.workspace_root.exists():
            return False
        try:
            with request.urlopen(
                f"http://127.0.0.1:{instance.port}/health", timeout=2.0
            ) as resp:
                return resp.status == 200
        except (error.URLError, TimeoutError, OSError):
            return False

    def _allocate_port(self) -> int:
        with self._global_lock:
            used_ports = {inst.port for inst in self._instances.values()}
            while self._next_port in used_ports:
                self._next_port += 1
            port = self._next_port
            self._next_port += 1
            return port

    def _read_port_from_config(self, user_key: str) -> int | None:
        """Read [gateway] port from existing per-user config.toml."""
        config_path = (
            self.settings.workspaces_root / user_key / ".zeroclaw" / "config.toml"
        )
        if not config_path.exists():
            return None
        text = config_path.read_text(encoding="utf-8")
        in_gateway = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_gateway = stripped == "[gateway]"
                continue
            if in_gateway and stripped.startswith("port"):
                try:
                    return int(stripped.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    return None
        return None

    @staticmethod
    def _probe_port_health(port: int) -> bool:
        """Check if a daemon is already healthy on given port."""
        try:
            with request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=2.0
            ) as resp:
                return resp.status == 200
        except (error.URLError, TimeoutError, OSError):
            return False

    def recover_from_workspaces(self) -> None:
        """Scan existing user workspaces to set _next_port above any used port."""
        workspaces_root = self.settings.workspaces_root
        if not workspaces_root.exists():
            return
        max_port = self.settings.manager_base_port - 1
        seen_ports: dict[int, list[str]] = {}
        for user_dir in workspaces_root.iterdir():
            if not user_dir.is_dir() or not user_dir.name.startswith("tg_"):
                continue
            port = self._read_port_from_config(user_dir.name)
            if port is not None:
                max_port = max(max_port, port)
                seen_ports.setdefault(port, []).append(user_dir.name)
        self._next_port = max_port + 1
        for port, users in seen_ports.items():
            if len(users) > 1:
                print(
                    f"[gateway-manager] WARNING: port {port} claimed by {users}",
                    flush=True,
                )

    def _rewrite_port_in_config(self, config_path: Path, new_port: int) -> None:
        """Rewrite port in [gateway] and [channels_config.webhook]."""
        text = config_path.read_text(encoding="utf-8")
        text = WorkspaceBootstrapper._rewrite_gateway_config(
            text, host=self.settings.child_host, port=new_port,
        )
        config_path.write_text(text, encoding="utf-8")

    @staticmethod
    def _spawn_process(
        user_key: str, _port: int, config_dir: Path
    ) -> subprocess.Popen[str]:
        env = os.environ.copy()
        env["ZEROCLAW_CONFIG_DIR"] = str(config_dir)
        # Point workspace to the sibling directory with personality files.
        # Without this, daemon resolves workspace as {config_dir}/workspace
        # (inside .zeroclaw/), missing the template-copied personality files.
        env["ZEROCLAW_WORKSPACE"] = str(config_dir.parent / "workspace")
        # Per-user agent-browser isolation (spec §7). The daemon is keyed by
        # --session + $HOME; $HOME is shared across per-user daemons, so a per-user
        # session name is the daemon-isolation key, and the profile is the on-disk
        # cookie/login store. Both must be in shell_env_passthrough (they are) to
        # survive the shell tool's env_clear.
        workspace = config_dir.parent / "workspace"
        env["AGENT_BROWSER_PROFILE"] = str(
            workspace / "state" / "agent-browser" / "profile"
        )
        env["AGENT_BROWSER_SESSION"] = user_key
        # glab reads GITLAB_TOKEN; reuse the existing GitLab deploy token so we don't
        # provision a second secret. GITLAB_HOST comes from the image ENV. Both must be
        # in shell_env_passthrough (they are) to survive the shell tool's env_clear.
        gitlab_token = os.environ.get("GITLAB_DEPLOY_TOKEN", "")
        if gitlab_token:
            env["GITLAB_TOKEN"] = gitlab_token
        # Remove env vars that override child config and cause conflicts:
        # - ZEROCLAW_GATEWAY_PORT: would override config port, causing bind conflict with manager
        # - ZEROCLAW_GATEWAY_HOST: child must bind to localhost, not 0.0.0.0
        # - ZEROCLAW_ALLOW_PUBLIC_BIND: child is behind manager, no public binding
        for key in (
            "ZEROCLAW_GATEWAY_PORT",
            "ZEROCLAW_GATEWAY_HOST",
            "ZEROCLAW_ALLOW_PUBLIC_BIND",
        ):
            env.pop(key, None)
        # Prompt-trace is opt-in per user. ZEROCLAW_PROMPT_TRACE_USERS is a
        # comma-separated allowlist of user keys (e.g. "tg_99999"); empty/"all"/
        # "*" means every daemon. Inject the flag ONLY into targeted daemons so a
        # globally-set secret never leaks raw prompts of non-targeted prod users.
        users_raw = os.getenv("ZEROCLAW_PROMPT_TRACE_USERS", "").strip()
        trace_all = users_raw in ("", "all", "*")
        users = {u.strip() for u in users_raw.split(",") if u.strip()}
        if _truthy(os.getenv("ZEROCLAW_PROMPT_TRACE")) and (
            trace_all or user_key in users
        ):
            env["ZEROCLAW_PROMPT_TRACE"] = "1"
            max_mb = os.getenv("ZEROCLAW_PROMPT_TRACE_MAX_MB")
            if max_mb:
                env["ZEROCLAW_PROMPT_TRACE_MAX_MB"] = max_mb
        else:
            env.pop("ZEROCLAW_PROMPT_TRACE", None)
            env.pop("ZEROCLAW_PROMPT_TRACE_MAX_MB", None)
        logs_dir = config_dir.parent / "workspace" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stderr_path = logs_dir / "daemon-stderr.log"
        if stderr_path.exists() and stderr_path.stat().st_size > 1_048_576:
            prev = logs_dir / "daemon-stderr.prev.log"
            stderr_path.rename(prev)
        stderr_file = open(stderr_path, "a", encoding="utf-8")  # noqa: SIM115
        try:
            process = subprocess.Popen(  # noqa: S603
                ["zeroclaw", "daemon"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                text=True,
            )
        finally:
            stderr_file.close()
        return process

    @staticmethod
    def _wait_until_healthy(port: int) -> None:
        # Cold-start of a per-user daemon includes MCP bundle init (context7,
        # lalafo-db, graylog), which can take ~15-20s on first spawn — longer
        # than the old hardcoded 10s, causing a spurious "did not become
        # healthy" 503 on the first request after idle. Default 25s covers it;
        # override via ZEROCLAW_MANAGER_HEALTH_TIMEOUT_SECS.
        try:
            budget = float(
                os.getenv("ZEROCLAW_MANAGER_HEALTH_TIMEOUT_SECS", "25")
            )
        except ValueError:
            budget = 25.0
        deadline = time.monotonic() + budget
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1.0) as response:
                    if response.status == 200:
                        return
            except (error.URLError, TimeoutError) as exc:
                last_error = exc
                time.sleep(0.2)
        raise RuntimeError(f"child daemon on port {port} did not become healthy") from last_error


class GatewayManagerServer:
    def __init__(
        self,
        *,
        settings: ManagerSettings,
        pairing_state: PairingState,
        registry: GatewayRegistry | object | None,
        forward_webhook: Callable[..., tuple[int, dict[str, object]]],
    ) -> None:
        self.settings = settings
        self.pairing_state = pairing_state
        self.registry = registry
        self.forward_webhook = forward_webhook

    def handle_health(self) -> tuple[int, dict[str, object]]:
        known = 0
        if self.registry is not None and hasattr(self.registry, "active_instances"):
            known = int(self.registry.active_instances())
        return 200, {
            "status": "ok",
            "mode": "gateway-manager",
            "instances": known,
            "known_instances": known,
        }

    def handle_pair(self, headers: dict[str, str]) -> tuple[int, dict[str, object]]:
        pairing_code = headers.get("x-pairing-code", "").strip()
        if not PAIRING_CODE_PATTERN.match(pairing_code):
            return 400, {"error": "pairing code must be a 6-digit string"}
        try:
            return 200, self.pairing_state.pair(pairing_code)
        except ValueError:
            return 403, {"error": "invalid pairing code"}

    def handle_webhook(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, object]]:
        if not self.pairing_state.is_authorized(headers.get("authorization")):
            return 401, {"error": "missing or invalid bearer token"}

        expected_secret = self.settings.webhook_secret
        if expected_secret and headers.get("x-webhook-secret") != expected_secret:
            return 403, {"error": "missing or invalid webhook secret"}

        try:
            payload = json.loads(body.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "invalid webhook payload"}

        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            return 400, {"error": "webhook payload requires a non-empty message"}

        user_key = self._extract_user_key(headers=headers, message=message)
        if user_key is None:
            return 400, {"error": "telegram routing identity is required"}
        if self.registry is None or not hasattr(self.registry, "ensure_instance"):
            raise RuntimeError("manager registry is not configured")

        try:
            instance = self.registry.ensure_instance(user_key)
        except (DaemonSpawnError, DaemonCapacityError) as exc:
            return 503, {"error": str(exc)}
        forwarded_headers = {
            "X-Webhook-Secret": headers["x-webhook-secret"],
        }
        idempotency_key = headers.get("x-idempotency-key")
        if idempotency_key:
            forwarded_headers["X-Idempotency-Key"] = idempotency_key
        session_id = headers.get("x-session-id")
        if session_id:
            forwarded_headers["X-Session-Id"] = session_id

        return self.forward_webhook(instance, headers=forwarded_headers, body=body)

    @staticmethod
    def _extract_user_key(*, headers: dict[str, str], message: str) -> str | None:
        explicit_user_id = headers.get("x-telegram-user-id", "").strip()
        if explicit_user_id.isdigit():
            return f"tg_{explicit_user_id}"

        match = REQUEST_CONTEXT_USER_ID_PATTERN.search(message)
        if match:
            return f"tg_{match.group(1)}"
        return None

    def handle_upload(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
        content_type: str,
    ) -> tuple[int, dict[str, object]]:
        if not self.pairing_state.is_authorized(headers.get("authorization")):
            return 401, {"error": "missing or invalid bearer token"}

        expected_secret = self.settings.webhook_secret
        if expected_secret and headers.get("x-webhook-secret") != expected_secret:
            return 403, {"error": "missing or invalid webhook secret"}

        user_key = headers.get("x-telegram-user-id", "").strip()
        if not user_key.isdigit():
            return 400, {"error": "X-Telegram-User-Id header is required"}
        user_key = f"tg_{user_key}"

        parsed = parse_multipart(body, content_type)
        if parsed is None:
            return 400, {"error": "no file in upload request"}

        file_data: bytes = parsed["file_data"]  # type: ignore[assignment]
        original_name: str = parsed["filename"]  # type: ignore[assignment]
        mime_type: str = parsed["mime_type"]  # type: ignore[assignment]

        # Create only the uploads directory — do NOT call ensure_workspace() here.
        # ensure_workspace() writes config.toml with a port number, and passing a
        # dummy port=0 would corrupt the config if upload arrives before first webhook.
        uploads_dir = (
            self.settings.workspaces_root / user_key / "workspace" / "uploads"
        )
        uploads_dir.mkdir(parents=True, exist_ok=True)

        safe_name = sanitize_filename(original_name)
        stem = Path(safe_name).stem
        suffix = Path(safe_name).suffix
        unique_name = f"{stem}_{secrets.token_hex(3)}{suffix}"
        dest = uploads_dir / unique_name
        dest.write_bytes(file_data)

        print(f"[gateway-manager] upload: {unique_name} ({len(file_data)} bytes) for {user_key}", flush=True)

        return 200, {
            "path": f"uploads/{unique_name}",
            "abs_path": str(dest.resolve()),
            "original_name": original_name,
            "size": len(file_data),
            "mime_type": mime_type,
        }

    def handle_warmup(
        self,
        *,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, object]]:
        """Spawn per-user daemons for all known workspaces without invoking the
        agent. Used after deploy to discharge cron catch-up before users start
        chatting, so missed jobs don't race with the first webhook turn."""
        if not self.pairing_state.is_authorized(headers.get("authorization")):
            return 401, {"error": "missing or invalid bearer token"}

        expected_secret = self.settings.webhook_secret
        if expected_secret and headers.get("x-webhook-secret") != expected_secret:
            return 403, {"error": "missing or invalid webhook secret"}

        exclude: set[str] = {"tg_99999"}
        if body:
            try:
                payload = json.loads(body.decode())
            except (UnicodeDecodeError, json.JSONDecodeError):
                return 400, {"error": "invalid warmup payload"}
            if not isinstance(payload, dict):
                return 400, {"error": "warmup payload must be a JSON object"}
            if "exclude" in payload:
                raw = payload["exclude"]
                if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
                    return 400, {
                        "error": "warmup payload `exclude` must be a list of strings"
                    }
                exclude = set(raw)

        workspaces_root = self.settings.workspaces_root
        if not workspaces_root.exists():
            return 200, {
                "warmed": [],
                "failed": {},
                "skipped": [],
                "elapsed_ms": 0,
            }

        candidates = sorted(
            d.name
            for d in workspaces_root.iterdir()
            if d.is_dir() and d.name.startswith("tg_")
        )
        targets = [u for u in candidates if u not in exclude]
        skipped = sorted(u for u in candidates if u in exclude)

        if self.registry is None or not hasattr(self.registry, "ensure_instance"):
            return 503, {"error": "manager registry is not configured"}

        start = time.monotonic()
        warmed: list[str] = []
        failed: dict[str, str] = {}
        lock = threading.Lock()

        def _warm_one(user_key: str) -> None:
            try:
                self.registry.ensure_instance(user_key)
                with lock:
                    warmed.append(user_key)
            except (DaemonSpawnError, DaemonCapacityError) as exc:
                with lock:
                    failed[user_key] = str(exc)
            except Exception as exc:  # noqa: BLE001 — log per-user, continue with rest
                with lock:
                    failed[user_key] = (
                        f"unexpected: {exc.__class__.__name__}: {exc}"
                    )

        if targets:
            max_workers = min(len(targets), max(self.settings.max_instances, 1))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                # Consume the iterator so all tasks complete before we return.
                for _ in pool.map(_warm_one, targets):
                    pass

        elapsed_ms = int((time.monotonic() - start) * 1000)
        print(
            f"[gateway-manager] warmup: warmed={len(warmed)} failed={len(failed)} "
            f"skipped={len(skipped)} elapsed_ms={elapsed_ms}",
            flush=True,
        )
        return 200, {
            "warmed": sorted(warmed),
            "failed": failed,
            "skipped": skipped,
            "elapsed_ms": elapsed_ms,
        }


_EVENT_TOOL_CALL_START = "tool_call_start"
_EVENT_TOOL_CALL_RESULT = "tool_call_result"
_EVENT_LLM_REQUEST = "llm_request"
_EVENT_TURN_FINAL_RESPONSE = "turn_final_response"
_EVENT_TURN_CANCELLED = "turn_cancelled"
_EVENT_CONTEXT_STATE = "context_state"
_EVENT_PROVIDER_FALLBACK = "provider_fallback"


class _ToolEvent(TypedDict):
    tool: str
    success: bool
    args: str


class _ContextFullnessState(TypedDict):
    warned_at_percent: int
    last_compression_event_id: str | None
    last_percent: int


class ProgressNotifier:
    """Monitor runtime trace and send progress notifications to Telegram.

    Design:
      - tool_call_results are buffered per agent iteration
      - buffer is flushed on iteration boundary (next llm_request) or turn end
      - one status message per flush, summarized by a lightweight LLM
        (openai/gpt-oss-120b:nitro via OpenRouter); falls back to a counted
        summary if the LLM call fails
      - watchdog fires "всё ещё думаю..." once per idle gap longer than
        _WATCHDOG_THRESHOLD_SECS (no hard cap)
    """

    # Baseline label per tool; specialized shell/skill/file patterns override.
    _TOOL_LABELS: dict[str, str] = {
        "file_read": "Читаю файл",
        "file_write": "Записываю файл",
        "file_edit": "Редактирую файл",
        "shell": "Выполняю команду",
        "http_request": "HTTP запрос",
        "memory_recall": "Ищу в памяти",
        "memory_store": "Сохраняю в память",
        "content_search": "Ищу контент",
        "glob_search": "Ищу файлы",
        "cron_add": "Создаю задачу",
        "cron_list": "Проверяю задачи",
        "cron_remove": "Удаляю задачу",
        "read_skill": "Читаю скилл",
        "calculator": "Считаю",
        "weather": "Погода",
    }

    # Shell patterns — checked in order; first match wins. Use list (not dict)
    # to preserve priority for substring overlaps (e.g. `creatio_api` under
    # `find-contact`).
    _SHELL_PATTERNS: list[tuple[str, str]] = [
        # Creatio family
        ("creatio_department_report", "Формирую отчёт по отделу"),
        ("creatio_pandas_runner", "Анализирую данные"),
        ("creatio_meta", "Получаю метаданные Creatio"),
        ("find-employees", "Ищу сотрудников"),
        ("find-contact", "Ищу контакт"),
        ("find-deals", "Ищу сделки"),
        ("creatio_api", "Запрашиваю данные из Creatio"),
        # Data export + skills
        ("db_export.py", "Выгружаю данные БД"),
        ("gsheets.py info", "Читаю Google Sheets"),
        ("gsheets.py preview", "Просматриваю лист Google Sheets"),
        ("gsheets.py export", "Выгружаю лист Google Sheets"),
        ("gsheets.py read-range", "Читаю диапазон Google Sheets"),
        ("gsheets.py read-multi", "Читаю диапазоны Google Sheets"),
        ("gsheets.py append-rows", "Добавляю строки в Google Sheets"),
        ("gsheets.py batch-update", "Обновляю Google Sheets"),
        ("gsheets.py update-cell", "Обновляю ячейку Google Sheets"),
        ("gsheets.py create-sheet", "Создаю лист Google Sheets"),
        ("gsheets.py delete-sheet", "Удаляю лист Google Sheets"),
        ("gsheets.py cleanup", "Убираю старые выгрузки"),
        ("gsheets.py", "Работаю с Google Sheets"),
        # Charts — agent calls via `python3 -c "...from charts import..."`
        ("from charts import", "Рисую график"),
        ("skills/charts/scripts/cleanup.py", "Убираю старые графики"),
        # File delivery
        ("send_file_telegram.py", "Отправляю файл"),
        ("notify_telegram.py", "Отправляю уведомление"),
        # Generic Python runners
        ("pyrun.sh", "Запускаю скрипт"),
    ]

    # read_skill patterns: extract name from args, label accordingly.
    _SKILL_PATTERNS: list[tuple[str, str]] = [
        ("creatio", "Читаю скилл Creatio"),
        ("weather", "Читаю скилл погоды"),
        ("google-sheets", "Читаю скилл Google Sheets"),
        ("charts", "Читаю скилл графиков"),
        ("telegram", "Читаю скилл уведомлений"),
        ("notify", "Читаю скилл уведомлений"),
        ("brave", "Читаю скилл поиска"),
        ("search", "Читаю скилл поиска"),
        # Lalafo family
        ("lalafo-db", "Читаю скилл Lalafo DB"),
        ("lalafo-code", "Читаю скилл Lalafo код"),
        ("lalafo-location", "Читаю скилл Lalafo locations"),
    ]

    # file_read patterns.
    _FILE_READ_PATTERNS: list[tuple[str, str]] = [
        ("SKILL.md", "Читаю инструкции скилла"),
        ("ODATA_REFERENCE", "Читаю справочник OData"),
        ("references/", "Читаю справочник"),
        ("uploads/google_sheets/", "Читаю выгрузку Google Sheets"),
        ("uploads/charts/", "Читаю метаданные графика"),
        ("uploads/", "Читаю файл из uploads"),
    ]

    # http_request patterns.
    _HTTP_PATTERNS: list[tuple[str, str]] = [
        ("open-meteo", "Получаю данные о погоде"),
        ("brave", "Ищу в интернете"),
    ]

    # Thresholds tuned against observed sessions (April 2026):
    # — typical chart request: 3–5 tool calls, pure-LLM pauses ≤30s
    # — long report / gsheets: 8–12 tool calls, pure-LLM pauses ≤60s
    _WATCHDOG_THRESHOLD_SECS: float = 45.0
    _LLM_MODEL: str = "openai/gpt-oss-120b:nitro"
    _LLM_TIMEOUT_SECS: float = 8.0
    _LLM_MAX_TOKENS: int = 400
    _BUFFER_MAX_EVENTS: int = 30
    _ARGS_TRUNCATE: int = 150
    # Rate-limit for progress messages. Iterations may fire every ~2s,
    # without this the chat gets 20+ statuses per turn. Buffer accumulates
    # events across iterations until interval elapses. turn_final_response
    # always force-flushes so no events are dropped at turn end.
    _MIN_SEND_INTERVAL_SECS: float = 5.0
    # Context fullness alert thresholds. Warn ratio is below the default
    # compaction trigger (0.70), giving the user a heads-up before compaction.
    _CTX_WARN_RATIO: float = 0.60
    _CTX_WARN_RESET_RATIO: float = 0.40
    _CTX_MIN_BUMP_FOR_REWARN_PCT: int = 15

    def __init__(
        self,
        trace_path: Path,
        user_id: str,
        notify_url: str,
        notify_secret: str,
        *,
        ctx_state: dict[str, _ContextFullnessState] | None = None,
        ctx_state_lock: threading.Lock | None = None,
        operator_user_id: str = "",
        fallback_state: dict[str, float] | None = None,
        fallback_lock: threading.Lock | None = None,
        fallback_window_secs: int = 1800,
    ) -> None:
        self.trace_path = trace_path
        self.user_id = user_id
        self.notify_url = notify_url
        self.notify_secret = notify_secret
        self.operator_user_id = (operator_user_id or "").strip()
        self._fallback_window_secs = fallback_window_secs
        # shared manager-level dedup dict + lock, plumbed from build_default_server
        # outer closure exactly like _ctx_state / _ctx_state_lock.
        self._fallback_state = fallback_state  # dict[str, float] | None
        self._fallback_lock = fallback_lock  # threading.Lock | None
        # Capture the webhook start time before forwarding the request.
        # The monitor thread may open the rolling trace a bit later, after the
        # daemon has already appended the first events for the current turn.
        self._started_at = datetime.now(timezone.utc)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Track last send to enforce _MIN_SEND_INTERVAL_SECS. Initialize to
        # -inf so the first flush is never rate-limited.
        self._last_sent_ts: float = float("-inf")
        self._ctx_state = ctx_state
        self._ctx_state_lock = ctx_state_lock

    def start(self) -> None:
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _reopen_if_rolled(
        self, f: TextIO, stats: dict[str, int]
    ) -> tuple[TextIO, bool]:
        # Rust's trim_to_last_entries() uses fs::rename, giving the path a
        # new inode on every rolling trim. Our fd holds the frozen old
        # inode. Detect mismatch (or truncation) and reopen at offset 0 so
        # events written between trims are still reachable; seen_set
        # handles dedup against what we've already processed. Raises
        # OSError on stat/open failure — caller decides policy.
        path_stat = self.trace_path.stat()
        file_stat = os.fstat(f.fileno())
        if (
            path_stat.st_ino == file_stat.st_ino
            and path_stat.st_size >= f.tell()
        ):
            return f, False
        try:
            f.close()
        except Exception:
            pass
        f = open(self.trace_path, encoding="utf-8")
        f.seek(0)
        stats["reopens"] += 1
        return f, True

    def _monitor(self) -> None:
        for _ in range(50):
            if self._stop.is_set():
                return
            if self.trace_path.exists():
                break
            time.sleep(0.1)

        if not self.trace_path.exists():
            print(
                f"[ProgressNotifier] monitor exit early: trace not found "
                f"user={self.user_id} path={self.trace_path}",
                flush=True,
            )
            return

        f: TextIO = open(self.trace_path, encoding="utf-8")
        # Dedup seen events by id across reopens. Rust rolling trim creates a
        # new inode on every trim_to_last_entries(); we re-read the new file
        # from offset 0 and skip events we've already processed. Bounded LRU
        # (5000 > typical 500-entry cap × 10x).
        seen_ids: deque[str] = deque(maxlen=5000)
        seen_set: set[str] = set()
        print(
            f"[ProgressNotifier] monitor started user={self.user_id} "
            f"since={self._started_at.isoformat()} offset={f.tell()}",
            flush=True,
        )
        # FIFO queue per tool — parallel tool_call_starts and their
        # tool_call_results arrive in matching order, so popleft() pairs
        # the correct arguments with each result.
        pending_starts: dict[str, deque[str]] = {}
        buffer: list[_ToolEvent] = []
        empty_reads = 0
        state = {"last_activity": time.monotonic(), "watchdog_fired": False}
        # Diagnostic counters — printed at monitor exit so we can correlate
        # per-turn behaviour from fly logs.
        stats = {
            "events": 0,
            "tool_results": 0,
            "flush_sent": 0,
            "flush_rate_limited": 0,
            "reopens": 0,
            "dedup_skips": 0,
        }

        def mark_activity() -> None:
            state["last_activity"] = time.monotonic()
            state["watchdog_fired"] = False

        try:
            # stop() fires only after forward_webhook_to_child() returns,
            # which means daemon already serialized the webhook response
            # and every record_event for this turn has been fdatasync'd.
            # So drain = one pass over current fd + one reopen if trim
            # rolled the inode. No sleep, no retries.
            drain_reopened = False
            while True:
                stopping = self._stop.is_set()

                line = f.readline()
                if not line:
                    if stopping:
                        if drain_reopened:
                            break
                        try:
                            f, drain_reopened = self._reopen_if_rolled(
                                f, stats
                            )
                        except OSError:
                            break
                        if not drain_reopened:
                            break
                        continue

                    if (
                        not state["watchdog_fired"]
                        and (time.monotonic() - state["last_activity"])
                        > self._WATCHDOG_THRESHOLD_SECS
                    ):
                        if buffer:
                            self._flush_buffer(buffer)
                            buffer = []
                        self._send_notify("<b>Статус:</b> всё ещё думаю...")
                        state["watchdog_fired"] = True

                    empty_reads += 1
                    if empty_reads % 3 == 0:
                        try:
                            f, reopened = self._reopen_if_rolled(f, stats)
                        except OSError:
                            return
                        if reopened:
                            print(
                                f"[ProgressNotifier] reopen "
                                f"user={self.user_id} "
                                f"seen={len(seen_ids)}",
                                flush=True,
                            )
                    self._stop.wait(0.2)
                    continue
                empty_reads = 0

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Read the whole rolling trace from offset 0 and filter by the
                # notifier start time instead of pre-seeding every line as
                # "already seen". This preserves events that were appended for
                # the current webhook before the monitor thread managed to open
                # the file on Fly.
                if not self._is_current_turn_event(event):
                    continue

                # Dedup across reopens: every rolling-trim gives us a new
                # inode, and we re-read the new file from offset 0 to recover
                # events written between reopens. Skip ones we've already
                # processed.
                eid = event.get("id")
                if eid:
                    if eid in seen_set:
                        stats["dedup_skips"] += 1
                        continue
                    seen_set.add(eid)
                    if len(seen_ids) == seen_ids.maxlen:
                        seen_set.discard(seen_ids[0])
                    seen_ids.append(eid)

                et = event.get("event_type", "")
                payload = event.get("payload") or {}
                stats["events"] += 1

                if et == _EVENT_TURN_CANCELLED:
                    # Skip user-facing notify on cancellation — the bot edits
                    # M1's "Думаю..." placeholder via WebhookCancelled response,
                    # so a separate progress notify here would be a duplicate.
                    print(
                        f"[ProgressNotifier] turn_cancelled "
                        f"user={self.user_id} "
                        f"session={payload.get('session_id', '')} "
                        f"reason={payload.get('reason', '')}",
                        flush=True,
                    )
                    continue

                if et == _EVENT_CONTEXT_STATE:
                    self._handle_context_state(event)
                    continue

                if et == _EVENT_PROVIDER_FALLBACK:
                    self._handle_provider_fallback(event)
                    continue

                if et == _EVENT_TOOL_CALL_START:
                    tool = payload.get("tool", "")
                    args = payload.get("arguments", "")
                    pending_starts.setdefault(tool, deque()).append(args)
                    mark_activity()
                    continue

                if et == _EVENT_TOOL_CALL_RESULT:
                    tool = str(payload.get("tool", ""))
                    queue = pending_starts.get(tool)
                    args_str = queue.popleft() if queue else ""

                    # Skip notify_telegram — our own progress mechanism.
                    if tool == "shell" and "notify_telegram" in args_str:
                        continue

                    output = str(payload.get("output", ""))
                    message = str(event.get("message", ""))
                    if (
                        "duplicate tool call" in output.lower()
                        or "duplicate tool call" in message.lower()
                    ):
                        continue

                    buffer.append(_ToolEvent(
                        tool=tool,
                        success=bool(event.get("success", True)),
                        args=args_str[: self._ARGS_TRUNCATE],
                    ))
                    stats["tool_results"] += 1
                    mark_activity()

                    # Cap runaway iterations: flush early so a single
                    # iteration can't balloon LLM context unboundedly.
                    # Buffer cap is a hard limit — bypass rate-limit.
                    if len(buffer) >= self._BUFFER_MAX_EVENTS:
                        self._flush_buffer(buffer, force=True)
                        stats["flush_sent"] += 1
                        buffer = []
                    continue

                if et == _EVENT_LLM_REQUEST:
                    # Iteration boundary — flush only if min-interval passed.
                    # Otherwise buffer keeps growing into next iteration.
                    if buffer:
                        if self._try_flush(buffer):
                            stats["flush_sent"] += 1
                            buffer = []
                        else:
                            stats["flush_rate_limited"] += 1
                    continue

                if et == _EVENT_TURN_FINAL_RESPONSE:
                    # Turn end — always flush regardless of rate-limit.
                    if buffer:
                        self._flush_buffer(buffer, force=True)
                        stats["flush_sent"] += 1
                        buffer = []
                    pending_starts.clear()
                    continue

            # Final flush safety net: drain phase above should have
            # processed turn_final_response (which force-flushes), but if
            # the daemon exited abnormally or drain timed out mid-burst,
            # any rate-limited events still in buffer would silently drop.
            if buffer:
                self._flush_buffer(buffer, force=True)
                stats["flush_sent"] += 1
        finally:
            try:
                f.close()
            except Exception:
                pass
            print(
                f"[ProgressNotifier] monitor stopped user={self.user_id} "
                f"events={stats['events']} "
                f"tool_results={stats['tool_results']} "
                f"flush_sent={stats['flush_sent']} "
                f"flush_rate_limited={stats['flush_rate_limited']} "
                f"reopens={stats['reopens']} "
                f"dedup_skips={stats['dedup_skips']}",
                flush=True,
            )

    @staticmethod
    def _parse_event_timestamp(event: dict[str, object]) -> datetime | None:
        raw = event.get("timestamp")
        if not isinstance(raw, str) or not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _is_current_turn_event(self, event: dict[str, object]) -> bool:
        event_ts = self._parse_event_timestamp(event)
        if event_ts is None:
            # Runtime trace records currently always include timestamps. If
            # parsing fails, fall back to processing the event rather than
            # silently dropping possible current-turn progress.
            return True
        return event_ts >= self._started_at

    def _describe_tool(self, tool: str, args_str: str) -> str:
        if tool == "shell":
            for pat, label in self._SHELL_PATTERNS:
                if pat in args_str:
                    return label
            return "Выполняю команду"
        if tool == "read_skill":
            lower = args_str.lower()
            for pat, label in self._SKILL_PATTERNS:
                if pat in lower:
                    return label
            return "Читаю скилл"
        if tool == "file_read":
            for pat, label in self._FILE_READ_PATTERNS:
                if pat in args_str:
                    return label
            return "Читаю файл"
        if tool == "http_request":
            lower = args_str.lower()
            for pat, label in self._HTTP_PATTERNS:
                if pat in lower:
                    return label
            return "Отправляю HTTP запрос"
        return self._TOOL_LABELS.get(tool, tool)

    def _try_flush(self, buffer: list[_ToolEvent]) -> bool:
        """Flush buffer if the min-send-interval has elapsed.

        Returns True if a flush was issued (buffer should be cleared by caller),
        False if rate-limited (buffer should keep accumulating).
        """
        if time.monotonic() - self._last_sent_ts < self._MIN_SEND_INTERVAL_SECS:
            return False
        self._flush_buffer(buffer, force=True)
        return True

    def _flush_buffer(self, buffer: list[_ToolEvent], *, force: bool = False) -> None:
        """Send a summarized status for the buffered tool events.

        Rate-limited by `_MIN_SEND_INTERVAL_SECS` unless `force=True`
        (turn end or hard buffer cap). LLM summary is primary; falls back
        to counted summary on failure or empty reply.
        """
        if not force and (
            time.monotonic() - self._last_sent_ts < self._MIN_SEND_INTERVAL_SECS
        ):
            return
        summary = ""
        try:
            summary = self._llm_summarize(buffer)
        except Exception as exc:
            print(f"[ProgressNotifier] LLM summarize failed: {exc}", flush=True)
        if not summary:
            summary = self._dumb_summary(buffer)
        self._send_notify(f"<b>Статус:</b> {summary}")

    def _llm_summarize(self, buffer: list[_ToolEvent]) -> str:
        api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set")

        lines = []
        for ev in buffer:
            ok = "ok" if ev["success"] else "ERR"
            lines.append(f"- {ev['tool']} [{ok}] args={ev['args']}")
        user_msg = "\n".join(lines)

        system = (
            "Ты пишешь промежуточный статус для пользователя Telegram-бота. "
            "На вход — список tool calls агента за одну итерацию (имя тула, success, аргументы). "
            "Опиши ОДНОЙ короткой фразой на русском, что агент сейчас делает, опираясь на эти tool calls. "
            "Не придумывай действия, которых нет в списке. "
            "Если есть ошибки — упомяни их кратко. "
            "Без эмодзи, без markdown, без HTML-тегов, без префиксов типа 'Статус:'. "
            "Максимум 120 символов в итоговой фразе."
        )

        payload = json.dumps({
            "model": self._LLM_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            "max_tokens": self._LLM_MAX_TOKENS,
            "temperature": 0.2,
        }).encode()

        req = request.Request(
            url="https://openrouter.ai/api/v1/chat/completions",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with request.urlopen(req, timeout=self._LLM_TIMEOUT_SECS) as resp:
            data = json.loads(resp.read().decode())

        text = (data["choices"][0]["message"]["content"] or "").strip()
        text = re.sub(r"<[^>]+>", "", text)
        return text[:200]

    def _dumb_summary(self, buffer: list[_ToolEvent]) -> str:
        counts: Counter[str] = Counter()
        errors = 0
        for ev in buffer:
            counts[self._describe_tool(ev["tool"], ev["args"])] += 1
            if not ev["success"]:
                errors += 1
        parts = [f"{label}×{n}" if n > 1 else label for label, n in counts.items()]
        summary = ", ".join(parts) or "работаю"
        if errors:
            summary += f" — ошибок: {errors}"
        return summary

    def _post_notify(self, user_id: int, message: str) -> None:
        try:
            payload = json.dumps({"user_id": user_id, "message": message}).encode()
            req = request.Request(
                url=self.notify_url,
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Secret": self.notify_secret,
                },
            )
            with request.urlopen(req, timeout=5.0) as resp:
                print(
                    f"[ProgressNotifier] sent ({resp.status}) to {user_id}: {message}",
                    flush=True,
                )
        except Exception as exc:
            print(f"[ProgressNotifier] send failed to {user_id}: {exc}", flush=True)

    def _send_notify(self, message: str) -> None:
        print(f"[ProgressNotifier] dispatching: {message}", flush=True)
        self._last_sent_ts = time.monotonic()
        self._post_notify(int(self.user_id), message)

    def _handle_provider_fallback(self, event: dict) -> None:
        # fork(stabilization): a reliability fallback answered this turn. Alert the
        # OPERATOR (not the end user — their turn succeeded), deduped per
        # (session, actual_provider) within the window. Silent if no operator set.
        if not self.operator_user_id or not self.operator_user_id.isdigit():
            return  # alerts disabled / misconfigured operator id (avoid int() ValueError)
        payload = event.get("payload") or {}
        sid = str(payload.get("session_id") or "")
        actual_provider = str(payload.get("actual_provider") or "")
        actual_model = str(payload.get("actual_model") or "")
        req_provider = str(payload.get("requested_provider") or "")
        req_model = str(payload.get("requested_model") or "")
        if not actual_provider:
            return
        # Defense in depth: A1 already filters same-pair retries, but never alert
        # on a recovery where the actual identity equals the requested one.
        if actual_provider == req_provider and actual_model == req_model:
            return
        key = f"{sid}|{actual_provider}"
        now = time.monotonic()
        if self._fallback_state is not None and self._fallback_lock is not None:
            with self._fallback_lock:
                # `None`/absent = never alerted → always fire. A 0.0 default would
                # falsely dedup the FIRST alert when the host's monotonic clock is
                # still below the window (e.g. a freshly-booted VM: now - 0.0 <
                # window). Distinguish "never sent" from a real prior timestamp.
                last = self._fallback_state.get(key)
                if last is not None and now - last < self._fallback_window_secs:
                    return  # deduped within window
                self._fallback_state[key] = now
        message = (
            f"⚠ Провайдер деградировал у tg_{self.user_id}: "
            f"запрошен {req_provider or '?'}/{req_model or '?'} → "
            f"ответил {actual_provider}/{actual_model or '?'}"
        )
        self._post_notify(int(self.operator_user_id), message)

    def _handle_context_state(self, event: dict) -> None:
        payload = event.get("payload") or {}
        sid = str(payload.get("session_id") or "")
        if not sid:
            return
        if self._ctx_state is None or self._ctx_state_lock is None:
            return

        tokens_before = int(payload.get("tokens_before", 0))
        tokens_after_trim = int(payload.get("tokens_after_trim", 0))
        window = int(payload.get("context_window", 0))
        compressed = bool(payload.get("compressed", False))

        if window <= 0:
            return

        percent_before = round(tokens_before / window * 100)
        percent_after = round(tokens_after_trim / window * 100)
        warn_threshold_pct = round(self._CTX_WARN_RATIO * 100)
        reset_threshold_pct = round(self._CTX_WARN_RESET_RATIO * 100)
        passes = int(payload.get("passes", 0))
        event_id = str(event.get("id") or "")
        message: str | None = None

        with self._ctx_state_lock:
            st = self._ctx_state.get(sid) or {
                "warned_at_percent": 0,
                "last_compression_event_id": None,
                "last_percent": 0,
            }

            if compressed and event_id != st["last_compression_event_id"]:
                st["last_compression_event_id"] = event_id
                st["warned_at_percent"] = 0
                st["last_percent"] = percent_after
                self._ctx_state[sid] = st
                if passes > 0:
                    message = (
                        f"📉 Сжал историю: {tokens_before:,} → "
                        f"{tokens_after_trim:,} токенов "
                        f"({passes} итераций суммаризации)"
                    )
                else:
                    message = (
                        "📉 Подрезал длинные tool-results: "
                        f"{tokens_before:,} → {tokens_after_trim:,} токенов "
                        "(без LLM суммаризации)"
                    )
            else:
                should_warn = (
                    not compressed
                    and percent_before >= warn_threshold_pct
                    and (
                        st["warned_at_percent"] == 0
                        or percent_before
                        >= st["warned_at_percent"]
                        + self._CTX_MIN_BUMP_FOR_REWARN_PCT
                    )
                )
                if should_warn:
                    st["warned_at_percent"] = percent_before
                    message = (
                        f"⚠ Контекст {percent_before}% "
                        f"({tokens_before:,} / {window:,} токенов) — "
                        "приближается к порогу компакции"
                    )
                elif (
                    percent_after < reset_threshold_pct
                    and st["warned_at_percent"] != 0
                ):
                    st["warned_at_percent"] = 0
                st["last_percent"] = percent_after
                self._ctx_state[sid] = st

        if message is not None:
            self._send_notify(message)


def forward_webhook_to_child(
    instance: DaemonInstance,
    *,
    headers: dict[str, str],
    body: bytes,
    timeout: float = 1800.0,
) -> tuple[int, dict[str, object]]:
    req = request.Request(
        url=f"http://127.0.0.1:{instance.port}/webhook",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            **headers,
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode())
            return response.status, payload
    except error.HTTPError as exc:
        payload = json.loads(exc.read().decode())
        return exc.code, payload
    except error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            return 504, {"error": "gateway timeout forwarding to child daemon"}
        return 502, {"error": f"child unreachable: {exc.reason}"}
    except TimeoutError:
        return 504, {"error": "gateway timeout forwarding to child daemon"}


def _raise_keyboard_interrupt(_signum: int, _frame: object | None) -> None:
    raise KeyboardInterrupt()


def install_shutdown_signal_handlers() -> None:
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    signal.signal(signal.SIGINT, _raise_keyboard_interrupt)


def build_default_server(settings: ManagerSettings) -> GatewayManagerServer:
    legacy_bearer_token = os.getenv("ZEROCLAW_BEARER_TOKEN", "").strip()
    pairing_state = PairingState(
        settings.manager_root,
        seed_tokens=[legacy_bearer_token] if legacy_bearer_token else (),
    )
    registry = GatewayRegistry(
        settings=settings,
        bootstrapper=WorkspaceBootstrapper(settings),
    )
    registry.recover_from_workspaces()
    timeout = settings.request_timeout_secs
    notify_url = os.getenv("NOTIFY_URL", "")
    notify_secret = os.getenv("NOTIFY_SECRET", "")
    ctx_state: dict[str, _ContextFullnessState] = {}
    ctx_state_lock = threading.Lock()
    # fork(stabilization): operator alerts on provider fallback (A2). Shared
    # manager-level dedup dict + lock, plumbed into every ProgressNotifier
    # exactly like ctx_state. Operator id / window read from env (safe defaults:
    # empty operator → alerts disabled).
    operator_user_id = os.environ.get("ZEROCLAW_OPERATOR_USER_ID", "")
    fallback_window_secs = int(
        os.environ.get("PROVIDER_FALLBACK_ALERT_WINDOW_SECS", "1800")
    )
    fallback_state: dict[str, float] = {}
    fallback_lock = threading.Lock()

    def _forward(
        instance: DaemonInstance,
        *,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, object]]:
        notifier: ProgressNotifier | None = None
        user_id = instance.user_key.removeprefix("tg_")
        if notify_url and user_id.isdigit():
            trace_path = (
                instance.workspace_root / "workspace" / "logs" / "runtime-trace.jsonl"
            )
            notifier = ProgressNotifier(
                trace_path=trace_path,
                user_id=user_id,
                notify_url=notify_url,
                notify_secret=notify_secret,
                ctx_state=ctx_state,
                ctx_state_lock=ctx_state_lock,
                operator_user_id=operator_user_id,
                fallback_state=fallback_state,
                fallback_lock=fallback_lock,
                fallback_window_secs=fallback_window_secs,
            )
            notifier.start()
        try:
            return forward_webhook_to_child(
                instance, headers=headers, body=body, timeout=timeout
            )
        finally:
            if notifier:
                notifier.stop()

    return GatewayManagerServer(
        settings=settings,
        pairing_state=pairing_state,
        registry=registry,
        forward_webhook=_forward,
    )


class _RuntimeHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        app: GatewayManagerServer,
    ) -> None:
        self.app = app
        super().__init__(server_address, _RuntimeRequestHandler)


class _RuntimeRequestHandler(BaseHTTPRequestHandler):
    server: _RuntimeHTTPServer

    def do_GET(self) -> None:
        try:
            if self.path != "/health":
                self._write_json(404, {"error": "not found"})
                return
            status_code, payload = self.server.app.handle_health()
            self._write_json(status_code, payload)
        except Exception as exc:
            print(f"[gateway-manager] unhandled error in GET: {exc}", flush=True)
            self._write_json(500, {"error": "internal server error"})

    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))

            # Early reject for /upload exceeding size limit
            if self.path == "/upload" and content_length > MAX_UPLOAD_SIZE:
                self._write_json(413, {"error": "file exceeds 20 MB limit"})
                return

            body = self.rfile.read(content_length) if content_length else b""
            headers = {key.lower(): value for key, value in self.headers.items()}

            if self.path == "/pair":
                status_code, payload = self.server.app.handle_pair(headers)
                self._write_json(status_code, payload)
                return

            if self.path == "/webhook":
                status_code, payload = self.server.app.handle_webhook(
                    headers=headers,
                    body=body,
                )
                self._write_json(status_code, payload)
                return

            if self.path == "/upload":
                content_type = headers.get("content-type", "")
                status_code, payload = self.server.app.handle_upload(
                    headers=headers,
                    body=body,
                    content_type=content_type,
                )
                self._write_json(status_code, payload)
                return

            if self.path == "/warmup":
                status_code, payload = self.server.app.handle_warmup(
                    headers=headers,
                    body=body,
                )
                self._write_json(status_code, payload)
                return
        except Exception as exc:
            print(f"[gateway-manager] unhandled error in POST: {exc}", flush=True)
            self._write_json(500, {"error": "internal server error"})
            return

        self._write_json(404, {"error": "not found"})

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write_json(self, status_code: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> int:
    settings = ManagerSettings.from_env()
    app = build_default_server(settings)
    print(
        f"[gateway-manager] public edge listening on {settings.manager_host}:{settings.manager_port}",
        flush=True,
    )
    print(app.pairing_state.startup_log_line, flush=True)

    server = _RuntimeHTTPServer((settings.manager_host, settings.manager_port), app)
    install_shutdown_signal_handlers()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        registry = app.registry
        if registry is not None and hasattr(registry, "stop_all"):
            registry.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
