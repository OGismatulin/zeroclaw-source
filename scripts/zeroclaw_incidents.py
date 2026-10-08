#!/usr/bin/env python3
"""Deterministic incident digest over per-user runtime evidence.

Reads what actually broke (tool failures, provider failures, cron runs,
delegate results) and keeps it in a durable daily snapshot, because the
runtime trace is a 5000-entry ring that no longer covers a full report
window for an active user.
"""

from __future__ import annotations

from collections.abc import Mapping
from collections import Counter
from dataclasses import dataclass, field, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from zoneinfo import ZoneInfo
import argparse
import json
import os
import re
import sqlite3
import sys

try:  # the image ships both scripts side by side; tests import from scripts/
    import volume_janitor
except ImportError:  # pragma: no cover - packaging guard
    from scripts import volume_janitor  # type: ignore[no-redef]

MAX_ERROR_CHARS = 400
MAX_DETAIL_CHARS = 300
#: The report covers a LOCAL day; every stamp it prints is in this zone.
DEFAULT_TIMEZONE = "Asia/Bishkek"
DEFAULT_SWEEP_INTERVAL_SECS = 1800.0


def _clip(text: object, limit: int) -> str:
    value = "" if text is None else str(text)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[:limit] + "…"


REDACTED = "[REDACTED]"
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL),
     REDACTED),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    (re.compile(
        r"(?i)\b([\w.-]*(?:token|secret|password|passwd|api[_-]?key|authorization|credential)[\w.-]*)"
        r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
    ), rf"\1\2{REDACTED}"),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}"), REDACTED),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bfo1_[A-Za-z0-9_-]{10,}"), REDACTED),
    (re.compile(r"\bFlyV1\s+\S+"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),
)


def _scrub(text: object) -> str:
    value = "" if text is None else str(text)
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _safe_clip(text: object, limit: int) -> str:
    return _clip(_scrub(text), limit)


@dataclass(frozen=True, slots=True)
class Incident:
    id: str
    ts: str
    user: str
    source: str
    severity: str
    channel: str
    channel_ref: str | None
    kind: str
    tool: str | None
    agent_alias: str | None
    model: str | None
    provider: str | None
    error_kind: str | None
    error_disposition: str | None
    error: str
    detail: str | None
    location: str | None
    turn_id: str | None
    gate: bool
    tool_call_id: str | None = None
    task_ids: list[str] | None = None
    policy_reason: str | None = None
    input_path: str | None = None
    parent_tool: str | None = None
    gate_reason: str | None = None

    def as_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True)


def _native_kind(row: dict) -> str | None:
    event = row.get("event") or {}
    category = event.get("category")
    severity = row.get("severity_text")
    if event.get("outcome") == "failure":
        if category == "tool":
            return "tool_failure"
        if category == "provider":
            return "provider_failure"
        return "runtime_error"
    if severity == "ERROR":
        return "runtime_error"
    attrs = row.get("attributes") or {}
    if severity == "WARN" and category == "provider" and attrs.get("error_kind"):
        return "provider_retry"
    return None


def _legacy_kind(row: dict) -> str | None:
    if row.get("success") is not False:
        return None
    etype = row.get("event_type") or ""
    if etype == "mcp_connect_failure":
        return "mcp_failure"
    if etype == "tool_call_result":
        return "tool_failure"
    return "runtime_error"


def classify_channel(row: dict, zc: dict) -> tuple[str, str | None]:
    """Attribute one trace row to its ORIGIN channel. Order is load-bearing.

    A jira run is launched from a cron job and executes through delegates, so
    the most specific profile must win or jira incidents dissolve into cron.
    Provider and MCP failures are a `kind`, never a channel: nearly all of
    them happen inside a cron job, and a separate "provider" section would
    empty the section the operator actually looks at.
    """
    if zc.get("runtime_profile") == "jira_analysis":
        return "jira", zc.get("agent_alias")
    if zc.get("cron_job_id"):
        return "cron", zc.get("cron_job_id")
    if zc.get("agent_alias"):
        return "delegate", zc.get("agent_alias")
    return "chat", None


_POLICY_BLOCK_PREFIX = "Command not allowed by security policy: "
# Verbs the shell policy blocks outright: the block IS the guard working.
# pip/pip3/npm/cargo are IN autonomy.allowed_commands (config.toml:499-533),
# so a block naming them is about how the command was written, not the
# guard doing its job — removed (fix round 1, F6). sed/mkdir/awk/tee are the
# original's four; rm/mv/chmod/chown/sudo/kill/dd are genuinely outside the
# live allowlist and stay.
_GUARD_DIRECT_CMD_RE = re.compile(
    r"^\s*(sed|mkdir|awk|tee|rm|mv|chmod|chown|sudo|kill|dd)\b"
)
# Coordinator poking directly at cron/jobs.db is discovery-ban territory
# (fix round 1, F2), but only when attributable to a known, non-"unknown"
# alias — an unknown/missing alias must never be assumed to be the
# coordinator.
_CRON_DB_RE = re.compile(r"\bcron/jobs\.db\b")
_CANCELLED_BY_USER = "request cancelled by user"
# Exact literal (fix round 1, F3): equality against the WHOLE stripped
# error, never a substring — the same JSON embedded in a larger genuinely
# broken message is a real defect, not the idempotency fence.
_VIS_WORKER_BOUND = '{"error": "visualization worker is already bound"}'
_TIMEOUT_RE = re.compile(r"tim(ed|e) ?out", re.IGNORECASE)
# Mirrors extract_day.py: a bare `analyst` alias must disqualify too.
_ANALYST_ALIAS_RE = re.compile(r"^analyst(_|$)")
# Whitelists only the two ported actions (fix round 1, F5) — the old
# pattern silenced EVERY disabled jira action, including a genuinely
# misconfigured create_ticket. Accepts straight quotes (the live form),
# backticks (the brief's original test), or no quote at all.
_JIRA_MYSELF_RE = re.compile(r"^Action ['`]?(myself|list_projects)['`]? is not enabled")
# Load-bearing, not belt (fix round 1, F4): the live text is lowercase
# `state_conflict: attachment[0] is missing: ...`, which the case-sensitive
# "StateConflict" check does not catch. Checked before any literal/pattern
# match so it wins even over an apparent guard-literal prefix.
_ATTACHMENT_MISSING_RE = re.compile(r"attachment\[[^\]]*\]\s+is\s+missing")
_GATE_LITERALS = (
    "Skipped duplicate tool call",
    "Cancelled by hook:",
    # Defensive only: this WARN is not captured by the rules in spec 4.2.
    "Cost tracking: no pricing entry found",
)


def is_expected_gate(error: str, tool: str | None, agent_alias: str | None) -> bool:
    """True when the failure is a guard doing its job, not a defect.

    Ported (not imported) from the nightly-retro classifier: that file lives
    in the user workspace and syncs on its own cadence, so the image cannot
    depend on it. Disqualifications come first — never mask a real bug.
    """
    if not error:
        return False
    if _ATTACHMENT_MISSING_RE.search(error):
        return False
    if _TIMEOUT_RE.search(error):
        return False
    if "StateConflict" in error:
        return False
    if agent_alias and _ANALYST_ALIAS_RE.match(agent_alias):
        return False
    stripped = error.strip()
    if stripped == _VIS_WORKER_BOUND:
        return True
    if tool == "jira" and _JIRA_MYSELF_RE.match(stripped):
        return True
    if error.startswith(_POLICY_BLOCK_PREFIX):
        cmd = error[len(_POLICY_BLOCK_PREFIX):]
        if _GUARD_DIRECT_CMD_RE.match(cmd):
            return True
        if _CRON_DB_RE.search(cmd):
            return bool(agent_alias) and agent_alias != "unknown"
        return False
    return any(error.startswith(literal) for literal in _GATE_LITERALS)


POLICY_REASONS = frozenset({
    "readonly", "command_not_allowed", "shell_expansion", "process_substitution",
    "output_redirect", "input_redirect", "background", "argument_not_allowed",
    "path_not_allowed", "approval_required", "high_risk", "invalid_syntax",
})
LEGACY_OUTPUT_LIMIT = 262144
MAX_TASK_IDS = 20
MAX_ID_CHARS = 128
_SECRET_PATH_RE = re.compile(
    r"(^|/)(\.env[^/]*|\.ssh|\.aws|\.gnupg|\.netrc|secrets?|credentials?|auth[-_.]?profiles?[^/]*"
    r"|[^/]*\.(pem|key|p12|pfx)|id_(rsa|dsa|ecdsa|ed25519)|[^/]*(token|password|secret)[^/]*)(/|$)",
    re.IGNORECASE,
)
_WORKSPACE_ABS_RE = re.compile(r"^/zeroclaw-data/workspaces/tg_[^/]+/workspace/")


def _as_diagnostic(value: object) -> dict | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and len(value) <= LEGACY_OUTPUT_LIMIT:
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _legacy_output_diagnostic(output: object) -> dict | None:
    if isinstance(output, dict):
        data = output.get("data")
        if isinstance(data, dict):
            return data
        output = output.get("text")
    if not isinstance(output, str) or len(output) > LEGACY_OUTPUT_LIMIT:
        return None
    if output.startswith("{"):
        start = 0
    else:
        marker = output.find("\n{")
        if marker < 0:
            return None
        start = marker + 1
    try:
        parsed, _end = json.JSONDecoder().raw_decode(output, start)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _diagnostic(attrs: dict) -> dict | None:
    if "tool_diagnostic" in attrs:
        return _as_diagnostic(attrs.get("tool_diagnostic"))
    return _legacy_output_diagnostic(attrs.get("output"))


def _policy_reason(diagnostic: dict | None) -> str | None:
    if not diagnostic or "policy_reason" not in diagnostic:
        return None
    value = diagnostic.get("policy_reason")
    return value if isinstance(value, str) and value in POLICY_REASONS else "unknown"


def _id_list(value: object) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return [
        _clip(item, 64) for item in value[:MAX_TASK_IDS]
        if isinstance(item, (str, int)) and not isinstance(item, bool)
    ]


def _await_outcome(diagnostic: dict | None) -> tuple[str | None, list[str] | None]:
    if not diagnostic or diagnostic.get("status") not in ("timeout", "complete"):
        return None, None
    pending = _id_list(diagnostic.get("pending"))
    missing = _id_list(diagnostic.get("missing"))
    failed = _id_list(diagnostic.get("failed"))
    if pending is None or missing is None or failed is None:
        return None, None
    task_ids = list(dict.fromkeys([*failed, *pending, *missing])) or None
    if failed:
        return "tool_failure", task_ids
    if missing:
        return "delegate_missing", task_ids
    if pending:
        return "delegate_wait", task_ids
    return None, None


def _normalize_input_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    raw = _WORKSPACE_ABS_RE.sub("", raw)
    if raw.startswith("/") or raw.startswith("~") or "\x00" in raw:
        return "outside_workspace"
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return "outside_workspace"
    cleaned = "/".join(parts)
    if not cleaned:
        return None
    if _SECRET_PATH_RE.search(cleaned):
        return "sensitive_path"
    return _safe_clip(cleaned, MAX_DETAIL_CHARS)


_GREP_HEAD_RE = re.compile(r"(?:git(?:\s+-C\s+\S+)?\s+)?grep\s")


def _last_segment(command: str) -> str:
    quote = None
    start = 0
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif command.startswith(("||", "&&"), i):
            start = i + 2
            i += 2
            continue
        elif ch in "|;":
            start = i + 1
        i += 1
    return command[start:]


def _is_grep_no_match(command: object, output: object, error: object) -> bool:
    if not isinstance(command, str):
        return False
    last = _last_segment(command).lstrip()
    if not _GREP_HEAD_RE.match(last):
        return False
    if "2>" in last:
        return False
    text = output.get("text") if isinstance(output, dict) else output
    if not isinstance(text, str) or text.strip():
        return False
    return not str(error or "").strip()


def normalize_trace_row(row: dict, user: str) -> Incident | None:
    """Map one trace row (native schema_version=2 OR legacy) to an Incident.

    Returns None for rows that are not failures. Counting by `event_type`
    alone undercounts ~37x: native rows put the event name in `message`.
    """
    if not isinstance(row, dict):
        return None
    native = "schema_version" in row
    kind = _native_kind(row) if native else _legacy_kind(row)
    if kind is None:
        return None
    ident = str(row.get("id") or "")
    ts = str(row.get("@timestamp") or row.get("timestamp") or "")
    if not ident or not ts:
        return None
    zc = row.get("zeroclaw")
    zc = zc if isinstance(zc, dict) else {}
    attrs = row.get("attributes")
    attrs = attrs if isinstance(attrs, dict) else {}
    payload = row.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    tool = attrs.get("tool") or zc.get("tool") or payload.get("tool")
    envelope = zc.get("tool")
    parent_tool = str(envelope) if envelope and tool and str(envelope) != str(tool) else None
    if kind == "mcp_failure" and not tool:
        tool = payload.get("server")
    command = None
    input_path = None
    raw_input = attrs.get("input")
    if isinstance(raw_input, dict):
        command = raw_input.get("command")
        input_path = _normalize_input_path(raw_input.get("path"))
    if native:
        error = attrs.get("error") or attrs.get("error_reason") or row.get("message")
    else:
        error = payload.get("output") or payload.get("error") or row.get("message")
    location = None
    if attrs.get("_file"):
        location = f"{attrs['_file']}:{attrs.get('_line', '?')}"
    diagnostic = _diagnostic(attrs) if native else None
    policy_reason = _policy_reason(diagnostic)
    task_ids = None
    if kind == "tool_failure":
        refined, task_ids = _await_outcome(diagnostic)
        if refined:
            kind = refined
    call_id = attrs.get("tool_call_id")
    call_id = _clip(call_id, MAX_ID_CHARS) if call_id else None
    clipped_error = _safe_clip(error, MAX_ERROR_CHARS)
    channel, channel_ref = classify_channel(row, zc)
    gate = is_expected_gate(clipped_error, str(tool) if tool else None, zc.get("agent_alias"))
    gate_reason = None
    if (
        native and not gate and kind == "tool_failure" and str(tool) == "shell"
        and policy_reason is None
        and _is_grep_no_match(command, attrs.get("output"), attrs.get("error"))
    ):
        gate, gate_reason = True, "no_match"
    if not gate and kind == "provider_failure" and clipped_error.strip() == _CANCELLED_BY_USER:
        gate, gate_reason = True, "cancelled"
    return Incident(
        id=ident,
        ts=ts,
        user=user,
        source="trace",
        severity=str(row.get("severity_text") or "WARN"),
        channel=channel,
        channel_ref=channel_ref,
        kind=kind,
        tool=str(tool) if tool else None,
        agent_alias=zc.get("agent_alias"),
        model=zc.get("model") or attrs.get("model"),
        provider=zc.get("model_provider") or attrs.get("model_provider"),
        error_kind=attrs.get("error_kind"),
        error_disposition=attrs.get("error_disposition"),
        error=clipped_error,
        detail=_safe_clip(command, MAX_DETAIL_CHARS) if command else None,
        location=location,
        turn_id=row.get("turn_id") or row.get("trace_id"),
        gate=gate,
        gate_reason=gate_reason,
        tool_call_id=call_id or None,
        task_ids=task_ids,
        policy_reason=policy_reason,
        input_path=input_path,
        parent_tool=parent_tool,
    )


CRON_FAILURE_STATUSES = ("error", "degraded")
CRON_OK_STATUS = "ok"
CRON_DEGRADED_JOBS = frozenset({"lalafo-errors-digest", "lalafo-commits-digest"})


def _is_degraded_output(output: object) -> bool:
    if not isinstance(output, str):
        return False
    for line in output.splitlines():
        if line.strip():
            return line.strip().startswith("⚠")
    return False
_KIND_RE = re.compile(r"\bkind=([a-z_]+)")
_DISPOSITION_RE = re.compile(r"\bdisposition=([a-z_]+)")


def _parse_ts(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


SOURCE_OK = "ok"
SOURCE_NOT_INITIALIZED = "not_initialized"
SOURCE_UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class SourceRead:
    incidents: list[Incident]
    status: str


def _missing_status(*, seen: bool, never_created: bool) -> str:
    if seen or not never_created:
        return SOURCE_UNAVAILABLE
    return SOURCE_NOT_INITIALIZED


def _connect_ro(db: Path) -> sqlite3.Connection | None:
    if not db.is_file():
        return None
    try:
        return sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return None


def cron_job_names(workspace: Path) -> dict[str, str]:
    """job_id -> human name. Trace rows only carry the id."""
    con = _connect_ro(workspace / "cron" / "jobs.db")
    if con is None:
        return {}
    try:
        return {str(i): str(n) for i, n in con.execute("SELECT id, name FROM cron_jobs") if n}
    except sqlite3.Error:
        return {}
    finally:
        con.close()


def read_cron_failures(
    workspace: Path,
    since: datetime,
    until: datetime,
    user: str,
    *,
    seen: bool = False,
    never_created: bool = False,
) -> SourceRead:
    """Failed cron runs from the per-user jobs.db (read-only, never written).

    `cron_runs.status` is ok | error | degraded (`skipped` lives on
    cron_jobs.last_status, not here). A failed delivery appends
    `delivery failed: …` to output, so the tail of output is the informative
    line.
    """
    db = workspace / "cron" / "jobs.db"
    if not db.is_file():
        return SourceRead([], _missing_status(seen=seen, never_created=never_created))
    con = _connect_ro(db)
    if con is None:
        return SourceRead([], SOURCE_UNAVAILABLE)
    try:
        rows = con.execute(
            "SELECT r.job_id, r.started_at, r.status, r.output, j.name"
            " FROM cron_runs r LEFT JOIN cron_jobs j ON j.id = r.job_id"
            " WHERE r.status IN (?, ?, ?) AND r.started_at >= ?",
            (*CRON_FAILURE_STATUSES, CRON_OK_STATUS,
             since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")),
        ).fetchall()
    except sqlite3.Error:
        return SourceRead([], SOURCE_UNAVAILABLE)
    finally:
        con.close()
    out: list[Incident] = []
    for job_id, started_at, status, output, name in rows:
        ts = _parse_ts(started_at)
        if ts is None or not (since <= ts < until):
            continue
        if status == CRON_OK_STATUS:
            if name not in CRON_DEGRADED_JOBS or not _is_degraded_output(output):
                continue
            first = next(line.strip() for line in output.splitlines() if line.strip())
            kind, severity, message = "cron_degraded", "WARN", first
        else:
            text = (output or "").strip().splitlines()
            kind = "cron_failure"
            severity = "ERROR" if status == "error" else "WARN"
            message = text[-1] if text else f"cron run {status}"
        out.append(
            Incident(
                id=f"cron:{job_id}:{started_at}", ts=str(started_at), user=user,
                source="cron", severity=severity,
                channel="cron", channel_ref=name or job_id, kind=kind,
                tool=None, agent_alias=None, model=None, provider=None,
                error_kind=status, error_disposition=None,
                error=_safe_clip(message, MAX_ERROR_CHARS), detail=None, location=None,
                turn_id=None, gate=False,
            )
        )
    return SourceRead(out, SOURCE_OK)


def read_delegate_failures(
    workspace: Path,
    since: datetime,
    until: datetime,
    user: str,
    *,
    seen: bool = False,
    never_created: bool = False,
) -> SourceRead:
    """Terminal delegate failures; `error` carries TerminalProviderFailure."""
    root = workspace / "delegate_results"
    if not root.exists():
        return SourceRead([], _missing_status(seen=seen, never_created=never_created))
    if not root.is_dir():
        return SourceRead([], SOURCE_UNAVAILABLE)
    out: list[Incident] = []
    status = SOURCE_OK
    try:
        paths = sorted(root.glob("*.json"))
    except OSError:
        return SourceRead([], SOURCE_UNAVAILABLE)
    for path in paths:
        if path.name.endswith(".progress.json"):
            continue
        # Nothing prunes delegate_results, so this directory only grows and is
        # re-read 48x/day on the public edge. A file last written before the
        # window cannot carry a `finished_at` inside it, so skip without opening.
        try:
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < since:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            status = SOURCE_UNAVAILABLE
            continue
        if not isinstance(data, dict) or data.get("status") not in ("failed", "cancelled"):
            continue
        finished = data.get("finished_at") or ""
        ts = _parse_ts(finished)
        if ts is None or not (since <= ts < until):
            continue
        error = str(data.get("error") or "")
        kind_match = _KIND_RE.search(error)
        disp_match = _DISPOSITION_RE.search(error)
        task_id = data.get("task_id")
        out.append(
            Incident(
                id=f"delegate:{task_id}:{finished}", ts=str(finished),
                user=user, source="delegate", severity="ERROR", channel="delegate",
                channel_ref=data.get("agent"), kind="delegate_failure", tool=None,
                agent_alias=data.get("agent"), model=None, provider=None,
                error_kind=kind_match.group(1) if kind_match else None,
                error_disposition=disp_match.group(1) if disp_match else None,
                error=_safe_clip(error, MAX_ERROR_CHARS), detail=None, location=None,
                turn_id=None, gate=False,
                task_ids=[_clip(task_id, 64)] if task_id else None,
            )
        )
    return SourceRead(out, status)


SNAPSHOT_DIRNAME = "incidents"
EPISODE_GAP_SECS = 120.0
RECOVERY_WINDOW_SECS = 300.0
ABSORB_WINDOW_SECS = 300.0
RECOVERY_KIND = "recovery"


def recovery_marker(row: dict, user: str) -> dict | None:
    if row.get("message") != "llm_response":
        return None
    event = row.get("event") or {}
    if event.get("outcome") != "success":
        return None
    attrs = row.get("attributes") or {}
    zc = row.get("zeroclaw") or {}
    ident, ts = row.get("id"), row.get("@timestamp")
    if not ident or not ts or not attrs.get("model"):
        return None
    return {"kind": RECOVERY_KIND, "id": f"recovery:{ident}", "ts": str(ts), "user": user,
            "agent_alias": zc.get("agent_alias"), "model": attrs.get("model"),
            "trace_id": attrs.get("trace_id") or row.get("trace_id")}


def snapshot_dir(data_root: Path) -> Path:
    return data_root / "observability" / SNAPSHOT_DIRNAME


def _known_ids(path: Path, *, markers: bool = False) -> set[str]:
    known: set[str] = set()
    if not path.is_file():
        return known
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or (row.get("kind") == RECOVERY_KIND) != markers:
            continue
        ident = row.get("id")
        if ident:
            known.add(str(ident))
    return known


def _previous_sources_seen(out_dir: Path) -> dict[str, set[str]]:
    try:
        files = sorted(out_dir.glob("*.jsonl"), reverse=True)
    except OSError:
        return {}
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or row.get("kind") != "sweep":
                continue
            sources = row.get("sources")
            if not isinstance(sources, dict):
                return {}
            return {
                str(user): {str(name) for name in info.get("sources_seen", []) if name}
                for user, info in sources.items()
                if isinstance(info, dict) and isinstance(info.get("sources_seen"), list)
            }
    return {}


def delegate_never_created(workspace: Path, name: str) -> bool:
    return name == "delegate"


def sweep(
    data_root: Path,
    now: datetime,
    *,
    apply: bool = True,
    timezone_name: str = DEFAULT_TIMEZONE,
    retention_days: int = 14,
    max_per_day: int = 20000,
    lifecycle_evidence: Callable[[Path, str], bool] | None = None,
) -> dict:
    """Capture new failures into the durable daily snapshot. Never raises.

    The whole file is re-read every run on purpose: a rolling trace renames
    its file on every event, so a byte offset cannot be trusted.
    """
    tz = ZoneInfo(timezone_name)
    out_dir = snapshot_dir(data_root)
    appended = 0
    truncated = False
    errors: list[str] = []
    sources: dict[str, dict] = {}
    known: dict[str, set[str]] = {}
    window = (now - timedelta(days=2), now + timedelta(days=1))

    def _day_of(inc: Incident) -> str:
        parsed = _parse_ts(inc.ts) or now
        return parsed.astimezone(tz).date().isoformat()

    def _sink(inc: Incident) -> None:
        nonlocal appended, truncated
        day = _day_of(inc)
        path = out_dir / f"{day}.jsonl"
        if day not in known:
            known[day] = _known_ids(path)
        if inc.id in known[day]:
            return
        if len(known[day]) >= max_per_day:
            truncated = True
            return
        known[day].add(inc.id)
        appended += 1
        if not apply:
            return
        out_dir.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(inc.to_json() + "\n")

    marker_known: dict[str, set[str]] = {}

    def _sink_marker(marker: dict) -> None:
        stamp = _parse_ts(marker["ts"]) or now
        day = stamp.astimezone(tz).date().isoformat()
        path = out_dir / f"{day}.jsonl"
        if day not in marker_known:
            marker_known[day] = _known_ids(path, markers=True)
        if marker["id"] in marker_known[day]:
            return
        marker_known[day].add(marker["id"])
        if not apply:
            return
        out_dir.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(marker, ensure_ascii=False, sort_keys=True) + "\n")

    try:
        workspaces = volume_janitor.workspace_dirs(data_root)
    except OSError as exc:  # never let enumeration escape into the caller
        errors.append(f"workspace_dirs: {type(exc).__name__}")
        workspaces = []
    previous_seen = _previous_sources_seen(out_dir)
    for workspace in workspaces:
        user = workspace.parent.name
        state: dict = {
            "trace": False, "cron": False, "delegate": False,
            "earliest_trace_ts": None, "trace_malformed_lines": 0,
            "source_status": {}, "sources_seen": sorted(previous_seen.get(user, set())),
        }
        try:
            seen_now = set(previous_seen.get(user, set()))
            names = cron_job_names(workspace)
            trace = workspace / "logs" / "runtime-trace.jsonl"
            if trace.is_file():
                malformed = 0
                last_provider_failure: dict[tuple, datetime] = {}
                with trace.open("r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line)
                        except ValueError:
                            malformed += 1
                            continue
                        if not isinstance(row, dict):
                            malformed += 1
                            continue
                        stamp = row.get("@timestamp") or row.get("timestamp")
                        if stamp and state["earliest_trace_ts"] is None:
                            state["earliest_trace_ts"] = str(stamp)
                        marker = recovery_marker(row, user)
                        if marker is not None:
                            failed_at = last_provider_failure.get(
                                (marker["agent_alias"], marker["model"]))
                            stamp_ok = _parse_ts(marker["ts"])
                            if (
                                failed_at and stamp_ok
                                and 0 < (stamp_ok - failed_at).total_seconds()
                                <= RECOVERY_WINDOW_SECS
                            ):
                                _sink_marker(marker)
                            continue
                        incident = normalize_trace_row(row, user)
                        if incident is None:
                            continue
                        if incident.kind.startswith("provider"):
                            failed_ts = _parse_ts(incident.ts)
                            if failed_ts:
                                last_provider_failure[(incident.agent_alias, incident.model)] = failed_ts
                        if incident.channel == "cron":
                            incident = replace(
                                incident,
                                channel_ref=names.get(incident.channel_ref or "",
                                                      incident.channel_ref),
                            )
                        _sink(incident)
                state["trace_malformed_lines"] = malformed
                # Set only once the file has been read to the end: a source
                # that threw halfway must never advertise itself as healthy.
                state["trace"] = True
            for name, reader in (("cron", read_cron_failures), ("delegate", read_delegate_failures)):
                never_created = bool(lifecycle_evidence and lifecycle_evidence(workspace, name))
                result = reader(
                    workspace, *window, user,
                    seen=name in seen_now, never_created=never_created,
                )
                state["source_status"][name] = result.status
                state[name] = result.status != SOURCE_UNAVAILABLE
                if result.status == SOURCE_OK:
                    seen_now.add(name)
                for incident in result.incidents:
                    _sink(incident)
            state["sources_seen"] = sorted(seen_now)
        except Exception as exc:  # one broken workspace must not stop the sweep
            errors.append(f"{user}: {type(exc).__name__}")
        sources[user] = state

    receipt = {
        "kind": "sweep",
        "ts": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanned": len(workspaces),
        "appended": appended,
        "truncated": truncated,
        "errors": errors,
        "sources": sources,
    }
    if apply:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            day = now.astimezone(tz).date().isoformat()
            try:
                with (out_dir / f"{day}.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")
            except OSError as exc:
                errors.append(f"receipt: {type(exc).__name__}")
            cutoff = (now.astimezone(tz).date() - timedelta(days=retention_days)).isoformat()
            for path in out_dir.glob("*.jsonl"):
                if path.stem < cutoff:
                    try:
                        path.unlink()
                    except OSError:
                        errors.append(f"prune {path.name}")
        except OSError as exc:  # e.g. out_dir exists as a non-directory
            errors.append(f"mkdir: {type(exc).__name__}")
    return receipt


# --- Digest: group incidents, attach hints, grade completeness by receipts ---

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_WS_PATH_RE = re.compile(r"/zeroclaw-data/workspaces/tg_\d+/")
_NUM_RE = re.compile(r"\d+")
MAX_SIGNATURE_CHARS = 120

HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"invalid_api_key|kind=auth|Insufficient balance"),
     "ключ провайдера отклонён — проверить слот (`make opencode-usage`), скилл zeroclaw-provider-triage"),
    (re.compile(r"kind=rate_limited|\b429\b"),
     "лимит провайдера; фолбэк есть у чата, у делегатов его нет"),
    (re.compile(r"connect to MCP server `?codemap"),
     "codemap недоступен: возможен временный отказ, агент деградирует на lalafo-code;"
     " окно обслуживания графа называть причиной только по подтверждённому receipt таймера"),
    (re.compile(r"MCP (server )?`?lalafo-db`? failed during tool call"),
     "sidecar MCP БД: `curl :4000/health`, скилл zeroclaw-runtime-sidecars"),
    (re.compile(r"MCP (server )?`?[\w-]+`? failed during tool call"),
     "сбой MCP-сервера: `:4000/health` относится только к lalafo-db и здоровья этого сервера не доказывает"),
    (re.compile(r"database is locked"),
     "конкуренция за brain.db — обычно параллельный турн и cron"),
    (re.compile(r"Traceback \(most recent call last\)"),
     "упал скрипт скилла; файл и строка — в тексте ошибки"),
    (re.compile(r"context_floor_exceeds_budget"),
     "системный промпт делегата перерос бюджет окна"),
)


def hint_for(error: str, error_kind: str | None) -> str | None:
    """First matching hint, or None. Never invent a cause."""
    haystack = f"{error} {error_kind or ''}"
    for pattern, hint in HINTS:
        if pattern.search(haystack):
            return hint
    return None


def _signature(error: str) -> str:
    text = _WS_PATH_RE.sub("<ws>/", error)
    text = _UUID_RE.sub("<uuid>", text)
    return _NUM_RE.sub("<n>", text)[:MAX_SIGNATURE_CHARS]


def _subject(row: dict) -> str | None:
    """tool for tool-shaped kinds, provider/model for provider_*, MCP server
    name for mcp_failure (already carried in `tool`, see normalize_trace_row)."""
    if str(row.get("kind") or "").startswith("provider"):
        provider, model = row.get("provider"), row.get("model")
        if not provider and not model:
            return None  # never render the literal `None/None`
        return f"{provider or '?'}/{model or '?'}"
    return row.get("tool")


HISTORY_DAYS = 7


def _novelty_key(channel, channel_ref, kind, subject, error) -> tuple:
    kind = "provider" if str(kind or "").startswith("provider") else kind
    if channel in ("jira", "delegate"):
        channel_ref = None
    return (channel, channel_ref, kind, subject, _signature(str(error or "")))


def _history_keys(
    data_root: Path, start_utc: datetime, tz: ZoneInfo, skip: frozenset[str] = frozenset(),
) -> tuple[set[tuple], int]:
    keys: set[tuple] = set()
    found = 0
    first = start_utc.astimezone(tz).date()
    for back in range(1, HISTORY_DAYS + 1):
        path = snapshot_dir(data_root) / f"{(first - timedelta(days=back)).isoformat()}.jsonl"
        if not path.is_file():
            continue
        day_keys: set[tuple] = set()
        swept = truncated = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            if row.get("kind") == "sweep":
                swept = True
                truncated = truncated or bool(row.get("truncated"))
                continue
            if row.get("kind") == RECOVERY_KIND or row.get("gate") or row.get("user") in skip:
                continue
            day_keys.add(_novelty_key(row.get("channel"), row.get("channel_ref"), row.get("kind"),
                                      _subject(row), row.get("error")))
        if swept and not truncated:
            found += 1
            keys |= day_keys
    return keys, found


@dataclass(frozen=True, slots=True)
class Group:
    channel: str
    channel_ref: str | None
    user: str
    kind: str
    subject: str | None
    count: int
    first_ts: datetime
    last_ts: datetime
    error: str
    detail: str | None
    location: str | None
    hint: str | None
    gate: bool
    agent_alias: str | None
    turn_id: str | None = None
    tool_call_id: str | None = None
    task_ids: list[str] | None = None
    policy_reason: str | None = None
    input_path: str | None = None
    parent_tool: str | None = None
    new: bool = False


@dataclass(frozen=True, slots=True)
class Digest:
    groups: list[Group]
    gate_count: int
    total: int
    by_channel: dict[str, int]
    state: str
    reasons: list[str]
    counters: dict = field(default_factory=dict)
    test_groups: list[Group] = field(default_factory=list)


DEFAULT_TEST_USERS = frozenset({"tg_99999", "tg_88888"})


def resolve_test_users(env: Mapping[str, str] | None = None) -> frozenset[str]:
    source = os.environ if env is None else env
    raw = source.get("ZEROCLAW_INCIDENTS_TEST_USERS")
    if raw is None:
        return DEFAULT_TEST_USERS
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _completeness(
    receipts: list[tuple[datetime, dict]],
    start_utc: datetime,
    end_utc: datetime,
    sweep_interval_secs: float,
    tz: ZoneInfo,
    skip_users: frozenset[str] = frozenset(),
) -> tuple[str, list[str]]:
    """Grade coverage from the sweep receipts, never from incident silence.

    A day with zero incidents proves nothing by itself — only a dense series
    of receipts does. Any receipt-reported gap, unreadable source, reported
    error or empty scan keeps the state out of "полное", even when no incident
    was captured either way. A sweeper that saw no workspaces at all measured
    nothing, which is "нет данных", not a partial observation.
    """
    if not receipts:
        return "нет данных", [
            "снимок инцидентов за сутки отсутствует — отсутствие ошибок ничем не подтверждено"
        ]
    reasons: list[str] = []
    measured_nothing = False
    times = sorted(ts for ts, _ in receipts)
    edges = [start_utc, *times, end_utc]
    gap_start, gap_end, max_gap = start_utc, start_utc, timedelta(0)
    for a, b in zip(edges, edges[1:]):
        gap = b - a
        if gap > max_gap:
            max_gap, gap_start, gap_end = gap, a, b
    if max_gap.total_seconds() > 2 * sweep_interval_secs:
        reasons.append(
            f"снимок инцидентов не вёлся {gap_start.astimezone(tz):%H:%M}"
            f"–{gap_end.astimezone(tz):%H:%M}"
        )
    seen: set[str] = set()
    for _, row in sorted(receipts, key=lambda item: item[0]):
        errors = row.get("errors")
        if errors and "errs" not in seen:
            reasons.append(f"развёртка сообщила об ошибках: {_clip(errors[0], 120)}")
            seen.add("errs")
        if row.get("scanned") == 0 and "empty" not in seen:
            reasons.append(
                "развёртка не нашла ни одного рабочего пространства — измерять было нечего"
            )
            seen.add("empty")
            measured_nothing = True
        if row.get("truncated") and "cap" not in seen:
            reasons.append("достигнут суточный потолок записей")
            seen.add("cap")
        sources = row.get("sources")
        if not isinstance(sources, dict):
            continue
        for user, info in sources.items():
            if user in skip_users or not isinstance(info, dict):
                continue
            for name in ("trace", "cron", "delegate"):
                if info.get(name) is False and f"src:{user}:{name}" not in seen:
                    reasons.append(f"`{user}`: источник недоступен ({name})")
                    seen.add(f"src:{user}:{name}")
            malformed = info.get("trace_malformed_lines")
            if (
                isinstance(malformed, int)
                and not isinstance(malformed, bool)
                and malformed > 0
                and f"malformed:{user}" not in seen
            ):
                reasons.append(f"`{user}`: невалидных строк трейса {malformed}")
                seen.add(f"malformed:{user}")
            earliest = _parse_ts(info.get("earliest_trace_ts"))
            # The trace is a rolling ring, so by evening its earliest entry is
            # ALWAYS later than the morning's window start. That is only a hole
            # in observation when nothing swept during the uncovered period —
            # otherwise those early failures are already in the snapshot.
            if (
                earliest is not None
                and earliest > start_utc
                and f"early:{user}" not in seen
                and not any(start_utc <= moment <= earliest for moment in times)
            ):
                reasons.append(
                    f"трейс `{user}` начинается в {earliest.astimezone(tz):%H:%M},"
                    " ранние ошибки не восстановимы"
                )
                seen.add(f"early:{user}")
    if measured_nothing:
        return "нет данных", reasons
    return ("частичное" if reasons else "полное"), reasons


_MERGE_FILL = (
    "parent_tool", "policy_reason", "task_ids", "input_path", "detail", "location",
    "tool", "error", "channel_ref",
)
_WAIT_KINDS = ("delegate_wait", "delegate_missing")


TWIN_WINDOW_SECS = 2.0
MCP_TWIN_WINDOW_SECS = 5.0
_MCP_CONNECT_RE = re.compile(r"Failed to connect to MCP server [`ʼ']?([\w.-]+)")


def _twin_base(
    ts: datetime, row: dict, bases: list[tuple[datetime, dict]], used: set[int],
) -> dict | None:
    match = _MCP_CONNECT_RE.search(str(row.get("error") or ""))
    server = match.group(1) if match else None
    best: tuple[float, dict] | None = None
    for base_ts, base in bases:
        if id(base) in used or base.get("user") != row.get("user"):
            continue
        if base.get("agent_alias") != row.get("agent_alias"):
            continue
        gap = abs((base_ts - ts).total_seconds())
        tool_twin = (
            base.get("kind") == "tool_failure" and bool(row.get("tool"))
            and base.get("tool") == row.get("tool") and gap <= TWIN_WINDOW_SECS
        )
        mcp_twin = (
            base.get("kind") == "mcp_failure" and server is not None
            and base.get("tool") == server and gap <= MCP_TWIN_WINDOW_SECS
        )
        if (tool_twin or mcp_twin) and (best is None or gap < best[0]):
            best = (gap, base)
    return best[1] if best is not None else None


def _merge_runtime_twins(
    incidents: list[tuple[datetime, dict]],
) -> list[tuple[datetime, dict]]:
    bases = [(ts, row) for ts, row in incidents if row.get("kind") in ("tool_failure", "mcp_failure")]
    used: set[int] = set()
    kept: list[tuple[datetime, dict]] = []
    for ts, row in incidents:
        if row.get("kind") == "runtime_error":
            base = _twin_base(ts, row, bases, used)
            if base is not None:
                used.add(id(base))
                for name in ("location", "detail"):
                    if base.get(name) in (None, "") and row.get(name) not in (None, ""):
                        base[name] = row[name]
                continue
        kept.append((ts, row))
    return kept


def _merge_same_call(
    incidents: list[tuple[datetime, dict]],
) -> list[tuple[datetime, dict]]:
    merged: list[tuple[datetime, dict]] = []
    index: dict[tuple[object, str], int] = {}
    for ts, row in sorted(incidents, key=lambda item: (item[0], str(item[1].get("id") or ""))):
        call_id = row.get("tool_call_id")
        if not call_id:
            merged.append((ts, dict(row)))
            continue
        key = (row.get("user"), str(call_id))
        position = index.get(key)
        if position is not None:
            base = merged[position][1]
            turn, base_turn = row.get("turn_id"), base.get("turn_id")
            if not turn or not base_turn or turn == base_turn:
                for name in _MERGE_FILL:
                    if base.get(name) in (None, "", []) and row.get(name) not in (None, "", []):
                        base[name] = row[name]
                if row.get("gate") and not base.get("gate"):
                    base["gate"] = True
                    base["gate_reason"] = row.get("gate_reason")
                if base.get("kind") == "tool_failure" and row.get("kind") in _WAIT_KINDS:
                    base["kind"] = row["kind"]
                continue
        index[key] = len(merged)
        merged.append((ts, dict(row)))
    return merged


def _is_provider_row(row: dict) -> bool:
    return str(row.get("kind") or "").startswith("provider") and not row.get("gate")


def _episode_fits(episode: dict, ts: datetime, turn: object) -> bool:
    if (ts - episode["end"]).total_seconds() > EPISODE_GAP_SECS:
        return False
    return not turn or not episode["turn"] or turn == episode["turn"]


def _provider_episodes(provider: list[tuple[datetime, dict]]) -> list[dict]:
    episodes: list[dict] = []
    for ts, row in sorted(provider, key=lambda item: item[0]):
        user, alias = row.get("user"), row.get("agent_alias")
        model, turn = row.get("model"), row.get("turn_id")
        candidates = [
            episode for episode in episodes
            if episode["user"] == user and episode["alias"] == alias
            and (model is None or episode["model"] == model)
            and _episode_fits(episode, ts, turn)
        ]
        if candidates:
            episode = max(candidates, key=lambda item: item["end"])
            episode["end"], episode["last"] = ts, row
            episode["turn"] = episode["turn"] or turn
            continue
        episodes.append({"user": user, "alias": alias, "model": model, "turn": turn,
                         "start": ts, "end": ts, "last": row})
    return episodes


def _is_recovered(episode: dict, recoveries: list[tuple[datetime, dict]]) -> bool:
    for ts, marker in recoveries:
        if marker.get("user") != episode["user"]:
            continue
        if not 0 < (ts - episode["end"]).total_seconds() <= RECOVERY_WINDOW_SECS:
            continue
        if episode["turn"]:
            if marker.get("trace_id") == episode["turn"]:
                return True
        elif (marker.get("agent_alias") == episode["alias"]
              and marker.get("model") == episode["model"]):
            return True
    return False


def _collapse_provider_episodes(
    incidents: list[tuple[datetime, dict]],
    recoveries: list[tuple[datetime, dict]],
) -> tuple[list[tuple[datetime, dict]], list[tuple]]:
    provider = [(ts, row) for ts, row in incidents if _is_provider_row(row)]
    others = [(ts, row) for ts, row in incidents if not _is_provider_row(row)]
    kept: list[tuple[datetime, dict]] = []
    recovered: list[tuple] = []
    for episode in _provider_episodes(provider):
        key = (episode["user"], episode["alias"], episode["model"])
        if _is_recovered(episode, recoveries):
            recovered.append(key)
            continue
        if any(
            row.get("kind") == "delegate_failure" and not row.get("gate")
            and row.get("user") == episode["user"] and row.get("agent_alias") == episode["alias"]
            and 0 <= (ts - episode["end"]).total_seconds() <= ABSORB_WINDOW_SECS
            for ts, row in others
        ):
            continue
        kept.append((episode["start"], dict(episode["last"], kind="provider_failure")))
    return others + kept, recovered


def _source_status_counts(
    receipts: list[tuple[datetime, dict]], skip_users: frozenset[str] = frozenset()
) -> dict[str, int]:
    counts = {SOURCE_OK: 0, SOURCE_NOT_INITIALIZED: 0, SOURCE_UNAVAILABLE: 0}
    if not receipts:
        return counts
    _, latest = max(receipts, key=lambda item: item[0])
    sources = latest.get("sources")
    if not isinstance(sources, dict):
        return counts
    for user, info in sources.items():
        if user in skip_users:
            continue
        statuses = info.get("source_status") if isinstance(info, dict) else None
        if not isinstance(statuses, dict):
            continue
        for value in statuses.values():
            if value in counts:
                counts[value] += 1
    return counts


def _build_groups(
    rows: list[tuple[datetime, dict]],
) -> tuple[list[Group], dict[str, int], int, dict]:
    gate_count = 0
    gate_reasons: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    denials: dict[str, int] = {}
    waits = missing = terminal = calls_with_id = 0
    buckets: dict[tuple, list[tuple[datetime, dict]]] = {}
    for ts, row in rows:
        reason = row.get("policy_reason")
        if reason:
            denials[str(reason)] = denials.get(str(reason), 0) + 1
        if row.get("gate"):
            gate_count += 1
            name = str(row.get("gate_reason") or "literal")
            gate_reasons[name] = gate_reasons.get(name, 0) + 1
            continue
        channel = str(row.get("channel") or "")
        by_channel[channel] = by_channel.get(channel, 0) + 1
        kind = row.get("kind")
        if kind == "delegate_wait":
            waits += 1
        elif kind == "delegate_missing":
            missing += 1
        elif kind == "delegate_failure":
            terminal += 1
        if row.get("tool_call_id"):
            calls_with_id += 1
        key = (
            row.get("user"), channel, row.get("channel_ref"), row.get("kind"),
            _subject(row), row.get("agent_alias"), _signature(str(row.get("error") or "")),
        )
        buckets.setdefault(key, []).append((ts, row))

    groups: list[Group] = []
    for (user, channel, channel_ref, kind, subject, agent_alias, _sig), members in buckets.items():
        members.sort(key=lambda item: item[0])
        _, sample = members[0]  # earliest member, for a deterministic sample
        error = str(sample.get("error") or "")
        groups.append(Group(
            channel=channel, channel_ref=channel_ref, user=user, kind=kind,
            subject=subject, count=len(members), first_ts=members[0][0],
            last_ts=members[-1][0], error=error, detail=sample.get("detail"),
            location=sample.get("location"), hint=hint_for(error, sample.get("error_kind")),
            gate=False, agent_alias=agent_alias, turn_id=sample.get("turn_id"),
            tool_call_id=sample.get("tool_call_id"), task_ids=sample.get("task_ids"),
            policy_reason=sample.get("policy_reason"), input_path=sample.get("input_path"),
            parent_tool=sample.get("parent_tool"),
        ))
    groups.sort(key=lambda g: (-g.count, g.first_ts))
    partial = {
        "waits": waits, "missing": missing, "terminal": terminal,
        "unique_calls_with_id": calls_with_id, "policy_denials": dict(sorted(denials.items())),
        "gate_reasons": dict(sorted(gate_reasons.items())),
    }
    return groups, by_channel, gate_count, partial


def build_digest(
    data_root: Path,
    start_utc: datetime,
    end_utc: datetime,
    *,
    timezone_name: str = DEFAULT_TIMEZONE,
    sweep_interval_secs: float = DEFAULT_SWEEP_INTERVAL_SECS,
    now: datetime | None = None,
    test_users: frozenset[str] | None = None,
) -> Digest:
    """Read the daily snapshot(s) covering the window and build a report digest.

    Never raises: a corrupt line, a missing file, or an unparseable
    timestamp is skipped, never propagated — the caller (Task 8) runs this
    inside a try only as belt-and-suspenders.
    """
    skip = test_users if test_users is not None else resolve_test_users()
    tz = ZoneInfo(timezone_name)
    first = start_utc.astimezone(tz).date()
    last = end_utc.astimezone(tz).date()
    dates = [first + timedelta(days=n) for n in range((last - first).days + 1)]
    rows: list[dict] = []
    for day in dates:
        path = snapshot_dir(data_root) / f"{day.isoformat()}.jsonl"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)

    # Incidents: half-open, same convention as read_cron_failures/read_delegate_failures
    # elsewhere in this module. Receipts: inclusive of end_utc — a sweep fires on a
    # fixed cadence and its last tick of the day commonly lands exactly on the
    # window edge (e.g. a 30-min cadence over a 24h window); excluding it would
    # silently blind the completeness check to that receipt's source state.
    receipts: list[tuple[datetime, dict]] = []
    recoveries: list[tuple[datetime, dict]] = []
    incidents: list[tuple[datetime, dict]] = []
    seen_ids: set[str] = set()
    for row in rows:
        ts = _parse_ts(row.get("ts"))
        if ts is None or ts < start_utc:
            continue
        if row.get("kind") == RECOVERY_KIND:
            if ts <= end_utc + timedelta(seconds=RECOVERY_WINDOW_SECS):
                recoveries.append((ts, row))
            continue
        if row.get("kind") == "sweep":
            if ts <= end_utc:
                receipts.append((ts, row))
        elif ts < end_utc:
            # A torn snapshot line is skipped by `_known_ids`, so the sweep
            # re-appends that id on its next pass. Count the incident once.
            ident = str(row.get("id") or "")
            if ident and ident in seen_ids:
                continue
            seen_ids.add(ident)
            incidents.append((ts, row))

    observed_until = min(end_utc, now or datetime.now(timezone.utc))
    state, reasons = _completeness(receipts, start_utc, observed_until, sweep_interval_secs, tz, skip_users=skip)

    raw_gate = sum(1 for _, row in incidents if row.get("gate"))
    raw_non_gate = len(incidents) - raw_gate
    incidents = _merge_same_call(incidents)
    incidents = _merge_runtime_twins(incidents)
    incidents, recovered_keys = _collapse_provider_episodes(incidents, recoveries)

    prod_rows = [p for p in incidents if p[1].get("user") not in skip]
    test_rows = [p for p in incidents if p[1].get("user") in skip]
    groups, by_channel, gate_count, part = _build_groups(prod_rows)
    test_groups, _, _, _ = _build_groups(test_rows)
    history, history_days = _history_keys(data_root, start_utc, tz, skip)
    if history_days == HISTORY_DAYS:
        groups = [
            replace(g, new=_novelty_key(g.channel, g.channel_ref, g.kind, g.subject, g.error) not in history)
            for g in groups
        ]

    malformed_total = 0
    if receipts:
        _, latest = max(receipts, key=lambda item: item[0])
        latest_sources = latest.get("sources")
        if isinstance(latest_sources, dict):
            for info in latest_sources.values():
                value = info.get("trace_malformed_lines") if isinstance(info, dict) else None
                if isinstance(value, int) and not isinstance(value, bool):
                    malformed_total += value
    counters = {
        "non_gate_records": raw_non_gate,
        "gate_records": raw_gate,
        **part,
        "source_status": _source_status_counts(receipts, skip_users=skip),
        "trace_malformed_lines": malformed_total,
        "history_days": history_days,
        "recovered_episodes": sum(1 for key in recovered_keys if key[0] not in skip),
        "test_users": dict(
            Counter(row["user"] for _, row in test_rows if not row.get("gate"))
        ),
    }

    # `total` is what the summary line breaks down by channel, and the
    # breakdown is built from non-gates only — counting gates here made the
    # operator read a total that did not add up (13 != 5+5+1+0).
    return Digest(
        groups=groups, gate_count=gate_count, total=sum(by_channel.values()),
        by_channel=by_channel, state=state, reasons=reasons, counters=counters,
        test_groups=test_groups,
    )


# --- Rendering: channel sections within an explicit character budget ---

def _gates_line(digest: "Digest") -> str:
    reasons = (digest.counters or {}).get("gate_reasons") or {}
    detail = ", ".join(
        f"{name} {count}" for name, count in sorted(reasons.items()) if name != "literal"
    )
    return (
        f"**Ожидаемые гейты:** {digest.gate_count}"
        + (f" ({detail})" if detail else "")
        + " — не дефекты"
    )


CHANNEL_TITLES = {"chat": "Чат", "cron": "Cron", "jira": "Jira-разбор", "delegate": "Делегаты"}
SECTION_ORDER = ("chat", "cron", "jira", "delegate")
MAX_GROUPS_PER_SECTION = 3
MAX_GROUPS_TOTAL = 10
#: Spec §8 budgets four channel sections. Buckets are finer than channels
#: (channel + cron job/jira alias + user), so this is the ceiling the ladder
#: falls back to under pressure, not a cap applied to a message that fits.
MAX_SECTIONS = 4
MSG_ERROR_CHARS = 160
MSG_DETAIL_CHARS = 120


def _section_order_index(channel: str) -> int:
    """Unknown channels sort last instead of crashing `SECTION_ORDER.index`.

    render_sections must survive an odd digest (Task 8 delivers whatever it
    returns), and a channel outside the four known ones is exactly the kind
    of oddity that must degrade gracefully, not raise.
    """
    return SECTION_ORDER.index(channel) if channel in SECTION_ORDER else len(SECTION_ORDER)


def _hhmm(ts: object, tz: ZoneInfo) -> str:
    parsed = _parse_ts(ts)
    return parsed.astimezone(tz).strftime("%H:%M") if parsed else "??:??"


def _span(first: object, last: object, tz: ZoneInfo) -> str:
    """`HH:MM` or `HH:MM–HH:MM`, in the report's local zone.

    Compares the FORMATTED strings: a span of a few seconds is one minute to
    the reader, and `22:02–22:02` is noise.
    """
    start, end = _hhmm(first, tz), _hhmm(last, tz)
    return start if start == end else f"{start}–{end}"


def _code(text: object) -> str:
    """Wrap in a Markdown code span, neutralising the fences inside it.

    The most frequent real sample carries three backticks of its own
    (``MCP server `lalafo-db` failed during tool call `query`​``), and shell
    details carry more: unescaped, the span closes early and the rest of the
    message reaches Telegram as broken markup.
    """
    return "`" + str(text).replace("`", "ʼ") + "`"


def _section_title(group: Group) -> str:
    title = CHANNEL_TITLES.get(group.channel, group.channel)
    if group.channel_ref:
        title = f"{title} · {group.channel_ref}"
    return f"**{title}** · {group.user}"


def _group_lines(
    group: Group, *, with_sample: bool, with_hint: bool, tz: ZoneInfo
) -> list[str]:
    head = f"- {'🆕 ' if group.new else ''}**{group.kind} ×{group.count}** · {_span(group.first_ts, group.last_ts, tz)}"
    if group.subject:
        head += f" · {_code(group.subject)}"
    lines = [head]
    if with_sample and group.error:
        lines.append("  " + _code(_clip(group.error, MSG_ERROR_CHARS)))
        if group.detail:
            lines.append("  " + _code(_clip(group.detail, MSG_DETAIL_CHARS)))
    if with_hint and group.hint:
        lines.append(f"  ↳ {group.hint}")
    return lines


def _sections_plural(n: int) -> str:
    return "секции" if n % 10 == 1 and n % 100 != 11 else "секциях"


def _allocate_rooms(keys_by_weight: list, buckets: dict, per_section: int) -> dict:
    rooms = {key: 0 for key in keys_by_weight}
    left = MAX_GROUPS_TOTAL
    for level in range(1, per_section + 1):
        for key in keys_by_weight:
            if left == 0:
                return rooms
            if len(buckets[key]) >= level:
                rooms[key] = level
                left -= 1
    return rooms


def render_sections(
    digest: Digest, *, budget: int, timezone_name: str = DEFAULT_TIMEZONE
) -> tuple[list[str], int]:
    """Render channel sections inside an explicit budget.

    Degradation order: hints, then whole sections, then verbatim samples,
    then groups. Sections are trimmed BEFORE samples on purpose — a bad day
    reaches 84 buckets, and one header plus one `+N ещё` per bucket spends the
    whole budget on bookkeeping and leaves no room for a single verbatim
    sample, the "degenerated into a counter" outcome gate G3 exists to catch.
    A message that already fits keeps every section: the cap is relief under
    pressure, not a rule applied to a short day.

    Dropping is never silent — every dropped group is counted, either in its
    section's `+N ещё` line or in the trailing one for the dropped sections,
    because a silently truncated report is how v1 lied.
    """
    tz = ZoneInfo(timezone_name)
    buckets: dict[tuple[str, str | None, str], list[Group]] = {}
    for group in digest.groups:
        buckets.setdefault((group.channel, group.channel_ref, group.user), []).append(group)
    ordered_keys = sorted(buckets, key=lambda k: _section_order_index(k[0]))
    # Which sections survive the cap is decided by weight, not by channel
    # order: ordering alone would spend all four slots on `chat` and never
    # show the cron job that actually broke. `sorted` is stable, so ties keep
    # the digest's own (-count, first_ts) order and the choice is deterministic.
    by_weight = sorted(
        ordered_keys,
        key=lambda k: (-sum(g.count for g in buckets[k]), _section_order_index(k[0])),
    )

    lines: list[str] = []
    dropped = 0
    for with_hint, with_sample, per_section, max_sections in (
        (True, True, MAX_GROUPS_PER_SECTION, None),
        (False, True, MAX_GROUPS_PER_SECTION, None),
        (False, True, MAX_GROUPS_PER_SECTION, MAX_SECTIONS),
        (False, False, MAX_GROUPS_PER_SECTION, MAX_SECTIONS),
        (False, False, 1, MAX_SECTIONS),
        (False, False, 1, 2),
        (False, False, 1, 1),
    ):
        chosen = set(by_weight if max_sections is None else by_weight[:max_sections])
        chosen_by_weight = [key for key in by_weight if key in chosen]
        rooms = _allocate_rooms(chosen_by_weight, buckets, per_section)
        lines = []
        dropped = 0
        folded = [key for key in ordered_keys if key in chosen and rooms[key] == 0]
        for key in ordered_keys:
            if key not in chosen or rooms[key] == 0:
                continue
            members = buckets[key]
            room = rooms[key]
            lines.append("")
            lines.append(_section_title(members[0]))
            for group in members[:room]:
                lines.extend(
                    _group_lines(group, with_sample=with_sample, with_hint=with_hint, tz=tz)
                )
            rest = len(members) - room
            if rest:
                dropped += rest
                lines.append(f"- +{rest} ещё")
        rest_keys = [key for key in ordered_keys if key not in chosen] + folded
        if rest_keys:
            rest_groups = sum(len(buckets[key]) for key in rest_keys)
            dropped += rest_groups
            lines.append("")
            lines.append(
                f"- +{rest_groups} ещё в {len(rest_keys)} {_sections_plural(len(rest_keys))}"
            )
        if digest.gate_count:
            lines.append("")
            lines.append(_gates_line(digest))
        if len("\n".join(lines)) <= budget:
            return lines, dropped
    return lines, dropped


def _attachment_group_lines(group: Group, tz: ZoneInfo) -> list[str]:
    """Same layout as `_group_lines`, but no message-side clip (400/300 chars
    are already applied at ingestion) and no cap: every field, always."""
    head = f"- {'🆕 ' if group.new else ''}**{group.kind} ×{group.count}** · {_span(group.first_ts, group.last_ts, tz)}"
    if group.subject:
        head += f" · {_code(group.subject)}"
    lines = [head]
    if group.error:
        lines.append("  " + _code(group.error))
    if group.detail:
        lines.append("  " + _code(group.detail))
    if group.location:
        lines.append(f"  {group.location}")
    if group.turn_id:
        lines.append(f"  turn_id: {group.turn_id}")
    if group.tool_call_id:
        lines.append(f"  tool_call_id: {group.tool_call_id}")
    if group.parent_tool:
        lines.append(f"  parent_tool: {group.parent_tool}")
    if group.policy_reason:
        lines.append(f"  policy_reason: {group.policy_reason}")
    if group.task_ids:
        lines.append(f"  task_ids: {', '.join(group.task_ids)}")
    if group.input_path:
        lines.append(f"  input_path: {group.input_path}")
    if group.hint:
        lines.append(f"  ↳ {group.hint}")
    return lines


def _counter_lines(counters: dict) -> list[str]:
    if not counters:
        return []
    lines = [
        "",
        "**Счётчики**",
        f"- записей без гейтов: {counters.get('non_gate_records', 0)}"
        f" · записей-гейтов: {counters.get('gate_records', 0)}"
        f" · уникальных вызовов с call ID: {counters.get('unique_calls_with_id', 0)}",
        f"- ожидание делегатов: {counters.get('waits', 0)}"
        f" · missing: {counters.get('missing', 0)}"
        f" · терминальные отказы: {counters.get('terminal', 0)}",
    ]
    denials = counters.get("policy_denials") or {}
    if denials:
        lines.append(
            "- отказы policy: " + " · ".join(f"{name} {count}" for name, count in denials.items())
        )
    status = counters.get("source_status") or {}
    if status:
        lines.append(
            "- источники: " + " · ".join(f"{name} {count}" for name, count in status.items())
            + f" · невалидных строк трейса {counters.get('trace_malformed_lines', 0)}"
        )
    return lines


def render_attachment(
    digest: Digest, date: str, *, timezone_name: str = DEFAULT_TIMEZONE
) -> str:
    """Complete Markdown digest, no caps — the file sent when render_sections
    had to drop something. Same section order/bucketing as render_sections,
    but every group appears exactly once, in full — this is the forensic
    artifact, and `turn_id` is the key for grepping `runtime-trace.jsonl`
    afterwards, so it prints here (spec §4.1) even though the budgeted
    message never has room for it. `Group.turn_id` is the earliest sample's
    turn (build_digest groups on an error signature, not on a single
    incident's turn, so groups spanning several turns still resolve to one
    representative id); absent, it prints nothing rather than "None".
    """
    tz = ZoneInfo(timezone_name)
    buckets: dict[tuple[str, str | None, str], list[Group]] = {}
    for group in digest.groups:
        buckets.setdefault((group.channel, group.channel_ref, group.user), []).append(group)

    lines = [f"# ZeroClaw — инциденты за {date}"]
    lines.extend(_counter_lines(digest.counters))
    for key in sorted(buckets, key=lambda k: _section_order_index(k[0])):
        members = buckets[key]
        lines.append("")
        lines.append(_section_title(members[0]))
        for group in members:
            lines.extend(_attachment_group_lines(group, tz))
    if digest.gate_count:
        lines.append("")
        lines.append(_gates_line(digest))
    if digest.test_groups:
        lines.extend(["", "## Тестовые воркспейсы", ""])
        for group in digest.test_groups:
            lines.extend(_attachment_group_lines(group, tz))
    return "\n".join(lines) + "\n"


# --- CLI: offline debugging and acceptance gate G6a (spec §3, §13) ---

DEFAULT_DATA_ROOT = "/zeroclaw-data"


def _group_as_dict(g: Group) -> dict:
    return {
        "channel": g.channel, "channel_ref": g.channel_ref, "user": g.user,
        "kind": g.kind, "subject": g.subject, "count": g.count,
        "first_ts": g.first_ts.isoformat(), "last_ts": g.last_ts.isoformat(),
        "error": g.error, "detail": g.detail, "location": g.location,
        "hint": g.hint, "gate": g.gate, "agent_alias": g.agent_alias,
        "turn_id": g.turn_id, "tool_call_id": g.tool_call_id,
        "task_ids": g.task_ids, "policy_reason": g.policy_reason,
        "input_path": g.input_path, "parent_tool": g.parent_tool,
        "new": g.new,
    }


def _digest_as_dict(digest: Digest) -> dict:
    return {
        "state": digest.state,
        "reasons": digest.reasons,
        "total": digest.total,
        "gate_count": digest.gate_count,
        "by_channel": digest.by_channel,
        "counters": digest.counters,
        "groups": [_group_as_dict(g) for g in digest.groups],
        "test_groups": [_group_as_dict(g) for g in digest.test_groups],
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline reader for the incident digest (spec §3, gate G6a)."
    )
    parser.add_argument("--date", required=True, help="local day to report on, YYYY-MM-DD")
    parser.add_argument(
        "--data-root", default=None,
        help=f"defaults to $ZEROCLAW_DATA_ROOT, else {DEFAULT_DATA_ROOT}",
    )
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument(
        "--sweep", action="store_true",
        help="capture new failures into the snapshot first (the only thing that writes)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: offline debugging and acceptance gate G6a (spec §3, §13).

    Read-only unless --sweep is passed: G6a runs this against production, so a
    plain invocation must never touch disk. Never lets an exception escape as a
    traceback — an unparseable --date or an unreadable data root becomes one
    line on stderr and a non-zero exit, and a day with no snapshot at all is a
    valid (zero-incident) answer, not a failure.
    """
    args = _parse_args(argv)
    try:
        day = datetime.strptime(args.date, "%Y-%m-%d").date()
        data_root = Path(
            args.data_root or os.environ.get("ZEROCLAW_DATA_ROOT", DEFAULT_DATA_ROOT)
        )
        tz = ZoneInfo(args.timezone)
        start_utc = datetime(day.year, day.month, day.day, tzinfo=tz).astimezone(timezone.utc)
        end_utc = start_utc + timedelta(days=1)

        if args.sweep:
            sweep(data_root, datetime.now(timezone.utc), timezone_name=args.timezone)

        digest = build_digest(data_root, start_utc, end_utc, timezone_name=args.timezone)

        if args.json:
            print(json.dumps(_digest_as_dict(digest), ensure_ascii=False, sort_keys=True))
        else:
            print(render_attachment(digest, args.date, timezone_name=args.timezone), end="")
    except Exception as exc:  # an operator running G6a sees one line, never a traceback
        print(f"zeroclaw_incidents: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
