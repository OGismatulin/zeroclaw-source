#!/usr/bin/env python3
"""Deterministic incident digest over per-user runtime evidence.

Reads what actually broke (tool failures, provider failures, cron runs,
delegate results) and keeps it in a durable daily snapshot, because the
runtime trace is a 5000-entry ring that no longer covers a full report
window for an active user.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    tool = zc.get("tool") or attrs.get("tool") or payload.get("tool")
    if kind == "mcp_failure" and not tool:
        tool = payload.get("server")
    command = None
    raw_input = attrs.get("input")
    if isinstance(raw_input, dict):
        command = raw_input.get("command")
    if native:
        error = attrs.get("error") or attrs.get("error_reason") or row.get("message")
    else:
        error = payload.get("output") or payload.get("error") or row.get("message")
    location = None
    if attrs.get("_file"):
        location = f"{attrs['_file']}:{attrs.get('_line', '?')}"
    clipped_error = _clip(error, MAX_ERROR_CHARS)
    channel, channel_ref = classify_channel(row, zc)
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
        detail=_clip(command, MAX_DETAIL_CHARS) if command else None,
        location=location,
        turn_id=row.get("turn_id") or row.get("trace_id"),
        gate=is_expected_gate(clipped_error, str(tool) if tool else None, zc.get("agent_alias")),
    )


CRON_FAILURE_STATUSES = ("error", "degraded")
_KIND_RE = re.compile(r"\bkind=([a-z_]+)")
_DISPOSITION_RE = re.compile(r"\bdisposition=([a-z_]+)")


def _parse_ts(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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
    workspace: Path, since: datetime, until: datetime, user: str
) -> list[Incident]:
    """Failed cron runs from the per-user jobs.db (read-only, never written).

    `cron_runs.status` is ok | error | degraded (`skipped` lives on
    cron_jobs.last_status, not here). A failed delivery appends
    `delivery failed: …` to output, so the tail of output is the informative
    line.
    """
    con = _connect_ro(workspace / "cron" / "jobs.db")
    if con is None:
        return []
    try:
        rows = con.execute(
            "SELECT r.job_id, r.started_at, r.status, r.output, j.name"
            " FROM cron_runs r LEFT JOIN cron_jobs j ON j.id = r.job_id"
            " WHERE r.status IN (?, ?)",
            CRON_FAILURE_STATUSES,
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()
    out: list[Incident] = []
    for job_id, started_at, status, output, name in rows:
        ts = _parse_ts(started_at)
        if ts is None or not (since <= ts < until):
            continue
        text = (output or "").strip().splitlines()
        message = text[-1] if text else f"cron run {status}"
        out.append(
            Incident(
                id=f"cron:{job_id}:{started_at}", ts=str(started_at), user=user,
                source="cron", severity="ERROR" if status == "error" else "WARN",
                channel="cron", channel_ref=name or job_id, kind="cron_failure",
                tool=None, agent_alias=None, model=None, provider=None,
                error_kind=status, error_disposition=None,
                error=_clip(message, MAX_ERROR_CHARS), detail=None, location=None,
                turn_id=None, gate=False,
            )
        )
    return out


def read_delegate_failures(
    workspace: Path, since: datetime, until: datetime, user: str
) -> list[Incident]:
    """Terminal delegate failures; `error` carries TerminalProviderFailure."""
    root = workspace / "delegate_results"
    if not root.is_dir():
        return []
    out: list[Incident] = []
    for path in sorted(root.glob("*.json")):
        # Nothing prunes delegate_results, so this directory only grows and is
        # re-read 48x/day on the public edge. A file last written before the
        # window cannot carry a `finished_at` inside it, so skip without opening.
        try:
            if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < since:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
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
        out.append(
            Incident(
                id=f"delegate:{data.get('task_id')}:{finished}", ts=str(finished),
                user=user, source="delegate", severity="ERROR", channel="delegate",
                channel_ref=data.get("agent"), kind="delegate_failure", tool=None,
                agent_alias=data.get("agent"), model=None, provider=None,
                error_kind=kind_match.group(1) if kind_match else None,
                error_disposition=disp_match.group(1) if disp_match else None,
                error=_clip(error, MAX_ERROR_CHARS), detail=None, location=None,
                turn_id=None, gate=False,
            )
        )
    return out


SNAPSHOT_DIRNAME = "incidents"


def snapshot_dir(data_root: Path) -> Path:
    return data_root / "observability" / SNAPSHOT_DIRNAME


def _known_ids(path: Path) -> set[str]:
    """Ids already in the snapshot. A torn last line is ignored, not fatal."""
    known: set[str] = set()
    if not path.is_file():
        return known
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        ident = row.get("id")
        if ident:
            known.add(str(ident))
    return known


def sweep(
    data_root: Path,
    now: datetime,
    *,
    apply: bool = True,
    timezone_name: str = DEFAULT_TIMEZONE,
    retention_days: int = 14,
    max_per_day: int = 20000,
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

    try:
        workspaces = volume_janitor.workspace_dirs(data_root)
    except OSError as exc:  # never let enumeration escape into the caller
        errors.append(f"workspace_dirs: {type(exc).__name__}")
        workspaces = []
    for workspace in workspaces:
        user = workspace.parent.name
        state = {"trace": False, "cron": False, "earliest_trace_ts": None}
        try:
            names = cron_job_names(workspace)
            state["cron"] = bool((workspace / "cron" / "jobs.db").is_file())
            trace = workspace / "logs" / "runtime-trace.jsonl"
            if trace.is_file():
                with trace.open("r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        stamp = row.get("@timestamp") or row.get("timestamp")
                        if stamp and state["earliest_trace_ts"] is None:
                            state["earliest_trace_ts"] = str(stamp)
                        incident = normalize_trace_row(row, user)
                        if incident is None:
                            continue
                        if incident.channel == "cron":
                            incident = replace(
                                incident,
                                channel_ref=names.get(incident.channel_ref or "",
                                                      incident.channel_ref),
                            )
                        _sink(incident)
                # Set only once the file has been read to the end: a source
                # that threw halfway must never advertise itself as healthy.
                state["trace"] = True
            for incident in read_cron_failures(workspace, *window, user):
                _sink(incident)
            for incident in read_delegate_failures(workspace, *window, user):
                _sink(incident)
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
     "окно обслуживания графа 02:30–03:00 UTC, деградация на lalafo-code"),
    (re.compile(r"MCP (server )?`?[\w-]+`? failed during tool call"),
     "sidecar MCP: `curl :4000/health`, скилл zeroclaw-runtime-sidecars"),
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


@dataclass(frozen=True, slots=True)
class Digest:
    groups: list[Group]
    gate_count: int
    total: int
    by_channel: dict[str, int]
    state: str
    reasons: list[str]


def _completeness(
    receipts: list[tuple[datetime, dict]],
    start_utc: datetime,
    end_utc: datetime,
    sweep_interval_secs: float,
    tz: ZoneInfo,
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
            if not isinstance(info, dict):
                continue
            if (info.get("trace") is False or info.get("cron") is False) and (
                f"src:{user}" not in seen
            ):
                reasons.append(f"`{user}`: источник недоступен")
                seen.add(f"src:{user}")
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


def build_digest(
    data_root: Path,
    start_utc: datetime,
    end_utc: datetime,
    *,
    timezone_name: str = DEFAULT_TIMEZONE,
    sweep_interval_secs: float = DEFAULT_SWEEP_INTERVAL_SECS,
) -> Digest:
    """Read the daily snapshot(s) covering the window and build a report digest.

    Never raises: a corrupt line, a missing file, or an unparseable
    timestamp is skipped, never propagated — the caller (Task 8) runs this
    inside a try only as belt-and-suspenders.
    """
    tz = ZoneInfo(timezone_name)
    dates = {start_utc.astimezone(tz).date(), end_utc.astimezone(tz).date()}
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
    incidents: list[tuple[datetime, dict]] = []
    seen_ids: set[str] = set()
    for row in rows:
        ts = _parse_ts(row.get("ts"))
        if ts is None or ts < start_utc:
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

    state, reasons = _completeness(receipts, start_utc, end_utc, sweep_interval_secs, tz)

    gate_count = 0
    by_channel: dict[str, int] = {}
    buckets: dict[tuple, list[tuple[datetime, dict]]] = {}
    for ts, row in incidents:
        if row.get("gate"):
            gate_count += 1
            continue
        channel = str(row.get("channel") or "")
        by_channel[channel] = by_channel.get(channel, 0) + 1
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
        ))
    groups.sort(key=lambda g: (-g.count, g.first_ts))

    # `total` is what the summary line breaks down by channel, and the
    # breakdown is built from non-gates only — counting gates here made the
    # operator read a total that did not add up (13 != 5+5+1+0).
    return Digest(
        groups=groups, gate_count=gate_count, total=len(incidents) - gate_count,
        by_channel=by_channel, state=state, reasons=reasons,
    )


# --- Rendering: channel sections within an explicit character budget ---

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
    head = f"- **{group.kind} ×{group.count}** · {_span(group.first_ts, group.last_ts, tz)}"
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
        lines = []
        dropped = 0
        shown = 0
        for key in ordered_keys:
            if key not in chosen:
                continue
            members = buckets[key]
            room = min(per_section, max(0, MAX_GROUPS_TOTAL - shown))
            lines.append("")
            lines.append(_section_title(members[0]))
            for group in members[:room]:
                lines.extend(
                    _group_lines(group, with_sample=with_sample, with_hint=with_hint, tz=tz)
                )
            shown += min(room, len(members))
            rest = len(members) - min(room, len(members))
            if rest:
                dropped += rest
                lines.append(f"- +{rest} ещё")
        rest_keys = [key for key in ordered_keys if key not in chosen]
        if rest_keys:
            rest_groups = sum(len(buckets[key]) for key in rest_keys)
            dropped += rest_groups
            lines.append("")
            lines.append(
                f"- +{rest_groups} ещё в {len(rest_keys)} {_sections_plural(len(rest_keys))}"
            )
        if digest.gate_count:
            lines.append("")
            lines.append(f"**Ожидаемые гейты:** {digest.gate_count} — не дефекты")
        if len("\n".join(lines)) <= budget:
            return lines, dropped
    return lines, dropped


def _attachment_group_lines(group: Group, tz: ZoneInfo) -> list[str]:
    """Same layout as `_group_lines`, but no message-side clip (400/300 chars
    are already applied at ingestion) and no cap: every field, always."""
    head = f"- **{group.kind} ×{group.count}** · {_span(group.first_ts, group.last_ts, tz)}"
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
    if group.hint:
        lines.append(f"  ↳ {group.hint}")
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
    for key in sorted(buckets, key=lambda k: _section_order_index(k[0])):
        members = buckets[key]
        lines.append("")
        lines.append(_section_title(members[0]))
        for group in members:
            lines.extend(_attachment_group_lines(group, tz))
    if digest.gate_count:
        lines.append("")
        lines.append(f"**Ожидаемые гейты:** {digest.gate_count} — не дефекты")
    return "\n".join(lines) + "\n"


# --- CLI: offline debugging and acceptance gate G6a (spec §3, §13) ---

DEFAULT_DATA_ROOT = "/zeroclaw-data"


def _digest_as_dict(digest: Digest) -> dict:
    """JSON-serializable form of a Digest — Group's timestamps need an explicit isoformat."""
    return {
        "state": digest.state,
        "reasons": digest.reasons,
        "total": digest.total,
        "gate_count": digest.gate_count,
        "by_channel": digest.by_channel,
        "groups": [
            {
                "channel": g.channel, "channel_ref": g.channel_ref, "user": g.user,
                "kind": g.kind, "subject": g.subject, "count": g.count,
                "first_ts": g.first_ts.isoformat(), "last_ts": g.last_ts.isoformat(),
                "error": g.error, "detail": g.detail, "location": g.location,
                "hint": g.hint, "gate": g.gate, "agent_alias": g.agent_alias,
                "turn_id": g.turn_id,
            }
            for g in digest.groups
        ],
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
