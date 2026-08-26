"""Deterministic retention sweeper for the ZeroClaw data volume.

Allowlist-only: it deletes exactly what RULES describes and nothing else.
See docs/superpowers/specs/2026-08-26-volume-retention-janitor-design.md
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

# No rule may ever delete something younger than this, whatever its window is.
MIN_AGE_SECS = 86_400.0

_USER_DIR_RE = re.compile(r"^tg_\d+$")

# A match here vetoes every rule. fnmatch does not treat "/" specially, so
# "memory/*" also covers "memory/retro/2026-01-01.md".
DENY_PATTERNS: tuple[str, ...] = (
    "memory/*",
    "cron/*",
    ".zeroclaw/*",
    "skills/*",
    "scripts/*",
    "state/jira_watch/*",
    "state/retention/*",
    "state/agent-browser/profile/*",
    "state/agent-browser/audit.log",
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*brain.db*",
    "MEMORY.md",
    "MEMORY_SNAPSHOT.md",
    "USER.md",
    "SOUL.md",
    "IDENTITY.md",
    "TOOLS.md",
    "HEARTBEAT.md",
    "logs/runtime-trace.jsonl",
    "logs/prompt-trace.jsonl",
    "logs/daemon-stderr.log",
)


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    kind: str  # "file" | "dir"
    patterns: tuple[str, ...]
    max_age_days: float
    guard: Callable[[Path], bool] | None = None


@dataclass(frozen=True, slots=True)
class Candidate:
    rule: str
    path: Path
    rel: str
    size_bytes: int
    age_secs: float


def is_denied(rel_posix: str) -> bool:
    return any(fnmatch.fnmatch(rel_posix, pattern) for pattern in DENY_PATTERNS)


def entry_age_secs(path: Path, now: float) -> float:
    """Age of a file, or of the newest file inside a directory tree."""
    try:
        if path.is_file():
            return now - path.stat().st_mtime
    except OSError:
        return 0.0
    newest = 0.0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                newest = max(newest, os.stat(os.path.join(root, name)).st_mtime)
            except OSError:
                continue
    if newest == 0.0:
        try:
            newest = path.stat().st_mtime
        except OSError:
            return 0.0
    return now - newest


def workspace_dirs(data_root: Path) -> list[Path]:
    """Per-user workspaces, fail-closed.

    Only `tg_<digits>` dirs qualify, and the workspace itself must not be a
    symlink: a symlinked workspace would make every workspace-relative
    allowlist glob resolve into some other directory (template, another user).
    """
    root = data_root / "workspaces"
    if not root.is_dir():
        return []
    found: list[Path] = []
    for entry in sorted(root.iterdir()):
        if not _USER_DIR_RE.match(entry.name) or entry.is_symlink():
            continue
        workspace = entry / "workspace"
        if workspace.is_symlink() or not workspace.is_dir():
            continue
        found.append(workspace)
    return found


def open_paths() -> set[str]:
    """Absolute paths currently held open by any live process (Linux only).

    A snapshot, not a lock: it lowers the odds of touching something in use,
    it does not eliminate the TOCTOU window. Acceptable because every candidate
    is at least 24h old.
    """
    held: set[str] = set()
    proc = Path("/proc")
    if not proc.is_dir():
        return held
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            entries = list((pid_dir / "fd").iterdir())
        except OSError:
            continue
        for fd in entries:
            try:
                held.add(os.readlink(fd))
            except OSError:
                continue
    return held


def _is_held(real: Path, kind: str, open_files: set[str]) -> bool:
    """A directory counts as held when any file *inside* it is open.

    /proc/<pid>/fd links point at files, never at their parent directory, so an
    exact-path check alone would happily rmtree a directory in active use.
    """
    if str(real) in open_files:
        return True
    if kind != "dir":
        return False
    prefix = str(real) + os.sep
    return any(path.startswith(prefix) for path in open_files)


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.stat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


def plan_workspace(
    workspace: Path,
    rules: Sequence[Rule],
    now: float,
    open_files: set[str],
) -> tuple[list[Candidate], dict[str, int]]:
    ws_real = workspace.resolve()
    plan: list[Candidate] = []
    skipped: dict[str, int] = {
        "denied": 0,
        "too_young": 0,
        "open": 0,
        "outside": 0,
        "guard": 0,
        "unresolvable": 0,
    }
    seen: set[Path] = set()
    for rule in rules:
        window = max(rule.max_age_days * 86_400.0, MIN_AGE_SECS)
        for pattern in rule.patterns:
            for match in sorted(workspace.glob(pattern)):
                if match in seen:
                    continue
                # resolve first: a broken symlink answers False to is_file()/
                # is_dir(), and skipping it silently would hide a real oddity.
                try:
                    real = match.resolve(strict=True)
                except OSError:
                    skipped["unresolvable"] += 1
                    continue
                if rule.kind == "file" and not match.is_file():
                    continue
                if rule.kind == "dir" and not match.is_dir():
                    continue
                rel = match.relative_to(workspace).as_posix()
                if is_denied(rel):
                    skipped["denied"] += 1
                    continue
                if ws_real not in real.parents:
                    skipped["outside"] += 1
                    continue
                if _is_held(real, rule.kind, open_files):
                    skipped["open"] += 1
                    continue
                age = entry_age_secs(match, now)
                if age < window:
                    skipped["too_young"] += 1
                    continue
                if rule.guard is not None and not rule.guard(match):
                    skipped["guard"] += 1
                    continue
                size = match.stat().st_size if rule.kind == "file" else _dir_size(match)
                seen.add(match)
                plan.append(Candidate(rule.name, match, rel, size, age))
    return plan, skipped


def jira_run_is_delivered(run_dir: Path) -> bool:
    """True only when the analysis result reached the user. Fail-closed.

    `done_at` is NOT a run field (it lives on the queue entry — see
    jira_analysis_run.py:5951). `exhausted_at` alone is not enough either:
    _exhaust_terminal() sets it even for delivery_status not_started/partial,
    and those artifacts are the only local evidence of a failed run.
    """
    try:
        data = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return data.get("delivery_status") == "complete" or data.get("status") == "delivered"


RULES: tuple[Rule, ...] = (
    Rule("graylog-dumps", "file", ("uploads/graylog/*",), 7.0),
    Rule(
        "gsheets-exports",
        "file",
        ("uploads/google_sheets/*", "state/gsheets_jobs/*", "logs/gsheets_jobs/*"),
        7.0,
    ),
    # legacy orphan names only; fork patch #35 stops new ones from accumulating
    Rule("trace-temp", "file", ("logs/runtime-trace.tmp.*",), 1.0),
    Rule("stderr-prev", "file", ("logs/*.prev.log",), 14.0),
    Rule("prompt-trace-rotated", "file", ("logs/prompt-trace.jsonl.[123]",), 14.0),
    Rule("images", "file", ("images/*",), 30.0),
    Rule(
        "uploads-agent",
        "file",
        ("uploads/jira/**/*", "uploads/diagrams/**/*"),
        30.0,
    ),
    Rule(
        "jira-runs",
        "dir",
        ("state/jira_tasks/*/runs/*",),
        30.0,
        guard=jira_run_is_delivered,
    ),
    Rule("commits-digest-state", "dir", ("state/lalafo_commits_digest/*",), 30.0),
    Rule(
        "agent-browser-scratch",
        "file",
        (
            "state/agent-browser/*.js",
            "state/agent-browser/*.png",
            "state/agent-browser/shots/*",
        ),
        30.0,
    ),
    Rule("sql-scratch", "file", ("state/sql/*",), 30.0),
)


def _delete(candidate: Candidate) -> None:
    if candidate.path.is_dir():
        shutil.rmtree(candidate.path)
    else:
        candidate.path.unlink()


def _normalize_users(users: Sequence[str] | None) -> set[str] | None:
    """Accept both `83292437` and `tg_83292437` — a silent 0-workspace scan is
    worse than a lenient filter."""
    if users is None:
        return None
    return {u if u.startswith("tg_") else f"tg_{u}" for u in users}


def _write_report(
    workspace: Path,
    *,
    rows: Sequence[dict[str, object]],
    skipped: dict[str, int],
    moment: float,
    dry_run: bool,
) -> str | None:
    """Write the per-workspace report atomically. Returns an error, never raises.

    The report is the only artifact the operator reads before enabling deletion,
    so it is written in BOTH modes and reflects real outcomes.
    """
    payload = {
        "ran_at": datetime.fromtimestamp(moment, tz=UTC).isoformat(),
        "dry_run": dry_run,
        "planned": len(rows),
        "deleted": sum(1 for r in rows if r["outcome"] == "deleted"),
        "failed": sum(1 for r in rows if r["outcome"] == "failed"),
        "freed_bytes": sum(
            int(r["size_bytes"]) for r in rows if r["outcome"] == "deleted"
        ),
        "skipped": skipped,
        "candidates": list(rows),
    }
    report_dir = workspace / "state" / "retention"
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        tmp = report_dir / "last-run.json.tmp"
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        tmp.replace(report_dir / "last-run.json")
    except OSError as exc:
        return str(exc)
    return None


def sweep(
    data_root: Path,
    *,
    rules: Sequence[Rule] = RULES,
    apply: bool = False,
    now: float | None = None,
    users: Sequence[str] | None = None,
    rule_names: Sequence[str] | None = None,
) -> dict[str, object]:
    moment = time.time() if now is None else now
    active = [r for r in rules if rule_names is None or r.name in set(rule_names)]
    wanted = _normalize_users(users)
    held = open_paths()

    per_rule: dict[str, dict[str, int]] = {}
    skipped_total: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    candidates: list[dict[str, object]] = []
    planned = deleted = failed = freed = workspaces = 0

    for workspace in workspace_dirs(data_root):
        if wanted is not None and workspace.parent.name not in wanted:
            continue
        workspaces += 1
        plan, skipped = plan_workspace(workspace, active, moment, held)
        for reason, count in skipped.items():
            skipped_total[reason] = skipped_total.get(reason, 0) + count

        rows: list[dict[str, object]] = []
        for candidate in plan:
            planned += 1
            row: dict[str, object] = {
                "rule": candidate.rule,
                "rel": candidate.rel,
                "size_bytes": candidate.size_bytes,
                "age_days": round(candidate.age_secs / 86_400, 1),
                "outcome": "planned",
            }
            bucket = per_rule.setdefault(candidate.rule, {"files": 0, "bytes": 0})
            if apply:
                try:
                    _delete(candidate)
                except OSError as exc:
                    row["outcome"] = "failed"
                    row["error"] = str(exc)
                    failed += 1
                    errors.append({"path": candidate.rel, "error": str(exc)})
                else:
                    row["outcome"] = "deleted"
                    deleted += 1
                    freed += candidate.size_bytes
                    bucket["files"] += 1
                    bucket["bytes"] += candidate.size_bytes
            else:
                bucket["files"] += 1
                bucket["bytes"] += candidate.size_bytes
            rows.append(row)
            candidates.append({"user": workspace.parent.name, **row})

        report_error = _write_report(
            workspace, rows=rows, skipped=skipped, moment=moment, dry_run=not apply
        )
        if report_error is not None:
            errors.append(
                {
                    "path": f"{workspace.parent.name}/state/retention",
                    "error": report_error,
                }
            )

    usage = shutil.disk_usage(data_root)
    return {
        "dry_run": not apply,
        "scanned_workspaces": workspaces,
        "planned": planned,
        "deleted": deleted,
        "failed": failed,
        "freed_bytes": freed,
        "per_rule": [
            {"rule": name, **counts} for name, counts in sorted(per_rule.items())
        ],
        "skipped": skipped_total,
        "errors": errors,
        "candidates": candidates,
        "free_bytes": usage.free,
        "total_bytes": usage.total,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Delete stale ZeroClaw artifacts by the retention rule table."
    )
    parser.add_argument("--data-root", required=True)
    parser.add_argument(
        "--apply", action="store_true", help="actually delete (default: dry-run)"
    )
    parser.add_argument("--user", action="append", default=None)
    parser.add_argument("--rule", action="append", default=None)
    args = parser.parse_args(argv)

    data_root = Path(args.data_root)
    if not data_root.is_dir():
        print(json.dumps({"error": f"data-root not a directory: {data_root}"}))
        return 2
    unknown = sorted(set(args.rule or []) - {rule.name for rule in RULES})
    if unknown:
        print(json.dumps({"error": f"unknown rules: {unknown}"}))
        return 2

    report = sweep(data_root, apply=args.apply, users=args.user, rule_names=args.rule)
    print(json.dumps(report, ensure_ascii=False))
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
