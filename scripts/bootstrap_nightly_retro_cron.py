#!/usr/bin/env python3
"""Bootstrap nightly-retrospective cron job for all per-user workspaces.

Idempotent: skips workspaces that already have a job named
'nightly-retrospective'. Time slots are deterministic per user_id so
the 1GB Fly VM doesn't see all daemons fire at the exact same minute.

Usage:
    # On Fly machine (default workspaces root):
    cat scripts/bootstrap_nightly_retro_cron.py | fly ssh console \\
        -a ai-forge-zeroclaw -C "python3 -"

    # Locally:
    python3 scripts/bootstrap_nightly_retro_cron.py \\
        --workspaces-root ./workspaces

    # Specific user only:
    python3 scripts/bootstrap_nightly_retro_cron.py --user 83292437

For new users this script can be re-run any time — it will skip those
that already have the cron entry. Hook it into fly-entrypoint.sh /
local-entrypoint.sh to run automatically on every machine startup.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

JOB_NAME = "nightly-retrospective"

# Explicit time slots for known production users (UTC) — staggered to
# avoid concurrent fires on the shared 1GB VM.
EXPLICIT_SLOTS: dict[str, str] = {
    "83292437": "0 3 * * *",    # Oleg — 03:00 UTC
    "585236623": "10 3 * * *",  # Altynay — 03:10 UTC
    "897389102": "20 3 * * *",  # Medina — 03:20 UTC
}

# Test users — never bootstrap retro cron for them.
EXCLUDE_USERS: set[str] = {"99999"}

PROMPT_TEMPLATE = (
    "Use the nightly-retrospective skill for yesterday. "
    "Notify telegram user_id {user_id} with the summary."
)


def slot_for(user_id: str) -> str:
    """Return cron expression for this user.

    Known users use explicit slots; unknown users get a deterministic
    minute based on user_id %% 60 to keep new-user bootstrap automatic.
    """
    if user_id in EXPLICIT_SLOTS:
        return EXPLICIT_SLOTS[user_id]
    try:
        minute = int(user_id) % 60
    except ValueError:
        minute = sum(ord(c) for c in user_id) % 60
    return f"{minute} 3 * * *"


def next_run_after(expression: str, now: datetime) -> datetime:
    """Compute next fire time for a daily expression '<min> <hour> * * *'."""
    parts = expression.split()
    if len(parts) != 5:
        raise ValueError(f"unsupported cron expression: {expression!r}")
    minute, hour, dom, mon, dow = parts
    if dom != "*" or mon != "*" or dow != "*":
        raise ValueError("bootstrap supports only daily expressions")
    target = now.replace(
        hour=int(hour), minute=int(minute), second=0, microsecond=0
    )
    if target <= now:
        target = target + timedelta(days=1)
    return target


def has_job(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM cron_jobs WHERE name = ? LIMIT 1", (name,)
    ).fetchone()
    return row is not None


def insert_cron(conn: sqlite3.Connection, user_id: str) -> str:
    expression = slot_for(user_id)
    now = datetime.now(timezone.utc)
    next_run = next_run_after(expression, now)
    job_id = str(uuid.uuid4())
    prompt = PROMPT_TEMPLATE.format(user_id=user_id)
    conn.execute(
        """
        INSERT INTO cron_jobs (
            id, expression, command, schedule, job_type, prompt, name,
            session_target, model, enabled, delivery, delete_after_run,
            created_at, next_run, last_run, last_status, last_output
        ) VALUES (?, ?, '', NULL, 'agent', ?, ?, 'isolated', NULL, 1, NULL, 0,
                  ?, ?, NULL, NULL, NULL)
        """,
        (
            job_id,
            expression,
            prompt,
            JOB_NAME,
            now.isoformat(),
            next_run.isoformat(),
        ),
    )
    conn.commit()
    return f"id={job_id[:8]} expression={expression!r} next_run={next_run.isoformat()}"


def bootstrap_workspace(workspace: Path, user_id: str, verbose: bool) -> str:
    """Bootstrap a single workspace. Returns a status string."""
    if user_id in EXCLUDE_USERS:
        return f"⊘ tg_{user_id}: excluded (test user)"
    db = workspace / "cron" / "jobs.db"
    if not db.is_file():
        return f"⚠ tg_{user_id}: no jobs.db (daemon never spawned)"
    with sqlite3.connect(db) as conn:
        if has_job(conn, JOB_NAME):
            return f"✓ tg_{user_id}: already has '{JOB_NAME}'"
        info = insert_cron(conn, user_id)
        return f"+ tg_{user_id}: inserted {info}"


def bootstrap_all(workspaces_root: Path, verbose: bool = True) -> int:
    if not workspaces_root.is_dir():
        print(f"ERROR: workspaces root not found: {workspaces_root}", file=sys.stderr)
        return 2
    inserted = 0
    existing = 0
    excluded = 0
    pending = 0
    for entry in sorted(workspaces_root.iterdir()):
        if not entry.is_dir() or not entry.name.startswith("tg_"):
            continue
        user_id = entry.name[len("tg_"):]
        ws = entry / "workspace"
        msg = bootstrap_workspace(ws, user_id, verbose)
        if verbose:
            print(f"  {msg}")
        if msg.startswith("+ "):
            inserted += 1
        elif msg.startswith("✓ "):
            existing += 1
        elif msg.startswith("⊘ "):
            excluded += 1
        elif msg.startswith("⚠ "):
            pending += 1
    if verbose:
        print(
            f"\nInserted: {inserted}  Existing: {existing}  "
            f"Excluded: {excluded}  Pending (no jobs.db yet): {pending}"
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap nightly-retrospective cron in per-user workspaces.",
    )
    parser.add_argument(
        "--workspaces-root",
        type=Path,
        default=Path("/zeroclaw-data/workspaces"),
        help="Directory containing tg_<user_id>/ subdirs (default: Fly volume path)",
    )
    parser.add_argument(
        "--user",
        help="Bootstrap one user only (e.g. 83292437)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.user:
        ws = args.workspaces_root / f"tg_{args.user}" / "workspace"
        msg = bootstrap_workspace(ws, args.user, verbose=not args.quiet)
        print(msg)
        return 0
    return bootstrap_all(args.workspaces_root, verbose=not args.quiet)


if __name__ == "__main__":
    sys.exit(main())
