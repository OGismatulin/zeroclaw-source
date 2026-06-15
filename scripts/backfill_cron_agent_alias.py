#!/usr/bin/env python3
"""Backfill `agent_alias` on orphaned cron jobs after the v0.8.0 (schema V3)
migration.

Background: V3 made every cron job owned by an agent. The DB migration added
`cron_jobs.agent_alias TEXT NOT NULL DEFAULT ''`, so pre-V3 rows got an empty
alias. The scheduler's `resolve_owning_agent` then returns None for them and
skips execution with `Cron job has no owning agent` — cron silently stops.

This sets the owning agent on those orphaned rows to the synthesized main
agent (`default`), which is the correct owner for our integration (full
toolset, main model). Idempotent: only touches rows where `agent_alias` is
empty / NULL; rows already owned are left untouched.

Usage:
    # all per-user databases under a workspaces root
    backfill_cron_agent_alias.py --workspaces-root /zeroclaw-data/workspaces
    # a single jobs.db
    backfill_cron_agent_alias.py --db /path/to/cron/jobs.db
    # preview without writing
    backfill_cron_agent_alias.py --workspaces-root ./workspaces --dry-run

Stdlib-only. Never deletes; only UPDATEs the owning-agent column.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def _has_agent_alias_column(conn: sqlite3.Connection) -> bool:
    cols = [row[1] for row in conn.execute("PRAGMA table_info(cron_jobs)")]
    return "agent_alias" in cols


def backfill_db(db_path: Path, alias: str, dry_run: bool) -> int:
    """Return number of rows that were (or would be) updated for one db."""
    if not db_path.exists():
        print(f"skip (missing): {db_path}")
        return 0
    conn = sqlite3.connect(str(db_path))
    try:
        # cron_jobs table may not exist yet (db created but daemon never
        # opened it). Treat as nothing to do.
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "cron_jobs" not in tables:
            print(f"skip (no cron_jobs table): {db_path}")
            return 0
        if not _has_agent_alias_column(conn):
            # Pre-V3 binary opened this db: no ownership concept, nothing to fix.
            print(f"skip (no agent_alias column): {db_path}")
            return 0
        n = conn.execute(
            "SELECT COUNT(*) FROM cron_jobs "
            "WHERE agent_alias IS NULL OR TRIM(agent_alias) = ''"
        ).fetchone()[0]
        if n and not dry_run:
            conn.execute(
                "UPDATE cron_jobs SET agent_alias = ? "
                "WHERE agent_alias IS NULL OR TRIM(agent_alias) = ''",
                (alias,),
            )
            conn.commit()
        verb = "would set" if dry_run else "set"
        if n:
            print(f"{verb} agent_alias='{alias}' on {n} job(s): {db_path}")
        else:
            print(f"ok (already owned): {db_path}")
        return n
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--workspaces-root",
        help="loop every tg_*/workspace/cron/jobs.db under this directory",
    )
    g.add_argument("--db", help="path to a single cron/jobs.db")
    ap.add_argument(
        "--alias",
        default="default",
        help="owning agent alias to set (default: 'default')",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing",
    )
    args = ap.parse_args(argv)

    total = 0
    if args.db:
        total += backfill_db(Path(args.db), args.alias, args.dry_run)
    else:
        root = Path(args.workspaces_root)
        if not root.is_dir():
            print(f"error: not a directory: {root}", file=sys.stderr)
            return 2
        dbs = sorted(root.glob("tg_*/workspace/cron/jobs.db"))
        if not dbs:
            print(f"no tg_*/workspace/cron/jobs.db under {root}")
        for db in dbs:
            total += backfill_db(db, args.alias, args.dry_run)

    verb = "would update" if args.dry_run else "updated"
    print(f"--- {verb} {total} orphaned job(s) total ---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
