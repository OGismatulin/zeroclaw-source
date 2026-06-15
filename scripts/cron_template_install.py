#!/usr/bin/env python3
"""Cron template install/uninstall CLI.

Loads template manifests from workspace/cron_templates/<name>/, validates,
renders prompt with params, INSERTs into per-user cron/jobs.db.

Used by:
- Makefile (manual install)
- bootstrap_default_cron_jobs.py (auto-bootstrap on first daemon spawn)
- runtime agent (via shell, through cron-templates skill)

See spec: docs/superpowers/specs/2026-05-28-default-cron-templates-and-lalafo-errors-digest-design.md
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from croniter import croniter
except ImportError:
    croniter = None  # type: ignore


class TemplateLoadError(Exception):
    """Manifest validation error."""


REQUIRED_TEMPLATE_FIELDS = (
    "name", "title", "description", "default_schedule",
    "session_target", "delete_after_run", "job_type",
)


@dataclass(frozen=True)
class CronTemplate:
    name: str
    title: str
    description: str
    default_schedule: str
    session_target: str
    delete_after_run: bool
    job_type: str
    prompt_template: str
    audience: frozenset[str] = field(default_factory=frozenset)
    audience_all: bool = False
    exclude: frozenset[str] = field(default_factory=frozenset)
    tags: tuple[str, ...] = ()
    slot_strategy: dict[str, Any] | None = None
    params_meta: dict[str, Any] = field(default_factory=dict)
    model_provider: str = ""
    model_name: str = ""
    model_reasoning_effort: str = ""
    source_dir: Path | None = None

    @classmethod
    def load(cls, template_dir: Path) -> "CronTemplate":
        manifest_path = template_dir / "template.toml"
        prompt_path = template_dir / "prompt.md"
        if not manifest_path.is_file():
            raise TemplateLoadError(f"template.toml missing: {manifest_path}")
        if not prompt_path.is_file():
            raise TemplateLoadError(f"prompt.md missing: {prompt_path}")
        with manifest_path.open("rb") as fh:
            data = tomllib.load(fh)
        for required in REQUIRED_TEMPLATE_FIELDS:
            if required not in data:
                raise TemplateLoadError(
                    f"template.toml missing required field '{required}' in {template_dir}"
                )
        schedule = data["default_schedule"]
        cls._validate_schedule(schedule, delete_after_run=data["delete_after_run"])
        ab = data.get("auto_bootstrap", {})
        audience_raw = ab.get("audience", [])
        audience_all = "all" in audience_raw
        audience = frozenset(a for a in audience_raw if a != "all")
        exclude = frozenset(ab.get("exclude", []))
        prompt_template = prompt_path.read_text(encoding="utf-8").strip()
        return cls(
            name=data["name"],
            title=data["title"],
            description=data["description"].strip(),
            default_schedule=schedule,
            session_target=data["session_target"],
            delete_after_run=bool(data["delete_after_run"]),
            job_type=data["job_type"],
            prompt_template=prompt_template,
            audience=audience,
            audience_all=audience_all,
            exclude=exclude,
            tags=tuple(data.get("tags", [])),
            slot_strategy=data.get("slot_strategy"),
            params_meta=data.get("params", {}),
            model_provider=data.get("model", {}).get("provider", ""),
            model_name=data.get("model", {}).get("model", ""),
            model_reasoning_effort=data.get("model", {}).get("reasoning_effort", ""),
            source_dir=template_dir,
        )

    @staticmethod
    def _validate_schedule(expr: str, delete_after_run: bool) -> None:
        # Reject RFC3339 (at-schedule) — NG2 в spec'е
        if "T" in expr or "Z" in expr:
            raise TemplateLoadError(
                f"at-schedule (RFC3339) not supported in templates, "
                f"only cron 5-field expressions: got {expr!r}"
            )
        parts = expr.split()
        if len(parts) != 5:
            raise TemplateLoadError(
                f"schedule must be cron 5-field expression, got {expr!r}"
            )
        if delete_after_run:
            raise TemplateLoadError(
                "delete_after_run=true incompatible with cron schedule "
                "(at-schedule one-shots not supported in templates)"
            )
        if croniter is not None:
            if not croniter.is_valid(expr):
                raise TemplateLoadError(f"invalid cron expression: {expr!r}")

    def render_prompt(self, params: dict[str, str]) -> str:
        try:
            return self.prompt_template.format_map(params)
        except KeyError as exc:
            raise TemplateLoadError(
                f"prompt references undefined param: {exc.args[0]}"
            ) from exc


@dataclass(frozen=True)
class InstallResult:
    status: str   # "installed" | "existing" | "reinstalled" | "removed" |
                  # "not_found" | "no_jobs_db" | "audience_skip" | "error"
    user_id: str
    template: str
    id: str | None = None
    expression: str | None = None
    next_run: str | None = None
    error: str | None = None


def resolve_templates_root(
    explicit: Path | None,
    workspaces_root: Path,
    user_id: str | None,
) -> Path:
    if explicit is not None:
        return explicit
    if user_id is not None:
        per_user = workspaces_root / f"tg_{user_id}" / "workspace" / "cron_templates"
        if per_user.is_dir():
            return per_user
    template_level = workspaces_root.parent / "template" / "workspace" / "cron_templates"
    if template_level.is_dir():
        return template_level
    script_dir = Path(__file__).resolve().parent.parent
    local_ws = script_dir / "workspace" / "cron_templates"
    if local_ws.is_dir():
        return local_ws
    raise FileNotFoundError(
        "cron_templates directory not found; tried per-user, template-level, local"
    )


def compute_next_run(expression: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    if croniter is None:
        # Fallback for daily expressions like "0 3 * * *"
        parts = expression.split()
        if len(parts) != 5 or parts[2:] != ["*", "*", "*"]:
            raise ValueError(
                f"without croniter, only daily expressions supported: {expression!r}"
            )
        minute, hour = int(parts[0]), int(parts[1])
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target
    itr = croniter(expression, now)
    return itr.get_next(datetime)


def resolve_params(
    template: CronTemplate,
    user_id: str,
    cli_overrides: dict[str, str],
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for key, meta in template.params_meta.items():
        if key in cli_overrides:
            resolved[key] = cli_overrides[key]
            continue
        if "default" in meta:
            resolved[key] = str(meta["default"])
            continue
        auto = meta.get("auto_default", "")
        if auto == "from_user_key":
            resolved[key] = user_id
            continue
        if auto.startswith("from_env:"):
            import os
            env_var = auto.split(":", 1)[1]
            val = os.environ.get(env_var)
            if val is None and meta.get("required"):
                raise ValueError(f"param '{key}' required but env '{env_var}' unset")
            resolved[key] = val or ""
            continue
        if meta.get("required"):
            raise ValueError(f"param '{key}' required but not provided")
    # Always provide user_id, even if not declared in params
    resolved.setdefault("user_id", user_id)
    return resolved


# Owning agent for bootstrap-installed cron jobs. The synthesized main agent
# ("default" in the in-memory V3 config) carries the full toolset + main model,
# unlike the restricted subagents (worker/coder/analyst_*).
CRON_OWNING_AGENT = "default"


def _ensure_agent_alias_column(conn: sqlite3.Connection) -> None:
    """Defensive guard: the daemon's DB migration normally adds this column
    before bootstrap runs (install happens after the daemon is healthy), but
    add it if missing so the INSERT can't fail on a freshly-created db."""
    cols = [row[1] for row in conn.execute("PRAGMA table_info(cron_jobs)")]
    # PRAGMA returns [] for a non-existent table; only ALTER an existing one.
    if cols and "agent_alias" not in cols:
        conn.execute(
            "ALTER TABLE cron_jobs ADD COLUMN agent_alias TEXT NOT NULL DEFAULT ''"
        )


def install_template(
    workspaces_root: Path,
    user_id: str,
    template: CronTemplate,
    schedule_override: str | None,
    cli_params: dict[str, str],
    reinstall: bool,
    dry_run: bool,
    *,
    force: bool = False,
    now: datetime | None = None,
) -> InstallResult:
    # Audience check
    if not force:
        if template.audience and user_id not in template.audience and not template.audience_all:
            return InstallResult("audience_skip", user_id, template.name)
        if user_id in template.exclude:
            return InstallResult("audience_skip", user_id, template.name)

    jobs_db = workspaces_root / f"tg_{user_id}" / "workspace" / "cron" / "jobs.db"
    if not jobs_db.is_file():
        return InstallResult("no_jobs_db", user_id, template.name)

    schedule = schedule_override or template.default_schedule
    CronTemplate._validate_schedule(schedule, delete_after_run=template.delete_after_run)
    next_run = compute_next_run(schedule, now=now)
    params = resolve_params(template, user_id, cli_params)
    rendered_prompt = template.render_prompt(params)
    job_id = str(uuid.uuid4())
    model = ""
    if template.model_provider and template.model_name:
        model = f"{template.model_provider}/{template.model_name}"

    if dry_run:
        return InstallResult(
            "installed" if not reinstall else "reinstalled",
            user_id, template.name, job_id, schedule, next_run.isoformat(),
        )

    conn = sqlite3.connect(jobs_db)
    try:
        _ensure_agent_alias_column(conn)
        existing = conn.execute(
            "SELECT id, expression FROM cron_jobs WHERE name = ?", (template.name,)
        ).fetchone()
        if existing and not reinstall:
            return InstallResult("existing", user_id, template.name, existing[0], existing[1])
        if existing and reinstall:
            conn.execute("DELETE FROM cron_jobs WHERE name = ?", (template.name,))
        # V3 (schema_version 3, zeroclaw v0.8.0+) requires every cron job to be
        # owned by an agent — the scheduler skips jobs with an empty
        # `agent_alias` ("Cron job has no owning agent"). Bootstrap-inserted
        # template jobs are owned by the synthesized main agent "default".
        conn.execute(
            """
            INSERT INTO cron_jobs (
                id, expression, command, schedule, job_type, prompt, name,
                session_target, model, enabled, delivery, delete_after_run,
                created_at, next_run, last_run, last_status, last_output,
                agent_alias
            ) VALUES (?, ?, '', NULL, ?, ?, ?, ?, ?, 1, NULL, ?,
                      ?, ?, NULL, NULL, NULL, ?)
            """,
            (
                job_id, schedule, template.job_type, rendered_prompt,
                template.name, template.session_target,
                model if model else None,
                1 if template.delete_after_run else 0,
                (now or datetime.now(timezone.utc)).isoformat(),
                next_run.isoformat(),
                CRON_OWNING_AGENT,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    status = "reinstalled" if existing else "installed"
    return InstallResult(status, user_id, template.name, job_id, schedule, next_run.isoformat())


def uninstall_template(
    workspaces_root: Path, user_id: str, template_name: str
) -> InstallResult:
    jobs_db = workspaces_root / f"tg_{user_id}" / "workspace" / "cron" / "jobs.db"
    if not jobs_db.is_file():
        return InstallResult("no_jobs_db", user_id, template_name)
    conn = sqlite3.connect(jobs_db)
    try:
        cur = conn.execute("DELETE FROM cron_jobs WHERE name = ?", (template_name,))
        conn.commit()
    finally:
        conn.close()
    return InstallResult("removed" if cur.rowcount else "not_found", user_id, template_name)


def format_text(result: InstallResult) -> str:
    prefix = {
        "installed": "+", "existing": "✓", "reinstalled": "~",
        "removed": "-", "not_found": "⊘", "no_jobs_db": "⚠",
        "audience_skip": "⊘", "error": "✗",
    }[result.status]
    parts = [f"{prefix} tg_{result.user_id}: {result.status} '{result.template}'"]
    if result.id:
        parts.append(f"id={result.id[:8]}")
    if result.expression:
        parts.append(f"schedule={result.expression!r}")
    if result.next_run:
        parts.append(f"next_run={result.next_run}")
    if result.error:
        parts.append(f"error={result.error}")
    return " ".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspaces-root", type=Path)
    parser.add_argument("--templates-root", type=Path, default=None)
    parser.add_argument("--user")
    parser.add_argument("--template")
    parser.add_argument("--schedule")
    parser.add_argument("--param", action="append", default=[],
                        help="param-key=value; repeatable")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--reinstall", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="bypass audience whitelist (for smoke / emergency)")
    args = parser.parse_args()

    if args.list:
        return _do_list(args)

    if not args.workspaces_root or not args.user or not args.template:
        print("ERROR: --workspaces-root, --user, --template required (unless --list)",
              file=sys.stderr)
        return 2

    try:
        templates_root = resolve_templates_root(
            args.templates_root, args.workspaces_root, args.user
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    tdir = templates_root / args.template
    if not tdir.is_dir():
        print(f"ERROR: template not found: {args.template} (looked in {templates_root})",
              file=sys.stderr)
        return 2

    try:
        template = CronTemplate.load(tdir)
    except TemplateLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.uninstall:
        result = uninstall_template(args.workspaces_root, args.user, template.name)
    else:
        cli_params = dict(p.split("=", 1) for p in args.param if "=" in p)
        try:
            result = install_template(
                args.workspaces_root, args.user, template,
                args.schedule, cli_params, args.reinstall, args.dry_run,
                force=args.force,
            )
        except (ValueError, TemplateLoadError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(result.__dict__, default=str))
    elif not args.quiet:
        print(format_text(result))
    return 0


def _do_list(args) -> int:
    """Dump all manifests as JSON list."""
    try:
        templates_root = resolve_templates_root(
            args.templates_root,
            args.workspaces_root or Path("workspaces"),
            args.user,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    out = []
    for tdir in sorted(templates_root.iterdir()):
        if not tdir.is_dir() or tdir.name.startswith("_"):
            continue
        if not (tdir / "template.toml").is_file():
            continue
        try:
            t = CronTemplate.load(tdir)
        except TemplateLoadError:
            continue
        out.append({
            "name": t.name,
            "title": t.title,
            "description": t.description,
            "default_schedule": t.default_schedule,
            "audience": sorted(t.audience),
            "audience_all": t.audience_all,
            "exclude": sorted(t.exclude),
            "tags": list(t.tags),
        })
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
