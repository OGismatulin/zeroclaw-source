#!/usr/bin/env python3
"""Bootstrap all auto-bootstrap templates for one or all users.

Thin orchestrator over cron_template_install.py. Idempotent.

Used by:
- gateway_manager._ensure_default_cron_jobs (subprocess on first daemon spawn)
- Manual one-shot bulk-bootstrap (`fly ssh console -C "python3 -" < this_file`)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore


def find_install_script() -> Path:
    """Resolve cron_template_install.py via /usr/local/bin/ or sibling."""
    in_path = Path("/usr/local/bin/cron_template_install.py")
    if in_path.is_file():
        return in_path
    sibling = Path(__file__).resolve().parent / "cron_template_install.py"
    if sibling.is_file():
        return sibling
    raise FileNotFoundError("cron_template_install.py not found")


def resolve_templates_root(workspaces_root: Path, user_id: str | None) -> Path:
    if user_id:
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
    raise FileNotFoundError(f"cron_templates not found near {workspaces_root}")


def list_auto_bootstrap_templates(templates_root: Path) -> list[tuple[str, dict]]:
    """Return [(name, manifest_dict), ...] for templates that declare auto_bootstrap."""
    out = []
    for tdir in sorted(templates_root.iterdir()):
        if not tdir.is_dir() or tdir.name.startswith("_"):
            continue
        manifest = tdir / "template.toml"
        if not manifest.is_file():
            continue
        with manifest.open("rb") as fh:
            data = tomllib.load(fh)
        if "auto_bootstrap" not in data:
            continue
        out.append((data["name"], data))
    return out


def bootstrap_user(
    user_id: str,
    workspaces_root: Path,
    install_script: Path,
    quiet: bool,
) -> int:
    templates_root = resolve_templates_root(workspaces_root, user_id)
    templates = list_auto_bootstrap_templates(templates_root)
    rc = 0
    for name, _ in templates:
        proc = subprocess.run(
            [sys.executable, str(install_script),
             "--workspaces-root", str(workspaces_root),
             "--user", user_id,
             "--template", name,
             "--json" if quiet else "--quiet"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(f"[bootstrap] {user_id}/{name}: rc={proc.returncode} {proc.stderr.strip()}",
                  file=sys.stderr)
            rc = max(rc, proc.returncode)
        elif not quiet:
            print(proc.stdout.strip())
    return rc


def bootstrap_all_users(workspaces_root: Path, install_script: Path, quiet: bool) -> int:
    if not workspaces_root.is_dir():
        print(f"ERROR: {workspaces_root} not found", file=sys.stderr)
        return 2
    rc = 0
    for entry in sorted(workspaces_root.iterdir()):
        if not entry.is_dir() or not entry.name.startswith("tg_"):
            continue
        user_id = entry.name[len("tg_"):]
        if not quiet:
            print(f"--- tg_{user_id} ---")
        rc = max(rc, bootstrap_user(user_id, workspaces_root, install_script, quiet))
    return rc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspaces-root", type=Path,
                        default=Path("/zeroclaw-data/workspaces"))
    parser.add_argument("--user", help="bootstrap one user only")
    parser.add_argument("--template",
                        help="bootstrap one template only (regardless of audience)")
    parser.add_argument("--all-users", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    install_script = find_install_script()
    if args.template and args.user:
        proc = subprocess.run(
            [sys.executable, str(install_script),
             "--workspaces-root", str(args.workspaces_root),
             "--user", args.user, "--template", args.template,
             "--json" if args.quiet else "--quiet"],
            capture_output=True, text=True,
        )
        if not args.quiet:
            print(proc.stdout.strip() or proc.stderr.strip())
        return proc.returncode
    if args.user:
        return bootstrap_user(args.user, args.workspaces_root, install_script, args.quiet)
    return bootstrap_all_users(args.workspaces_root, install_script, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
