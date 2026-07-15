#!/usr/bin/env python3
"""
Clone, update, and discover Lalafo microservice and frontend repositories for agent code browsing.

Shallow-clones services into a shared directory (no vendor, no node_modules).
The ZeroClaw agent uses built-in file_read/content_search/glob_search to browse code.

Commands:
    clone                   First-time bulk clone of the initial bootstrap set (SERVICES + frontends + shared)
    pull [<name>]           Update all cloned repos, or a single one
    add <name>              Clone a single repo from gitlab.lalafo.com.ua/lalafo/<name> (any repo in the group)
    list-remote [--output PATH]
                            Fetch full list of projects in the lalafo GitLab group and write a Markdown snapshot
                            (split into cloned / not-cloned) to references/REPOS.md

Usage:
    # Local
    uv run python scripts/code_repos_sync.py clone
    uv run python scripts/code_repos_sync.py pull
    uv run python scripts/code_repos_sync.py pull user-microservice
    uv run python scripts/code_repos_sync.py add marketplace-microservice
    uv run python scripts/code_repos_sync.py list-remote

    # On Fly (via ssh)
    fly ssh console -a ai-forge-zeroclaw -C 'python3 /usr/local/bin/code_repos_sync.py pull'

Environment:
    GITLAB_DEPLOY_USER          GitLab deploy token username
    GITLAB_DEPLOY_TOKEN         GitLab deploy token password
    ZEROCLAW_DATA_ROOT          base dir for code-repos (default: ./code-repos locally, /zeroclaw-data on Fly)
    ZEROCLAW_SKILL_OUTPUT_ROOT  optional override for where list-remote writes REPOS.md
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

GITLAB_HOST = "gitlab.lalafo.com.ua"
GITLAB_GROUP = "lalafo"
GITLAB_API_BASE = f"https://{GITLAB_HOST}/api/v4"

# Initial bootstrap set used by `clone` / `pull` without args.
# NOT a whitelist — `add <name>` can clone any repo in the group.
SERVICES = [
    "user-microservice",
    "payment-microservice",
    "campaign-microservice",
    "catalog-microservice",
    "crm-microservice",
    "business-profile-microservice",
    "fraud-microservice",
    "moderation-microservice",
    "micromarket-microservice",
    "trigger-microservice",
    "wallet-microservice",
    "tds-microservice",
    "promo-microservice",
    "experiment-microservice",
]

FRONTEND_SERVICES = [
    "react-next-client",
]

SHARED_PACKAGES = [
    "platform",
]

ALL_REPOS = SERVICES + FRONTEND_SERVICES + SHARED_PACKAGES

_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def get_repos_dir() -> Path:
    """Determine code-repos directory based on environment."""
    data_root = os.environ.get("ZEROCLAW_DATA_ROOT")
    if data_root:
        return Path(data_root) / "code-repos"
    return Path(__file__).resolve().parent.parent / "code-repos"


def _get_credentials() -> tuple[str, str]:
    user = os.environ.get("GITLAB_DEPLOY_USER", "")
    token = os.environ.get("GITLAB_DEPLOY_TOKEN", "")
    if not user or not token:
        print("ERROR: GITLAB_DEPLOY_USER and GITLAB_DEPLOY_TOKEN must be set")
        sys.exit(1)
    return user, token


def get_clone_url(service: str) -> str:
    """Build HTTPS clone URL with deploy token credentials."""
    user, token = _get_credentials()
    return f"https://{user}:{token}@{GITLAB_HOST}/{GITLAB_GROUP}/{service}.git"


def run_git(args: list[str], cwd: Path | None = None) -> bool:
    """Run a git command, return True on success."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"  FAIL: git {' '.join(args)}")
        if result.stderr:
            print(f"  stderr: {result.stderr.strip()}")
        return False
    return True


def clone_all() -> None:
    """Shallow-clone the initial bootstrap set (ALL_REPOS)."""
    repos_dir = get_repos_dir()
    repos_dir.mkdir(parents=True, exist_ok=True)

    total = len(ALL_REPOS)
    cloned = 0
    skipped = 0
    failed = 0

    for i, service in enumerate(ALL_REPOS, 1):
        dest = repos_dir / service
        print(f"[{i}/{total}] {service} ... ", end="", flush=True)

        if dest.exists() and (dest / ".git").exists():
            print("already cloned, skipping")
            skipped += 1
            continue

        url = get_clone_url(service)
        if run_git(["clone", "--depth", "1", url, str(dest)]):
            print("OK")
            cloned += 1
        else:
            print("FAILED")
            failed += 1

    print(f"\nDone: {cloned} cloned, {skipped} skipped, {failed} failed")


def pull_all() -> None:
    """Git pull in all cloned service repos (bootstrap set)."""
    repos_dir = get_repos_dir()

    if not repos_dir.exists():
        print(f"ERROR: {repos_dir} does not exist. Run 'clone' first.")
        sys.exit(1)

    total = len(ALL_REPOS)
    updated = 0
    skipped = 0
    failed = 0

    for i, service in enumerate(ALL_REPOS, 1):
        dest = repos_dir / service
        print(f"[{i}/{total}] {service} ... ", end="", flush=True)

        if not dest.exists() or not (dest / ".git").exists():
            print("not cloned, skipping")
            skipped += 1
            continue

        if run_git(["pull"], cwd=dest):
            print("OK")
            updated += 1
        else:
            print("FAILED")
            failed += 1

    print(f"\nDone: {updated} updated, {skipped} skipped, {failed} failed")


def pull_one(name: str) -> None:
    """Update a single cloned repository."""
    repos_dir = get_repos_dir()
    dest = repos_dir / name
    if not (dest / ".git").is_dir():
        print(f"ERROR: repo not cloned: {name}")
        sys.exit(1)
    if run_git(["pull"], cwd=dest):
        print(f"updated: {dest}")
    else:
        print(f"FAILED to pull {name}")
        sys.exit(1)


def add_repo(name: str) -> None:
    """Clone a single repo from the lalafo group by name.

    Validates the name, checks repo existence via GitLab API, skips if already cloned,
    otherwise does a shallow clone.
    """
    if not _NAME_RE.match(name):
        print(f"ERROR: Invalid repo name: {name!r}")
        sys.exit(1)

    _, token = _get_credentials()
    repos_dir = get_repos_dir()
    repos_dir.mkdir(parents=True, exist_ok=True)
    dest = repos_dir / name

    if (dest / ".git").is_dir():
        print(f"already cloned: {dest}")
        return

    probe_url = f"{GITLAB_API_BASE}/projects/{GITLAB_GROUP}%2F{name}"
    resp = requests.get(probe_url, headers={"PRIVATE-TOKEN": token}, timeout=30)
    if resp.status_code == 404:
        print(f"ERROR: repo not found in group {GITLAB_GROUP}: {name}")
        sys.exit(1)
    if resp.status_code >= 400:
        print(f"ERROR: GitLab API returned {resp.status_code} for {name}")
        sys.exit(1)

    url = get_clone_url(name)
    if run_git(["clone", "--depth", "1", url, str(dest)]):
        print(f"cloned: {dest}")
    else:
        print(f"FAILED to clone {name}")
        sys.exit(1)


def fetch_all_projects() -> list[dict]:
    """Fetch all projects in the lalafo group via GitLab API with pagination."""
    _, token = _get_credentials()

    projects: list[dict] = []
    page = 1
    while True:
        url = (
            f"{GITLAB_API_BASE}/groups/{GITLAB_GROUP}/projects"
            f"?per_page=100&simple=true&archived=false&page={page}"
        )
        resp = requests.get(url, headers={"PRIVATE-TOKEN": token}, timeout=30)
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        projects.extend(batch)
        next_page = resp.headers.get("X-Next-Page", "")
        if not next_page:
            break
        page = int(next_page)
    return projects


def render_repos_md(projects: list[dict], repos_dir: Path, now: str) -> str:
    """Render a Markdown snapshot splitting cloned vs not-cloned repos."""
    rows: list[tuple[str, str, str, bool]] = []
    for p in projects:
        name = p["path"]
        activity = (p.get("last_activity_at") or "")[:10]
        desc = (p.get("description") or "").replace("|", "/").strip()
        cloned = (repos_dir / name / ".git").is_dir()
        rows.append((name, activity, desc, cloned))
    rows.sort(key=lambda r: r[0])

    cloned_rows = [r for r in rows if r[3]]
    not_cloned_rows = [r for r in rows if not r[3]]

    lines = [
        "# Lalafo GitLab Repositories",
        "",
        f"Snapshot of https://{GITLAB_HOST}/{GITLAB_GROUP} — refreshed {now}.",
        "Refresh command: `python3 scripts/code_repos_sync.py list-remote`",
        "",
        (
            f"Total: {len(rows)} repos. "
            f"Cloned locally: {len(cloned_rows)}. "
            f"Not cloned: {len(not_cloned_rows)}."
        ),
        "",
        f"## Cloned locally ({len(cloned_rows)})",
        "",
        "| Repo | Last activity | Description |",
        "|---|---|---|",
    ]
    for name, activity, desc, _ in cloned_rows:
        lines.append(f"| {name} | {activity} | {desc} |")
    lines += [
        "",
        f"## Not cloned ({len(not_cloned_rows)})",
        "",
        "| Repo | Last activity | Description |",
        "|---|---|---|",
    ]
    for name, activity, desc, _ in not_cloned_rows:
        lines.append(f"| {name} | {activity} | {desc} |")
    lines.append("")
    return "\n".join(lines)


def resolve_repos_md_path(explicit: str | None) -> Path:
    """Resolve where to write REPOS.md. Priority: explicit > env > local layout > CWD > fallback."""
    if explicit:
        return Path(explicit)
    env_root = os.environ.get("ZEROCLAW_SKILL_OUTPUT_ROOT")
    if env_root:
        return Path(env_root) / "skills" / "lalafo-code" / "references" / "REPOS.md"
    script = Path(__file__).resolve()
    if script.parent.name == "scripts" and (script.parent.parent / "workspace").is_dir():
        return (
            script.parent.parent
            / "workspace"
            / "skills"
            / "lalafo-code"
            / "references"
            / "REPOS.md"
        )
    cwd_candidate = Path.cwd() / "skills" / "lalafo-code" / "references" / "REPOS.md"
    if (Path.cwd() / "skills").is_dir():
        return cwd_candidate
    return Path("/zeroclaw-data/template/workspace/skills/lalafo-code/references/REPOS.md")


def list_remote(explicit_output: str | None) -> None:
    """Fetch projects from GitLab and write a Markdown snapshot."""
    projects = fetch_all_projects()
    repos_dir = get_repos_dir()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = render_repos_md(projects, repos_dir, now=now)
    out = resolve_repos_md_path(explicit_output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    print(f"Wrote {len(projects)} projects to {out}")


def _parse_list_remote_output() -> str | None:
    for i, a in enumerate(sys.argv):
        if a == "--output" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("clone", "pull", "list-remote", "add"):
        print("Usage: code_repos_sync.py <clone|pull [<name>]|add <name>|list-remote [--output PATH]>")
        sys.exit(1)

    command = sys.argv[1]
    repos_dir = get_repos_dir()
    print(f"Code repos directory: {repos_dir}")
    print(f"Command: {command}\n")

    if command == "clone":
        clone_all()
    elif command == "pull":
        if len(sys.argv) >= 3:
            pull_one(sys.argv[2])
        else:
            pull_all()
    elif command == "add":
        if len(sys.argv) < 3:
            print("Usage: code_repos_sync.py add <name>")
            sys.exit(1)
        add_repo(sys.argv[2])
    elif command == "list-remote":
        list_remote(_parse_list_remote_output())


if __name__ == "__main__":
    main()
