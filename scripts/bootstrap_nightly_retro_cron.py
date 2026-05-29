#!/usr/bin/env python3
"""DEPRECATED — thin backward-compat wrapper.

Delegates to /usr/local/bin/bootstrap_default_cron_jobs.py with --template
nightly-retrospective. Works under `cat ... | python3 -` heredoc pipe
because find_delegate() does not rely on __file__ / sys.argv[0] / cwd.

External callers:
- `cat scripts/bootstrap_nightly_retro_cron.py | fly ssh console
  -a ai-forge-zeroclaw -C "python3 -"` for emergency rebootstrap

Will be removed 2-3 weeks after deploy.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


# Strict resolution: only /usr/local/bin/ (запечено в image) or PATH lookup.
# No __file__ / cwd fallback (unreliable under heredoc pipe).
DELEGATE_PATH = Path("/usr/local/bin/bootstrap_default_cron_jobs.py")


def find_delegate() -> Path:
    """Resolve delegate via /usr/local/bin/ or PATH. Raises if not found."""
    if DELEGATE_PATH.is_file():
        return DELEGATE_PATH
    via_path = shutil.which("bootstrap_default_cron_jobs.py")
    if via_path:
        return Path(via_path)
    raise FileNotFoundError(
        f"bootstrap_default_cron_jobs.py not found at {DELEGATE_PATH} or in PATH. "
        "Image rebuild required."
    )


def main() -> int:
    delegate = find_delegate()
    args = sys.argv[1:]
    cmd = [sys.executable, str(delegate), "--template", "nightly-retrospective", *args]
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
