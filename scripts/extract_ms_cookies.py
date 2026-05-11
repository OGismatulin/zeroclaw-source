#!/usr/bin/env python3
"""Extract Microsoft Entra + oauth2-proxy cookies from local Chrome for the
Graylog silent-SSO spike.

Reads Chrome's SQLite cookie store, decrypts via macOS Keychain (will trigger
a one-time Keychain prompt: "python3 wants to use Chrome Safe Storage"), filters
to relevant domains, writes a JSON summary to secrets/microsoft-session-cookies.json.

Run from project root:
    pip3 install --user browser_cookie3
    python3 scripts/extract_ms_cookies.py

The output file is gitignored (secrets/ is in .gitignore). Values inside are the
raw HttpOnly cookies that allow re-authenticating as the current user against
Microsoft Entra — handle with the same care as a password.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

RELEVANT_DOMAIN_SUFFIXES: dict[str, str] = {
    ".microsoftonline.com": "microsoft_session",
    ".live.com": "microsoft_live",
    ".graylog.yallasvc.net": "graylog_oauth2_proxy",
    "graylog.yallasvc.net": "graylog_oauth2_proxy",
}

DEFAULT_OUT = Path("secrets/microsoft-session-cookies.json")


def _classify(domain: str) -> str | None:
    for suffix, group in RELEVANT_DOMAIN_SUFFIXES.items():
        if domain == suffix.lstrip("."):
            return group
        if suffix.startswith(".") and domain.endswith(suffix):
            return group
        if domain == suffix:
            return group
    return None


def _pack(input_path: Path) -> str:
    raw = json.loads(input_path.read_text())
    subset = {"microsoft_session": raw["cookies"].get("microsoft_session", {})}
    return base64.b64encode(json.dumps(subset).encode()).decode("ascii")


def _extract(out_path: Path) -> int:
    try:
        import browser_cookie3
    except ImportError:
        print("install browser_cookie3 first: "
              "pip3 install --user --break-system-packages browser_cookie3", file=sys.stderr)
        return 1

    jar = browser_cookie3.chrome(domain_name="")
    by_group: dict[str, dict[str, dict[str, dict]]] = {}
    for c in jar:
        group = _classify(c.domain)
        if not group:
            continue
        by_group.setdefault(group, {})
        by_group[group].setdefault(c.domain, {})
        by_group[group][c.domain][c.name] = {
            "value": c.value, "expires": c.expires, "secure": bool(c.secure), "path": c.path,
        }

    summary = {
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "groups": {
            g: {
                "domains": sorted(domains.keys()),
                "cookie_names": sorted({n for d in domains.values() for n in d.keys()}),
                "count": sum(len(c) for c in domains.values()),
            }
            for g, domains in sorted(by_group.items())
        },
        "cookies": by_group,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    total = sum(g["count"] for g in summary["groups"].values())
    print(f"Wrote {out_path} ({total} cookies)")
    for g, info in summary["groups"].items():
        print(f"  {g:25s} domains={info['domains']}")
        print(f"  {'':25s} names={info['cookie_names']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"extract output path (default: {DEFAULT_OUT})")
    ap.add_argument("--in", dest="input_path", type=Path, default=None,
                    help="for --pack: input JSON path (default: --out value)")
    ap.add_argument("--pack", action="store_true",
                    help="emit base64(JSON) of microsoft_session subset to stdout (no extract)")
    args = ap.parse_args()

    if args.pack:
        src = args.input_path or args.out
        if not src.exists():
            print(f"FATAL: {src} not found; run without --pack first", file=sys.stderr)
            return 1
        print(_pack(src))
        return 0

    return _extract(args.out)


if __name__ == "__main__":
    sys.exit(main())
