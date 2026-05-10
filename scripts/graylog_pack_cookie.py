"""Pack multiple oauth2-proxy cookies into base64 JSON for GRAYLOG_SESSION_COOKIE.

Usage (DevTools workflow):
    python3 scripts/graylog_pack_cookie.py \\
        --cookie '_oauth2_proxy=MTczMzg5...' \\
        --cookie '_oauth2_proxy_0=...' \\
        --cookie '_oauth2_proxy_csrf=...'

Usage (Cookie-Editor extension JSON export):
    python3 scripts/graylog_pack_cookie.py --json-file ~/Downloads/cookies.json

Outputs base64-encoded JSON to stdout. Filters only cookies with _oauth2_proxy prefix
to avoid leaking PII tracking cookies (PostHog, etc.).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path


def parse_cookie_arg(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise ValueError(f"Invalid cookie format (expected name=value): {raw!r}")
    name, _, value = raw.partition("=")
    name = name.strip()
    if not name:
        raise ValueError(f"Empty cookie name in: {raw!r}")
    return name, value


def parse_json_export(path: Path) -> dict[str, str]:
    """Parse Cookie-Editor extension JSON export (list of {name, value, ...} dicts)."""
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError(
            f"Expected JSON array (Cookie-Editor 'Export → JSON' format), got {type(raw).__name__}"
        )
    out: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and isinstance(value, str):
            out[name] = value
    if not out:
        raise ValueError(f"No usable cookies found in {path}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cookie", action="append", default=[], dest="cookies",
        help="Cookie in name=value format (repeatable). Only _oauth2_proxy* are kept.",
    )
    parser.add_argument(
        "--json-file", default=None, dest="json_file",
        help="Path to Cookie-Editor extension JSON export (alternative to --cookie).",
    )
    args = parser.parse_args()

    if not args.cookies and not args.json_file:
        print("error: pass --cookie name=value (repeatable) or --json-file PATH", file=sys.stderr)
        return 2

    parsed: dict[str, str] = {}
    if args.json_file:
        try:
            parsed.update(parse_json_export(Path(args.json_file)))
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    try:
        for c in args.cookies:
            name, value = parse_cookie_arg(c)
            parsed[name] = value
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Filter to oauth2-proxy* only (защита от PII tracking cookies)
    filtered = {k: v for k, v in parsed.items() if k.startswith("_oauth2_proxy")}

    if "_oauth2_proxy" not in filtered:
        print(
            "error: missing required _oauth2_proxy cookie. "
            "Make sure you copied the main session cookie, not just _0/_1/_csrf shards.",
            file=sys.stderr,
        )
        return 2

    encoded = base64.b64encode(json.dumps(filtered).encode("utf-8")).decode("ascii")
    print(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
