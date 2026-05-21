"""Warm up all per-user daemons on Fly without invoking the agent.

Hits the manager's `POST /warmup` endpoint on localhost so daemons spawn and
the scheduler discharges any overdue cron jobs (e.g. nightly retro) before a
user sends their first webhook. Without warmup the scheduler's catch-up runs
in parallel with the user's webhook turn — see
`docs/analysis/2026-05-21-deploy-cron-race-fix.md`.

Usage (from CI or local):

    cat scripts/fly_warmup.py | fly ssh console -a ai-forge-zeroclaw -C 'python3 -'

The script reads the bearer token from `/zeroclaw-data/manager/bearer_tokens.json`
and the webhook secret from `ZEROCLAW_WEBHOOK_SECRET`, both already present
inside the running container.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib import error, request


def main() -> int:
    tokens_path = Path("/zeroclaw-data/manager/bearer_tokens.json")
    if not tokens_path.exists():
        print("ERROR: bearer_tokens.json not found", flush=True)
        return 1
    tokens = json.loads(tokens_path.read_text(encoding="utf-8"))
    if not tokens:
        print("ERROR: no bearer tokens available", flush=True)
        return 1
    token = tokens[0]
    secret = os.environ.get("ZEROCLAW_WEBHOOK_SECRET", "")

    body = b"{}"  # Default exclude list (currently tg_99999) is applied server-side.
    req = request.Request(
        url="http://127.0.0.1:3000/warmup",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Webhook-Secret": secret,
        },
    )

    try:
        with request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode())
    except error.HTTPError as exc:
        body_text = exc.read().decode()
        print(f"HTTP {exc.code}: {body_text}", flush=True)
        return 1
    except (error.URLError, TimeoutError, OSError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1

    warmed = data.get("warmed", [])
    failed = data.get("failed", {})
    skipped = data.get("skipped", [])
    elapsed_ms = data.get("elapsed_ms", 0)

    print(
        f"Warmup complete in {elapsed_ms} ms: "
        f"warmed={len(warmed)} failed={len(failed)} skipped={len(skipped)}",
        flush=True,
    )
    if warmed:
        print(f"  Warmed: {', '.join(warmed)}", flush=True)
    if skipped:
        print(f"  Skipped: {', '.join(skipped)}", flush=True)
    if failed:
        for user_key, reason in failed.items():
            print(f"  FAILED {user_key}: {reason}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
