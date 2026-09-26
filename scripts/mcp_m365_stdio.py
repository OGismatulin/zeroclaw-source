#!/usr/bin/env python3
"""stdio MCP shim that serves the claude.ai Microsoft 365 connector to one daemon.

Spawned by the ZeroClaw daemon — per webhook turn and as long-lived children of
the daemon's shared registries (heartbeat, agents). initialize and tools/list are answered locally from a baked snapshot
so the connect budget never depends on the network; read-only tools/call is
forwarded upstream with the calling user's own token. The user is derived from
the inherited ZEROCLAW_WORKSPACE, never from call arguments.
Spec: docs/superpowers/specs/2026-09-25-m365-teams-read-mcp-design.md
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping, TextIO

try:
    import m365_tokens as tok
except ModuleNotFoundError:  # repo layout: imported as scripts.mcp_m365_stdio
    from scripts import m365_tokens as tok

SNAPSHOT_PATH = tok.SNAPSHOT_PATH
# The fork client reads replies up to 4 MB per line; stay well below it.
MAX_REPLY_BYTES = 1_000_000
CALL_WORKERS = 4
NOT_CONNECTED = (
    "Microsoft 365 is not connected for this user. Call m365__login_start and "
    "forward the link and code to the user verbatim."
)
UNAVAILABLE = (
    "Microsoft 365 is temporarily unavailable ({detail}). This is the connector "
    "server, not the user's account. Retry at most once."
)
LOGIN_TOOLS: list[dict[str, Any]] = [
    {
        "name": "login_start",
        "description": (
            "Connect this user's Microsoft 365 account (Teams, Outlook, SharePoint). "
            "Returns a link and a one-time code to forward to the user verbatim."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"force": {"type": "boolean",
                                     "description": "Start a new login even if connected."}},
            "additionalProperties": False,
        },
    },
    {
        "name": "login_status",
        "description": (
            "Check the Microsoft 365 connection; call after the user says they signed in."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def load_snapshot(path: Path | None = None) -> list[dict[str, Any]]:
    data = json.loads((path or SNAPSHOT_PATH).read_text(encoding="utf-8"))
    return [t for t in data["tools"] if t.get("name") in tok.READ_ALLOWLIST]


def _log(cls: str, key: str, status: object) -> None:
    print(f"m365: {cls} user={key} status={status}", file=sys.stderr, flush=True)


def _text(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _login_start(key: str, args: Mapping[str, Any]) -> dict[str, Any]:
    if tok.status(key)["state"] == "ok" and not args.get("force"):
        return _text("Microsoft 365 is already connected for this user.")
    try:
        started = tok.start_device_login(key)
    except tok.TransientError as exc:
        _log("m365_login_unavailable", key, exc)
        return _text("Could not start Microsoft login right now; try again later.", True)
    minutes = max(1, started["expires_in"] // 60)
    return _text(
        f"Forward to the user verbatim: open {started['verification_uri']} and enter "
        f"the code {started['user_code']}. The code is valid for {minutes} minutes. "
        "After signing in, the user should tell you, and you call m365__login_status."
    )


def _login_status(key: str) -> dict[str, Any]:
    try:
        if tok.status(key).get("device"):
            tok.poll_device_login(key)
    except tok.TransientError as exc:
        _log("m365_login_unavailable", key, exc)
        return _text("Could not check the Microsoft login right now; try again.", True)
    current = tok.status(key)
    state = current["state"]
    if state == "ok":
        who = ""
        try:
            code, message = tok.upstream_rpc(tok.access_token(key), "tools/call",
                                             {"name": "get_me", "arguments": {}})
            if code == 200 and message and "result" in message:
                who = " " + message["result"]["content"][0]["text"][:300]
        except (tok.NeedsLogin, tok.TransientError, KeyError, IndexError, TypeError):
            pass
        return _text("Microsoft 365 is connected." + who)
    if state == "pending" and current.get("device"):
        device = current["device"]
        return _text(
            "The user has not finished signing in yet: open "
            f"{device['verification_uri']} and enter the code {device['user_code']}."
        )
    if state == "expired":
        return _text("The login code expired. Call m365__login_start for a new one.", True)
    if state == "needs_login":
        return _text(f"Access was revoked or expired ({current.get('error')}). "
                     "Call m365__login_start.", True)
    return _text(NOT_CONNECTED, True)


def _forward(key: str, name: str, args: Mapping[str, Any], rid: object) -> dict[str, Any]:
    params = {"name": name, "arguments": dict(args)}
    try:
        code, message = tok.upstream_rpc(tok.access_token(key), "tools/call", params, rid)
        if code == 401:
            code, message = tok.upstream_rpc(
                tok.access_token(key, force_refresh=True), "tools/call", params, rid)
    except tok.NeedsLogin as exc:
        return _text(f"{NOT_CONNECTED} Reason: {exc}", True)
    except tok.TransientError as exc:
        _log("m365_upstream_unavailable", key, exc)
        return _text(UNAVAILABLE.format(detail=str(exc)), True)
    if code != 200 or message is None:
        _log("m365_upstream_unavailable", key, code)
        return _text(UNAVAILABLE.format(detail=f"HTTP {code}"), True)
    if "error" in message:
        return _text(f"Microsoft 365 error: {message['error'].get('message', '')}"[:2000], True)
    return _cap(message["result"])


def _cap(result: dict[str, Any]) -> dict[str, Any]:
    """Truncate content texts so the serialised reply stays under MAX_REPLY_BYTES."""
    budget = MAX_REPLY_BYTES - 1000  # JSON-RPC envelope headroom
    excess = len(json.dumps(result, ensure_ascii=False).encode()) - budget
    for item in result.get("content", []):
        text = item.get("text") if isinstance(item, dict) else None
        if excess <= 0 or not isinstance(text, str):
            continue
        raw = text.encode()
        # Cut by the text's serialised size so JSON escaping cannot overshoot.
        ratio = len(json.dumps(text, ensure_ascii=False).encode()) / max(len(raw), 1)
        keep = max(0, len(raw) - int((excess + 200) / ratio) - 1)
        kept = raw[:keep].decode("utf-8", "ignore")
        omitted = len(raw) - len(kept.encode())
        item["text"] = kept + f"\n[truncated by m365 shim: {omitted} bytes omitted]"
        excess = len(json.dumps(result, ensure_ascii=False).encode()) - budget
    if excess > 0:
        return _text("Microsoft 365 result was too large to return; narrow the query.", True)
    return result


def handle(message: dict[str, Any], *, key: str | None,
           tools: list[dict[str, Any]]) -> dict[str, Any] | None:
    if "id" not in message:
        return None  # notification
    rid = message["id"]
    method = message.get("method")
    params = message.get("params") or {}
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "m365", "version": "1"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": tools}
    elif method == "tools/call" and params.get("name") in {t["name"] for t in tools}:
        name = params["name"]
        args = params.get("arguments") or {}
        if key is None:
            result = _text("m365 works only inside a per-user ZeroClaw daemon.", True)
        elif name == "login_start":
            result = _login_start(key, args)
        elif name == "login_status":
            result = _login_status(key)
        else:
            result = _forward(key, name, args, rid)
    else:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"not supported: {method}"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _safe_handle(message: Any, *, key: str | None,
                 tools: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(message, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request"}}
    try:
        return handle(message, key=key, tools=tools)
    except Exception as exc:  # a long-lived shim must survive one bad message
        _log("m365_internal", key or "-", type(exc).__name__)  # never the text: may echo data
        if "id" not in message:
            return None
        return {"jsonrpc": "2.0", "id": message["id"],
                "error": {"code": -32603, "message": "internal error"}}


def serve(stdin: TextIO, stdout: TextIO, env: Mapping[str, str]) -> int:
    try:
        key: str | None = tok.user_key_from_env(env)
    except ValueError:
        key = None
    tools = LOGIN_TOOLS + load_snapshot()
    write_lock = threading.Lock()

    def reply(message: Any) -> None:
        out = _safe_handle(message, key=key, tools=tools)
        if out is not None:
            with write_lock:
                stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
                stdout.flush()

    # The client runs tool calls in parallel and times each one from send time, so
    # calls run concurrently; control messages stay inline and in order.
    with concurrent.futures.ThreadPoolExecutor(max_workers=CALL_WORKERS) as pool:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                with write_lock:
                    stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {
                        "code": -32700, "message": "parse error"}}) + "\n")
                    stdout.flush()
                continue
            if isinstance(message, dict) and message.get("method") == "tools/call" \
                    and "id" in message:
                pool.submit(reply, message)
            else:
                reply(message)
    return 0  # the with-block waited for in-flight calls


def _cli_login(key: str) -> int:
    # No stdin: polls until the device code is used or expires (15 min), so the
    # step runs unattended while the human signs in.
    started = tok.start_device_login(key)
    print(f"Open {started['verification_uri']} and enter {started['user_code']}", flush=True)
    outcome = "pending"
    while outcome == "pending":
        time.sleep(5)
        try:
            outcome = tok.poll_device_login(key)
        except tok.TransientError:
            continue
    print(f"login: {outcome}")
    return 0 if outcome == "ok" else 1


def _cli_capture(key: str) -> int:
    code, message = tok.upstream_rpc(tok.access_token(key), "tools/list", {})
    if code != 200 or not message or "result" not in message:
        print(f"capture failed: HTTP {code}", file=sys.stderr)
        return 1
    tools = [t for t in message["result"]["tools"] if t.get("name") in tok.READ_ALLOWLIST]
    missing = sorted(set(tok.READ_ALLOWLIST) - {t["name"] for t in tools})
    if missing:
        print(f"capture failed: upstream lacks {missing}", file=sys.stderr)
        return 1
    tools.sort(key=lambda t: tok.READ_ALLOWLIST.index(t["name"]))
    SNAPSHOT_PATH.write_text(json.dumps({
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "source": tok.mcp_url(),
        "tools": tools,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(tools)} tools to {SNAPSHOT_PATH}")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        return serve(sys.stdin, sys.stdout, os.environ)
    parser = argparse.ArgumentParser(prog="mcp_m365_stdio.py")
    parser.add_argument("command", choices=["login", "capture-snapshot"])
    parser.add_argument("--user-key", required=True)
    args = parser.parse_args(argv)
    if args.command == "login":
        return _cli_login(args.user_key)
    return _cli_capture(args.user_key)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
