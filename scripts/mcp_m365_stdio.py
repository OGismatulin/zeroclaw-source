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
import urllib.parse
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
CHAT_READ_PAGE_SIZE = 25
CHAT_READ_MAX_PAGES = 10
CHAT_READ_SEARCH_START_SECS = 15
BAD_DATE = (
    "afterDateTime and beforeDateTime must be ISO 8601 date-times with a zone, for "
    "example 2026-10-26T00:00:00+06:00; a date without a time or a zone is refused."
)
BAD_WINDOW = "afterDateTime must be earlier than beforeDateTime."
EMPTY_SEARCH = (
    "0 results from the Teams search index for these parameters. This does not prove "
    "that such a message does not exist. For a known chat or DM call "
    "m365__teams_read_chat; for a word also try the other form (bare or \"quoted\")."
)
LOCAL_NOTES: dict[str, str] = {
    "read_resource": (
        "ZeroClaw: to read a chat or DM for a period call m365__teams_read_chat instead "
        "of composing a URI. teams:///chats/{chatId}/messages returns at most 50 "
        "messages ordered by last update; a final item with truncated: true means "
        "older and some recent messages are missing. A channel reply has no URI of its "
        "own: .../messages/{replyId} fails with NOT_FOUND and "
        ".../messages/{parentId}/replies/{replyId} silently returns the parent. Read "
        "replies with m365__teams_list_channel_messages and parentMessageId."
    ),
    "chat_message_search": (
        "ZeroClaw: results are candidates from a search index, not a complete list. "
        "Zero results or a missing message never proves that a message does not "
        "exist: say what you searched and that it was not found. For a known chat or "
        "DM call m365__teams_read_chat first. For a word run both the bare and the "
        "\"quoted\" form and merge by id: neither is a superset of the other. Pages "
        "can repeat items: deduplicate by chatId (or channelUri) and id. A result with "
        "isError is an access or tool error, not an empty result."
    ),
    "teams_list_channel_messages": (
        "ZeroClaw: keep each reply's replyToId together with its id. bodyTruncated: "
        "true means only the preview is available through this connector: say so "
        "instead of presenting the preview as the full text."
    ),
    "teams_list_chats": (
        "ZeroClaw: members carry displayName and email: use them to match a person "
        "and an address, people search is not available (People.Read is not granted). "
        "Read a chat's messages with m365__teams_read_chat. Favourite or pinned chats "
        "cannot be read: there is no tool and no TeamworkSection.Read. Before drafting "
        "a reply for the user read skills/m365/SKILL.md, section «Ответ собеседнику»."
    ),
}
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
_DATE_SCHEMA = {
    "type": "string",
    "description": (
        "ISO 8601 date-time with a zone, for example 2026-10-26T00:00:00+06:00 for "
        "the user's local midnight."
    ),
}
CHAT_READ_TOOL: dict[str, Any] = {
    "name": "teams_read_chat",
    "description": (
        "Read the messages of one Teams chat (1:1, group or meeting) for a period, with "
        "a coverage status computed by code. Use it whenever the user asks what was "
        "written in a known chat or DM or asks for all messages of a period. It reads "
        "the chat directly and, when the chat is longer than one page, adds "
        "chat_message_search hits for the period that belong to this chat. status "
        "complete: every message of the chat in the period is listed. status partial: "
        "the chat is longer than one page and the search index can miss messages: tell "
        "the user which period was read and that the list may be incomplete, never "
        "that a message does not exist. chatId comes from m365__teams_list_chats or "
        "the chatId of a search result. Texts are previews: read a full message with "
        "m365__read_resource on its uri."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "chatId": {"type": "string", "minLength": 1, "maxLength": 512},
            "afterDateTime": {**_DATE_SCHEMA, "description": _DATE_SCHEMA["description"]
                              + " Messages sent at or after it. Needed to search a long "
                              "chat beyond its first page."},
            "beforeDateTime": {**_DATE_SCHEMA, "description": _DATE_SCHEMA["description"]
                               + " Messages sent before it."},
        },
        "required": ["chatId"],
        "additionalProperties": False,
    },
}
LOCAL_TOOLS: list[dict[str, Any]] = LOGIN_TOOLS + [CHAT_READ_TOOL]


def load_snapshot(path: Path | None = None) -> list[dict[str, Any]]:
    data = json.loads((path or SNAPSHOT_PATH).read_text(encoding="utf-8"))
    tools = []
    for tool in data["tools"]:
        if tool.get("name") not in tok.READ_ALLOWLIST:
            continue
        note = LOCAL_NOTES.get(tool["name"])
        if note:
            tool = {**tool, "description": f"{tool.get('description', '')}\n\n{note}"}
        tools.append(tool)
    return tools


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


def _call_upstream(key: str, name: str, args: Mapping[str, Any],
                   rid: object) -> dict[str, Any]:
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
    result: dict[str, Any] = message["result"]
    return result


def _forward(key: str, name: str, args: Mapping[str, Any], rid: object) -> dict[str, Any]:
    result = _call_upstream(key, name, args, rid)
    if name == "chat_message_search" and not result.get("isError") \
            and not result.get("content"):
        return _text(EMPTY_SEARCH)
    return _cap(result)


def _items(result: object) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(result, dict):
        return [], 1
    items: list[dict[str, Any]] = []
    unreadable = 0
    for part in result.get("content") or []:
        text = part.get("text") if isinstance(part, dict) else None
        try:
            item = json.loads(text) if isinstance(text, str) else None
        except ValueError:
            item = None
        if isinstance(item, dict):
            items.append(item)
        else:
            unreadable += 1
    return items, unreadable


def _moment(value: object) -> datetime.datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("not a string")
    moment = datetime.datetime.fromisoformat(value)
    if moment.tzinfo is None:
        raise ValueError("date-time without a zone")
    return moment.astimezone(datetime.UTC)


def _sent(item: Mapping[str, Any]) -> datetime.datetime | None:
    try:
        return _moment(item.get("createdDateTime"))
    except (ValueError, OverflowError):
        return None


def _iso(moment: datetime.datetime, *, up: bool = False) -> str:
    if up and moment.microsecond:
        moment = moment.replace(microsecond=0) + datetime.timedelta(seconds=1)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _message(item: Mapping[str, Any], source: str) -> dict[str, Any]:
    sender = item.get("from")
    email = None
    if isinstance(sender, dict):
        email = sender.get("email")
        sender = sender.get("displayName")
    out = {"id": str(item["id"]), "createdDateTime": item["createdDateTime"],
           "from": sender, "text": item.get("bodyPreview") or item.get("summary") or "",
           "uri": item.get("uri"), "source": source}
    if email:
        out["email"] = email
    return out


Found = dict[str, tuple[datetime.datetime, dict[str, Any]]]


def _search_chat(key: str, chat_id: str, after: datetime.datetime,
                 before: datetime.datetime | None, rid: object, started: float,
                 found: Found) -> dict[str, Any]:
    args: dict[str, Any] = {"query": "*", "afterDateTime": _iso(after),
                            "limit": CHAT_READ_PAGE_SIZE}
    if before is not None:
        args["beforeDateTime"] = _iso(before, up=True)
    report: dict[str, Any] = {"pages": 0, "exhausted": False, "hits_in_chat": 0,
                              "duplicates": 0, "unparsed_items": 0, "stopped": None,
                              "error": None}
    offset = 0
    while True:
        if report["pages"] >= CHAT_READ_MAX_PAGES:
            report["stopped"] = "search_stopped_page_limit"
            return report
        if time.monotonic() - started >= CHAT_READ_SEARCH_START_SECS:
            report["stopped"] = "search_stopped_time_budget"
            return report
        result = _call_upstream(key, "chat_message_search", {**args, "offset": offset}, rid)
        report["pages"] += 1
        if not isinstance(result, dict) or result.get("isError"):
            parts = result.get("content") if isinstance(result, dict) else None
            report["stopped"] = "search_error"
            report["error"] = " ".join(
                p.get("text", "") for p in parts or [] if isinstance(p, dict))[:300]
            return report
        more, next_offset = False, None
        for item in _items(result)[0]:
            if "moreResults" in item:
                more = item.get("moreResults") is True
                next_offset = item.get("nextOffset")
                continue
            if item.get("chatId") != chat_id or "id" not in item:
                continue
            report["hits_in_chat"] += 1
            sent = _sent(item)
            if sent is None:
                report["unparsed_items"] += 1
                continue
            if str(item["id"]) in found:
                report["duplicates"] += 1
                continue
            found[str(item["id"])] = (sent, _message(item, "search"))
        if not more:
            report["exhausted"] = True
            return report
        if type(next_offset) is not int or next_offset <= offset:
            report["stopped"] = "search_bad_offset"
            return report
        offset = next_offset


def _read_chat(key: str, args: object, rid: object) -> dict[str, Any]:
    started = time.monotonic()
    if not isinstance(args, Mapping):
        return _text("arguments must be an object with chatId.", True)
    chat_id = args.get("chatId")
    if not isinstance(chat_id, str) or not chat_id:
        return _text("chatId is required: take it from m365__teams_list_chats or from "
                     "the chatId of a search result.", True)
    try:
        after = _moment(args.get("afterDateTime"))
        before = _moment(args.get("beforeDateTime"))
    except (ValueError, OverflowError):
        return _text(BAD_DATE, True)
    if after is not None and before is not None and after >= before:
        return _text(BAD_WINDOW, True)
    uri = "teams:///chats/" + urllib.parse.quote(chat_id, safe="") + "/messages"
    page = _call_upstream(key, "read_resource", {"uri": uri}, rid)
    if isinstance(page, dict) and page.get("isError"):
        return page
    items, unreadable = _items(page)
    found: Found = {}
    truncated = False
    system = unparsed = 0
    for item in items:
        if "id" not in item and "createdDateTime" not in item:
            truncated = truncated or item.get("truncated") not in (None, False)
            continue
        if item.get("messageType") not in (None, "message"):
            system += 1
            continue
        sent = _sent(item)
        if sent is None or "id" not in item:
            unparsed += 1
            continue
        found[str(item["id"])] = (sent, _message(item, "chat"))
    page_order = sorted(found.values(), key=lambda pair: pair[0])
    reasons: list[str] = []
    search = None
    if truncated:
        reasons.append("chat_has_more_than_one_page")
        if after is None:
            reasons.append("no_afterDateTime")
        else:
            search = _search_chat(key, chat_id, after, before, rid, started, found)
            if search["stopped"]:
                reasons.append(search["stopped"])
            unparsed += search["unparsed_items"]
    if not items or unreadable:
        reasons.append("chat_page_unreadable")
    if unparsed:
        reasons.append("unparsed_items")
    messages = [m for sent, m in sorted(found.values(), key=lambda pair: pair[0])
                if (after is None or sent >= after) and (before is None or sent < before)]
    status = "partial" if reasons else "complete"
    note = (
        "The whole chat fits in one page: every message of the period is listed."
        if status == "complete" else
        "The list may be incomplete (see reasons): tell the user which period was read "
        "and that some messages may be missing, never that a message does not exist."
    )
    return _text(json.dumps({
        "chatId": chat_id,
        "after": _iso(after) if after else None,
        "before": _iso(before, up=True) if before else None,
        "status": status,
        "reasons": reasons,
        "chat_page": {"messages": len(page_order), "truncated": truncated,
                      "oldest": page_order[0][1]["createdDateTime"] if page_order else None,
                      "newest": page_order[-1][1]["createdDateTime"] if page_order else None},
        "search": search,
        "system_messages_skipped": system,
        "unparsed_items": unparsed,
        "messages": messages,
        "note": note,
    }, ensure_ascii=False))


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
        elif name == "teams_read_chat":
            result = _cap(_read_chat(key, args, rid))
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
    tools = LOCAL_TOOLS + load_snapshot()
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
