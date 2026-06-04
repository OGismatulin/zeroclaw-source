#!/bin/sh
# agent-browser wrapper (installed as /usr/local/bin/agent-browser).
#
# Purpose: the ZeroClaw runtime agent invokes `agent-browser ...` via the shell
# tool. This wrapper sits in front of the real native binary
# (/usr/local/bin/agent-browser-bin) to enforce three project invariants:
#
#   1. Per-user single-browser guarantee. The agent-browser daemon is keyed by
#      `--session` name + $HOME (NOT by --profile). $HOME=/zeroclaw-data is shared
#      across every per-user daemon, so isolation relies on a per-user
#      AGENT_BROWSER_SESSION (injected by the gateway manager) plus a per-user
#      AGENT_BROWSER_PROFILE. Before each `open` we gracefully close any existing
#      daemon for this session so at most one browser runs per user AND so that
#      spawn-time flags (--engine/--profile/--executable-path) actually take effect
#      (they are silently IGNORED while a daemon for the session is already alive).
#
#   2. Best-effort audit of write/eval verbs into state/agent-browser/audit.log.
#
#   3. Transparent pass-through of everything else to the real binary.
#
# Known minor gaps (acceptable, documented):
#   - `--headed false`-style optional-value booleans may mis-parse during the
#     subcommand scan (we treat --headed as a value-less boolean).
#   - `eval --stdin` / `eval -b <body>` script bodies are not present in argv,
#     so the audit line records the invocation but not the executed JS.

set -eu

REAL_BIN=/usr/local/bin/agent-browser-bin

session="${AGENT_BROWSER_SESSION:-}"
profile="${AGENT_BROWSER_PROFILE:-}"

# Audit directory: alongside the per-user profile (state/agent-browser/), else
# fall back to the workspace state dir.
if [ -n "$profile" ]; then
    audit_dir=$(dirname "$profile")
else
    audit_dir="${ZEROCLAW_WORKSPACE:-$PWD}/state/agent-browser"
fi

# Global flags that consume the NEXT token as their value. They precede the
# subcommand. Anything else (booleans, --x=y inline, short flags, the subcommand
# itself) does not consume a following token.
is_value_global() {
    case "$1" in
        --engine|--profile|--session|--session-name|--executable-path|\
        --provider|-p|--device|--model|--proxy|--user-agent|--color-scheme|\
        --download-path|--screenshot-dir|--screenshot-quality|--screenshot-format|\
        --max-output|--allowed-domains|--action-policy|--confirm-actions|--args|\
        --headers|--state|--config|--cdp|--extension|--init-script|--enable)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# Scan argv to find the first bare token (the subcommand), skipping leading
# global flags. A value-taking global flag consumes the following token.
subcommand=""
skip_next=0
for tok in "$@"; do
    if [ "$skip_next" -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$tok" in
        --*=*)
            # inline value form, e.g. --engine=chrome — no following token
            continue ;;
        -*)
            if is_value_global "$tok"; then
                skip_next=1
            fi
            continue ;;
        *)
            subcommand="$tok"
            break ;;
    esac
done

# Pre-open kill: gracefully close any existing daemon for this session BEFORE
# launching, so a per-call --engine/--profile actually applies and at most one
# browser exists per user. Uses the real binary (profile is NOT in the daemon's
# argv, so pkill-by-profile would not work).
if [ "$subcommand" = "open" ] && [ -n "$session" ]; then
    "$REAL_BIN" --session "$session" close >/dev/null 2>&1 || true
fi

# Audit write/eval verbs (best-effort; never fail the command).
case "$subcommand" in
    eval|fill|type|click|dblclick|press|check|uncheck|select|upload|drag|\
    keyboard|keydown|keyup|find)
        mkdir -p "$audit_dir" 2>/dev/null || true
        ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
        printf '%s\t%s\t%s\n' "$ts" "${session:-default}" "$*" \
            >> "$audit_dir/audit.log" 2>/dev/null || true
        ;;
esac

exec "$REAL_BIN" "$@"
