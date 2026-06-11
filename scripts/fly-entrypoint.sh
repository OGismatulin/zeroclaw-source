#!/bin/sh
set -eu

legacy_config_dir="/zeroclaw-data/.zeroclaw"
legacy_workspace_dir="/zeroclaw-data/workspace"
config_dir="/zeroclaw-data/template/.zeroclaw"
config_file="$config_dir/config.toml"
workspace_dir="/zeroclaw-data/template/workspace"
shared_auth_dir="/zeroclaw-data/shared-auth"
manager_dir="/zeroclaw-data/manager"
workspaces_dir="/zeroclaw-data/workspaces"
template_file="/seed/config.fly.toml.template"
baseline_allowed_commands="git npm cargo sh ls cat grep find echo pwd wc head tail date wget python3 pip pip3 node npx ffmpeg convert pandoc curl jq agent-browser gh glab"
baseline_auto_approve="file_read file_write memory_recall shell http_request"
openvpn_log_path="${OPENVPN_LOG_PATH:-/tmp/openvpn.log}"

mkdir -p "$config_dir" "$workspace_dir" "$shared_auth_dir" "$manager_dir" "$workspaces_dir"

vpn_route_ok() {
  ip link show tun0 >/dev/null 2>&1 || return 1
  ip route get 46.4.211.98 2>/dev/null | grep -q ' dev tun0 ' || return 1
  ip route get 195.201.82.13 2>/dev/null | grep -q ' dev tun0 ' || return 1
}

start_openvpn_watchdog() {
  (
    set +e
    failures=0
    restarts=0
    restarts_window_start=$(date +%s)
    restarts_limit=${VPN_WATCHDOG_MAX_RESTARTS:-5}
    restarts_window_secs=${VPN_WATCHDOG_RESTARTS_WINDOW_SECS:-3600}
    cooldown_secs=${VPN_WATCHDOG_COOLDOWN_SECS:-900}
    while true; do
      if vpn_route_ok; then
        failures=0
      else
        failures=$((failures + 1))
        echo "[vpn-watchdog] tun0/routes unhealthy (failures=$failures)" >&2
        if [ "$failures" -ge 3 ]; then
          now=$(date +%s)
          if [ "$((now - restarts_window_start))" -ge "$restarts_window_secs" ]; then
            restarts=0
            restarts_window_start=$now
          fi
          if [ "$restarts" -ge "$restarts_limit" ]; then
            echo "[vpn-watchdog] CRITICAL: ${restarts_limit} restarts in last ${restarts_window_secs}s; backing off ${cooldown_secs}s before next attempt" >&2
            sleep "$cooldown_secs"
            restarts=0
            restarts_window_start=$(date +%s)
            failures=0
            continue
          fi
          restarts=$((restarts + 1))
          echo "[vpn-watchdog] restarting openvpn (restart $restarts/$restarts_limit in window)" >&2
          pkill -x openvpn || true
          sleep 1
          openvpn --config /zeroclaw-data/vpn/client.ovpn --daemon --log "$openvpn_log_path" || echo "[vpn-watchdog] ERROR: openvpn restart command failed" >&2
          failures=0
        fi
      fi
      sleep "${VPN_WATCHDOG_INTERVAL_SECS:-5}"
    done
  ) &
  VPN_WATCHDOG_PID=$!
  echo "[fly-entrypoint] OpenVPN watchdog started (pid=$VPN_WATCHDOG_PID)"
}

copy_sanitized_workspace_template() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import os
import shutil
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

if not src.exists():
    raise SystemExit(0)

dst.mkdir(parents=True, exist_ok=True)
excluded_dirs = {"memory", "state", "logs", "cron"}
excluded_suffixes = (".db", ".db-shm", ".db-wal")

for path in src.rglob("*"):
    rel = path.relative_to(src)
    if any(part in excluded_dirs for part in rel.parts):
        continue
    if path.is_file() and path.name.endswith(excluded_suffixes):
        continue

    target = dst / rel
    if path.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        continue

    target.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(os.readlink(path))
        continue

    shutil.copy2(path, target)
PY
}

if [ -d "$legacy_workspace_dir" ] && [ -z "$(find "$workspace_dir" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1)" ]; then
  copy_sanitized_workspace_template "$legacy_workspace_dir" "$workspace_dir"
fi

for auth_file in auth-profiles.json .secret_key; do
  if [ -f "$legacy_config_dir/$auth_file" ] && [ ! -f "$shared_auth_dir/$auth_file" ]; then
    cp "$legacy_config_dir/$auth_file" "$shared_auth_dir/$auth_file"
  fi
done

needs_regen=0

if [ -f "$config_file" ]; then
  if ! awk '
    BEGIN {
      in_webhook = 0
      in_channels = 0
      in_agent = 0
      has_webhook_port = 0
      has_cli = 0
      dispatcher_ok = 0
    }
    /^\[channels_config\]/ { in_channels = 1; in_webhook = 0; in_agent = 0; next }
    /^\[channels_config\.webhook\]/ { in_webhook = 1; in_agent = 0; next }
    /^\[agent\]/ { in_agent = 1; in_channels = 0; in_webhook = 0; next }
    /^\[/ { in_channels = 0; in_webhook = 0; in_agent = 0 }
    in_channels && $1 == "cli" && $3 == "true" { has_cli = 1 }
    in_webhook && $1 == "port" { has_webhook_port = 1 }
    in_agent && $1 == "tool_dispatcher" && $3 == "\"native\"" { dispatcher_ok = 1 }
    END { exit (has_cli && has_webhook_port && dispatcher_ok) ? 0 : 1 }
  ' "$config_file"; then
    needs_regen=1
  fi
fi

if [ ! -f "$config_file" ] || [ "$needs_regen" -eq 1 ]; then
  if [ -z "${ZEROCLAW_WEBHOOK_SECRET:-}" ]; then
    echo "ZEROCLAW_WEBHOOK_SECRET is required to initialize Fly runtime config." >&2
    exit 1
  fi

  if [ -f "$config_file" ]; then
    cp "$config_file" "$config_file.bak"
  fi

  sed -e "s|__ZEROCLAW_WEBHOOK_SECRET__|$ZEROCLAW_WEBHOOK_SECRET|g" \
      -e "s|__OPENROUTER_API_KEY__|${OPENROUTER_API_KEY:-}|g" \
      -e "s|__ZEROCLAW_BEARER_TOKEN__|${ZEROCLAW_BEARER_TOKEN:-}|g" \
      "$template_file" > "$config_file"
  chmod 0600 "$config_file"
fi

ensure_multiline_array_item() {
  array_name="$1"
  item="$2"

  if ! awk -v array_name="$array_name" -v item="$item" '
    BEGIN {
      in_array = 0
      found = 0
      seen = 0
    }
    $0 ~ "^" array_name "[[:space:]]*=[[:space:]]*\\[" {
      seen = 1
      in_array = 1
    }
    in_array && index($0, "\"" item "\"") {
      found = 1
    }
    in_array && $0 ~ /^[[:space:]]*]/ {
      exit(found ? 0 : 1)
    }
    END {
      if (!seen) {
        exit 1
      }
      exit(found ? 0 : 1)
    }
  ' "$config_file"; then
    sed -i "/^${array_name} = \\[/,/^[[:space:]]*]/ s/^[[:space:]]*]/    \\\"${item}\\\",\\
]/" "$config_file"
  fi
}

ensure_observability_runtime_trace() {
  python3 - "$config_file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines()
updates = [
    ('backend', 'backend = "none"'),
    ('runtime_trace_mode', 'runtime_trace_mode = "rolling"'),
    ('runtime_trace_path', 'runtime_trace_path = "logs/runtime-trace.jsonl"'),
    ('runtime_trace_max_entries', 'runtime_trace_max_entries = 500'),
]

section_header = "[observability]"

def find_section_bounds(data: list[str]) -> tuple[int | None, int | None]:
    start = None
    for idx, line in enumerate(data):
        if line.strip() == section_header:
            start = idx
            break
    if start is None:
        return None, None

    end = len(data)
    for idx in range(start + 1, len(data)):
        if data[idx].startswith("["):
            end = idx
            break
    return start, end

start, end = find_section_bounds(lines)
if start is None:
    if lines and lines[-1].strip():
        lines.append("")
    lines.append(section_header)
    lines.extend([value for _, value in updates])
else:
    for key, value in updates:
        replaced = False
        for idx in range(start + 1, end):
            if lines[idx].startswith(f"{key} ="):
                lines[idx] = value
                replaced = True
                break
        if not replaced:
            lines.insert(end, value)
            end += 1

path.write_text("\n".join(lines) + "\n")
PY
}

# Patch: append [autonomy] section if missing (preserves existing config)
if ! grep -q '^\[autonomy\]' "$config_file" 2>/dev/null; then
  cat >> "$config_file" <<'AUTONOMY'

[autonomy]
level = "full"
workspace_only = false
allowed_commands = [
    "git",
    "npm",
    "cargo",
    "sh",
    "ls",
    "cat",
    "grep",
    "find",
    "echo",
    "pwd",
    "wc",
    "head",
    "tail",
    "date",
    "wget",
    "python3",
    "pip",
    "pip3",
    "node",
    "npx",
    "ffmpeg",
    "convert",
    "pandoc",
    "curl",
    "jq",
]
forbidden_paths = [
    "/etc",
    "/root",
    "/home",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/opt",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/var",
    "/tmp",
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.config",
]
max_actions_per_hour = 20
max_cost_per_day_cents = 500
require_approval_for_medium_risk = false
block_high_risk_commands = false
shell_env_passthrough = ["NOTIFY_URL", "NOTIFY_SECRET", "CREATIO_BASE_URL", "CREATIO_USERNAME", "CREATIO_PASSWORD"]
auto_approve = [
    "file_read",
    "file_write",
    "memory_recall",
    "shell",
    "http_request",
]
always_ask = []
allowed_roots = ["/zeroclaw-data/code-repos"]
non_cli_excluded_tools = []
AUTONOMY
fi

ensure_observability_runtime_trace

# Patch: Ensure global fallback to opencode-go is configured (three-files sync).
# Idempotent: strips ALL existing [reliability...] sections (including the
# invented "targets" subsection from past buggy deploys) then re-appends one
# canonical block with the actual ReliabilityConfig schema:
# fallback_providers + model_fallbacks. Safe to re-run on already-clean configs.
#
# Applies to template AND every per-user config (in-place loop, no rm).
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_RELIABILITY'
import sys, re
from pathlib import Path
p = Path(sys.argv[1])
c = p.read_text(encoding="utf-8")
# Match [reliability] or [reliability.<sub>] header + content up to next
# non-reliability section header or EOF. Re.sub removes all such sections
# (collapses duplicates from past broken deploys with non-greedy regex).
section_re = re.compile(
    r'(?ms)^\[reliability(?:\.[a-zA-Z0-9_]+)?\].*?(?=^\[(?!reliability)|\Z)'
)
c = section_re.sub('', c)
canonical = """[reliability]
fallback_providers = ["opencode-go"]

[reliability.model_fallbacks]
# Phase 1 (2026-05-22)
"GLM-5.1"            = ["deepseek-v4-flash"]
"Qwen3.5-397B-A17B"  = ["deepseek-v4-flash"]
"gpt-5.5"            = ["deepseek-v4-flash"]
"gpt-5.4"            = ["deepseek-v4-flash"]
"gpt-5.4-mini"       = ["deepseek-v4-flash"]
"glm-5-turbo"        = ["deepseek-v4-flash"]
"glm-5.1"            = ["deepseek-v4-flash"]
"minimax-m2.7"       = ["deepseek-v4-flash"]
# Phase 2 (2026-05-28) — native opencode-go fallback
# Spec: docs/superpowers/specs/2026-05-28-opencode-go-native-fallback-design.md
"mimo-v2.5-pro"      = ["deepseek-v4-flash"]
"mimo-v2.5"          = ["deepseek-v4-flash"]
"mimo-v2-pro"        = ["deepseek-v4-flash"]
"mimo-v2-omni"       = ["deepseek-v4-flash"]
"glm-5"              = ["deepseek-v4-flash"]
"minimax-m2.5"       = ["deepseek-v4-flash"]
"kimi-k2.5"          = ["deepseek-v4-flash"]
"qwen3.6-plus"       = ["deepseek-v4-flash"]
# 2026-05-29 — analyst ensemble (deepseek-v4-pro has no native upstream fallback)
"deepseek-v4-pro"    = ["deepseek-v4-flash"]

"""
c = c.rstrip() + "\n\n" + canonical
p.write_text(c, encoding="utf-8")
print(f"[entrypoint] Configured reliability fallback in {p}")
PY_RELIABILITY
done

# Patch: fix api_key = "minimax-oauth" literal leak for non-minimax providers
sed -i 's/^api_key = "minimax-oauth"/api_key = ""/' "$config_file"

# NOTE: per-user config.toml regeneration via rm has been REMOVED (2026-05-22).
# Migration of [reliability] section happens in-place via the PY_RELIABILITY block
# above, which is idempotent and will apply to template + every per-user config
# after the v3 fix-forward commit. Removing per-user configs violated
# «ЗАПРЕТ: удаление пользовательских данных на Fly» (CLAUDE.md) and contributed
# to incident 2026-04-01.

# Patch: ensure shell_env_passthrough includes NOTIFY vars
if grep -q 'shell_env_passthrough = \[\]' "$config_file" 2>/dev/null; then
  sed -i 's/shell_env_passthrough = \[\]/shell_env_passthrough = ["NOTIFY_URL", "NOTIFY_SECRET"]/' "$config_file"
fi

# Patch: ensure shell_env_passthrough includes CREATIO and PG_PROD env vars
for cvar in CREATIO_BASE_URL CREATIO_USERNAME CREATIO_PASSWORD PG_PROD_HOST PG_PROD_PORT PG_PROD_USER PG_PROD_PASSWORD PG_STAGE_HOST PG_STAGE_PORT PG_STAGE_USER PG_STAGE_PASSWORD; do
  if ! grep -q "\"$cvar\"" "$config_file" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "$cvar"
  fi
done

# Patch: ensure shell_env_passthrough includes NOTIFY_FILE_URL
if ! grep -q '"NOTIFY_FILE_URL"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "NOTIFY_FILE_URL"
fi

# Propagate NOTIFY_FILE_URL to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"NOTIFY_FILE_URL"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "NOTIFY_FILE_URL"
  fi
done

# Bump main-agent max_tool_iterations 50 -> 100 (browser automation is
# iteration-heavy; the old default cut off multi-step browse turns). Idempotent:
# only the old default value is rewritten. Template AND every per-user config.
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  sed -i 's/^max_tool_iterations = 50$/max_tool_iterations = 100/' "$cfg"
done

# Patch: ensure shell_env_passthrough includes OPENROUTER_API_KEY
if ! grep -q '"OPENROUTER_API_KEY"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "OPENROUTER_API_KEY"
fi

# Propagate OPENROUTER_API_KEY to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"OPENROUTER_API_KEY"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "OPENROUTER_API_KEY"
  fi
done

# Patch: ensure shell_env_passthrough includes GITLAB_DEPLOY_USER
if ! grep -q '"GITLAB_DEPLOY_USER"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "GITLAB_DEPLOY_USER"
fi

# Propagate GITLAB_DEPLOY_USER to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"GITLAB_DEPLOY_USER"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "GITLAB_DEPLOY_USER"
  fi
done

# Patch: ensure shell_env_passthrough includes GITLAB_DEPLOY_TOKEN
if ! grep -q '"GITLAB_DEPLOY_TOKEN"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "GITLAB_DEPLOY_TOKEN"
fi

# Propagate GITLAB_DEPLOY_TOKEN to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"GITLAB_DEPLOY_TOKEN"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "GITLAB_DEPLOY_TOKEN"
  fi
done

# Patch: ensure shell_env_passthrough includes GOOGLE_SERVICE_ACCOUNT_JSON
if ! grep -q '"GOOGLE_SERVICE_ACCOUNT_JSON"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "GOOGLE_SERVICE_ACCOUNT_JSON"
fi

# Propagate GOOGLE_SERVICE_ACCOUNT_JSON to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"GOOGLE_SERVICE_ACCOUNT_JSON"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "GOOGLE_SERVICE_ACCOUNT_JSON"
  fi
done

# Patch: ensure shell_env_passthrough includes SCRAPECREATORS_API_KEY
if ! grep -q '"SCRAPECREATORS_API_KEY"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "SCRAPECREATORS_API_KEY"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"SCRAPECREATORS_API_KEY"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "SCRAPECREATORS_API_KEY"
  fi
done

# Patch: ensure shell_env_passthrough includes XAI_API_KEY
if ! grep -q '"XAI_API_KEY"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "XAI_API_KEY"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"XAI_API_KEY"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "XAI_API_KEY"
  fi
done

# Patch: ensure shell_env_passthrough includes BRAVE_API_KEY
if ! grep -q '"BRAVE_API_KEY"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "BRAVE_API_KEY"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"BRAVE_API_KEY"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "BRAVE_API_KEY"
  fi
done

# Patch: ensure shell_env_passthrough includes JIRA_API_TOKEN
if ! grep -q '"JIRA_API_TOKEN"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "JIRA_API_TOKEN"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"JIRA_API_TOKEN"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "JIRA_API_TOKEN"
  fi
done

# Patch: ensure shell_env_passthrough includes JWT_SIGNING_SECRET
if ! grep -q '"JWT_SIGNING_SECRET"' "$config_file" 2>/dev/null; then
  python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$config_file" "JWT_SIGNING_SECRET"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '"JWT_SIGNING_SECRET"' "$user_config" 2>/dev/null; then
    python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "JWT_SIGNING_SECRET"
  fi
done

# Patch: ensure [jira] section exists with enabled=true and Lalafo defaults
#  - template ($config_file) AND every per-user config get the same block
#  - api_token stays empty; runtime reads JIRA_API_TOKEN env var (Fly secret)
#  - idempotent: skip if section already present
#  - NO shell function (dash -eu + nested fn = crash-loop risk, see
#    docs/analysis/2026-05-22-vpn-flap-mitigations-attempted.md)
if ! grep -q '^\[jira\]' "$config_file" 2>/dev/null; then
  python3 -c "
import sys
p = sys.argv[1]
with open(p, 'a') as f:
    f.write('''

[jira]
enabled = true
base_url = \"https://yallaclassifieds.atlassian.net\"
email = \"oleg.gismatulin@lalafo.com\"
api_token = \"\"
allowed_actions = [\"get_ticket\", \"search_tickets\", \"comment_ticket\"]
timeout_secs = 30
''')
" "$config_file"
fi

for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '^\[jira\]' "$user_config" 2>/dev/null; then
    python3 -c "
import sys
p = sys.argv[1]
with open(p, 'a') as f:
    f.write('''

[jira]
enabled = true
base_url = \"https://yallaclassifieds.atlassian.net\"
email = \"oleg.gismatulin@lalafo.com\"
api_token = \"\"
allowed_actions = [\"get_ticket\", \"search_tickets\", \"comment_ticket\"]
timeout_secs = 30
''')
" "$user_config"
  fi
done

# Patch: keep runtime allowlist aligned with config.toml and config.fly.toml.template
for command in $baseline_allowed_commands; do
  ensure_multiline_array_item "allowed_commands" "$command"
done

# Patch: keep auto_approve aligned with config.toml and config.fly.toml.template
for action in $baseline_auto_approve; do
  ensure_multiline_array_item "auto_approve" "$action"
done

# Patch: child daemons behind manager must not require pairing
if grep -q 'require_pairing = true' "$config_file" 2>/dev/null; then
  sed -i 's/require_pairing = true/require_pairing = false/' "$config_file"
fi

# Patch: ensure require_approval_for_medium_risk is false
if grep -q 'require_approval_for_medium_risk = true' "$config_file" 2>/dev/null; then
  sed -i 's/require_approval_for_medium_risk = true/require_approval_for_medium_risk = false/' "$config_file"
fi

# Patch: ensure block_high_risk_commands is false (wget needs it)
if grep -q 'block_high_risk_commands = true' "$config_file" 2>/dev/null; then
  sed -i 's/block_high_risk_commands = true/block_high_risk_commands = false/' "$config_file"
fi

# Patch: increase autonomy limits for pro-active tasks
sed -i 's/max_actions_per_hour = [0-9]*/max_actions_per_hour = 500/' "$config_file"
sed -i 's/max_cost_per_day_cents = [0-9]*/max_cost_per_day_cents = 5000/' "$config_file"

# Patch: enable embedding provider for RAG (vector + keyword hybrid search)
if grep -q 'embedding_provider = "none"' "$config_file" 2>/dev/null; then
  sed -i 's/embedding_provider = "none"/embedding_provider = "openrouter"/' "$config_file"
fi
if ! grep -q 'embedding_model' "$config_file" 2>/dev/null; then
  sed -i '/embedding_provider/a embedding_model = "openai/text-embedding-3-small"\nembedding_dimensions = 1536' "$config_file"
fi

# Patch: propagate embedding config to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if grep -q 'embedding_provider = "none"' "$user_config" 2>/dev/null; then
    sed -i 's/embedding_provider = "none"/embedding_provider = "openrouter"/' "$user_config"
  fi
  if ! grep -q 'embedding_model' "$user_config" 2>/dev/null; then
    sed -i '/embedding_provider/a embedding_model = "openai/text-embedding-3-small"\nembedding_dimensions = 1536' "$user_config"
  fi
done

# Patch: set allowed_roots for code-repos access via content_search/glob_search
if grep -q 'allowed_roots = \[\]' "$config_file" 2>/dev/null; then
  sed -i 's/allowed_roots = \[\]/allowed_roots = ["\/zeroclaw-data\/code-repos"]/' "$config_file"
fi

# Propagate allowed_roots to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if grep -q 'allowed_roots = \[\]' "$user_config" 2>/dev/null; then
    sed -i 's/allowed_roots = \[\]/allowed_roots = ["\/zeroclaw-data\/code-repos"]/' "$user_config"
  fi
done

# Patch: allow reading env via /proc
sed -i 's/"\/proc",//' "$config_file"

# Patch: remove deprecated top-level keys (v0.3.3 does not recognize them)
sed -i '/^workspace_dir = /d' "$config_file"
sed -i '/^config_path = /d' "$config_file"

# Patch: propagate shell_env_passthrough updates to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  for cvar in CREATIO_BASE_URL CREATIO_USERNAME CREATIO_PASSWORD PG_PROD_HOST PG_PROD_PORT PG_PROD_USER PG_PROD_PASSWORD PG_STAGE_HOST PG_STAGE_PORT PG_STAGE_USER PG_STAGE_PASSWORD; do
    if ! grep -q "\"$cvar\"" "$user_config" 2>/dev/null; then
      python3 -c "
import sys, re
p, v = sys.argv[1], sys.argv[2]
c = open(p).read()
c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\1\"' + v + r'\", ', c, count=1)
open(p, 'w').write(c)
" "$user_config" "$cvar"
    fi
  done
done

# Patch: append [mcp] section with Context7 if missing (hosted HTTP, no API key)
if ! grep -q '^\[mcp\]' "$config_file" 2>/dev/null; then
  cat >> "$config_file" <<'MCP'

[mcp]
enabled = true
deferred_loading = false

[[mcp.servers]]
name = "context7"
transport = "http"
url = "https://mcp.context7.com/mcp"
tool_timeout_secs = 60
MCP
fi

# Patch: propagate [mcp] section to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  if ! grep -q '^\[mcp\]' "$user_config" 2>/dev/null; then
    cat >> "$user_config" <<'MCP'

[mcp]
enabled = true
deferred_loading = false

[[mcp.servers]]
name = "context7"
transport = "http"
url = "https://mcp.context7.com/mcp"
tool_timeout_secs = 60
MCP
  fi
done

# Patch: disable deferred_loading for MCP (tools must be available immediately per webhook)
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if grep -q 'deferred_loading = true' "$cfg" 2>/dev/null; then
    sed -i 's/deferred_loading = true/deferred_loading = false/' "$cfg"
  fi
done

# Patch: append [shell_tool] section to raise shell timeout from 60s default to 600s
# (long-running research scripts like skills/last30days/scripts/run.py).
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if ! grep -q '^\[shell_tool\]' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<'SHELLTOOL'

[shell_tool]
timeout_secs = 600
SHELLTOOL
  fi
done

# Patch: append [multimodal] vision routing section if missing (idempotent).
# Delegated vision: [IMAGE:<abspath>] markers route the iteration to openrouter
# (main provider opencode-go has vision=false). Keep block byte-identical to
# config.toml / config.fly.toml.template (three-files rule).
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if ! grep -q '^\[multimodal\]' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<'MULTIMODAL'

[multimodal]
max_images = 4
max_image_size_mb = 20
vision_provider = "openrouter"
vision_model = "google/gemini-3.1-flash-lite-preview"
MULTIMODAL
  fi
done

# Patch: append lalafo-db MCP server if missing (requires [mcp] to already exist)
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if grep -q '^\[mcp\]' "$cfg" && ! grep -q 'name = "lalafo-db"' "$cfg"; then
    cat >> "$cfg" <<'MCPDB'

[[mcp.servers]]
name = "lalafo-db"
transport = "http"
url = "http://localhost:4000/mcp"
tool_timeout_secs = 120
MCPDB
  fi
done

# Graylog MCP migration (post lalafo-db)
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if grep -q '^\[mcp\]' "$cfg" && ! grep -q 'name = "graylog"' "$cfg"; then
    echo "[entrypoint] Adding graylog MCP to $cfg"
    cat >> "$cfg" <<'MCPGRAYLOG'

[[mcp.servers]]
name = "graylog"
transport = "http"
url = "http://localhost:4001/mcp"
tool_timeout_secs = 120
MCPGRAYLOG
  fi
done

# forbidden_paths — Python для робастности (sed на multiline TOML arrays)
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PYEOF'
import re
import sys
from pathlib import Path

p = Path(sys.argv[1])
text = p.read_text()
if "/zeroclaw-data/mcp_graylog" in text:
    sys.exit(0)
new = re.sub(
    r'(forbidden_paths\s*=\s*\[)',
    r'\1\n    "/zeroclaw-data/mcp_graylog",',
    text, count=1
)
if new != text:
    p.write_text(new)
    print(f"[entrypoint] Added /zeroclaw-data/mcp_graylog to forbidden_paths in {p}")
PYEOF
done

# Patch: subagents roster v3 (6 agents: worker/coder + 4 analysts for error-analysis ensemble)
# Idempotent bounded strip-and-replace of [delegate] + every [agents.*] section.
# Guard: version marker. Removal regex stops at next ^[ so it never touches
# [agent.context_compression] / [reliability] (which sit AFTER agents at runtime).
# Spec: docs/superpowers/specs/2026-05-29-analysis-ensemble-subagents-design.md
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_SUBAGENTS'
import sys, re
from pathlib import Path
p = Path(sys.argv[1])
c = p.read_text(encoding="utf-8")
MARKER = "# subagents-v4"
if MARKER in c:
    sys.exit(0)  # already migrated
# Strip orphan old marker lines left above [delegate] by prior migrations.
c = c.replace("# subagents-v2-ensemble\n", "")
c = c.replace("# subagents-v3\n", "")
# Remove [delegate] and every [agents.<name>] section: header -> next ^[ or EOF.
c = re.sub(r'(?ms)^\[delegate\].*?(?=^\[|\Z)', '', c)
c = re.sub(r'(?ms)^\[agents\.[^\]]+\].*?(?=^\[|\Z)', '', c)
# MARKER is the LITERAL first line of canonical (not %s) so runtime guard and
# the test regex anchor on the same string.
canonical = """# subagents-v4
[delegate]
timeout_secs = 90
agentic_timeout_secs = 600

[agents.worker]
provider = "openai-codex"
model = "gpt-5.4-mini"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are a fast, focused task executor. Run the delegated sub-task independently using the tools available. Return a concise, structured result."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "swarm", "cron_add",
    "cron_list", "cron_remove", "cron_run", "cron_runs",
    "cron_update", "schedule", "model_switch", "model_routing_config",
    "claude_code", "codex_cli", "gemini_cli", "opencode_cli",
    "image_gen", "image_info", "pdf_read", "screenshot",
    "sessions_history", "sessions_list", "sessions_send", "workspace",
    "calculator", "counting", "project_intel", "llm_task",
    "report_template", "execute_pipeline", "git_operations", "sop_advance",
    "sop_approve", "sop_execute", "sop_list", "sop_status",
    "security_ops", "vi_verify", "notion", "jira",
    "linkedin", "google_workspace", "microsoft365", "discord_search",
    "composio", "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query",
    "lalafo-db__query_file", "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases",
    "lalafo-db__ch_tables", "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health",
    "graylog__health", "graylog__count", "graylog__search", "graylog__by_request_id",
    "graylog__by_user", "graylog__search_to_file",
]

[agents.coder]
provider = "openai-codex"
model = "gpt-5.5"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are a senior engineer. Read code with content_search/glob_search, reason carefully, make precise edits, run tests via shell. Treat the task description and any cited prior logic as a CLAIM to verify against the real code, not ground truth — trace callers to confirm you are editing the right path. Before treating something as a bug to fix, check whether it is intentional (git blame, comments, other call sites, other countries/configs); distinguish a real defect from code that merely looks wrong but is deliberate. Before and after editing, state the blast radius: what else calls this code, which other paths/configs/countries are affected, what could regress. Explicitly flag anything you could not verify instead of filling the gap with a plausible guess. Report concisely what you changed and why."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "swarm", "cron_add",
    "cron_list", "cron_remove", "cron_run", "cron_runs",
    "cron_update", "schedule", "model_switch", "model_routing_config",
    "claude_code", "codex_cli", "gemini_cli", "opencode_cli",
    "image_gen", "image_info", "pdf_read", "screenshot",
    "sessions_history", "sessions_list", "sessions_send", "workspace",
    "calculator", "counting", "project_intel", "llm_task",
    "report_template", "execute_pipeline", "git_operations", "sop_advance",
    "sop_approve", "sop_execute", "sop_list", "sop_status",
    "security_ops", "vi_verify", "notion", "jira",
    "linkedin", "google_workspace", "microsoft365", "discord_search",
    "composio", "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query",
    "lalafo-db__query_file", "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases",
    "lalafo-db__ch_tables", "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health",
    "graylog__health", "graylog__count", "graylog__search", "graylog__by_request_id",
    "graylog__by_user", "graylog__search_to_file",
]

[agents.analyst_mimo]
provider = "opencode-go"
model = "mimo-v2.5-pro"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are an independent diagnostic analyst. From ONLY the error context in the user message plus the tools available, perform a thorough root-cause analysis. You have NO access to prior conversation, personal files, or stored memory — work strictly from what is given. Investigate with content_search/glob_search/shell, DB (lalafo-db__*), logs (graylog__*) and docs (context7__*) where relevant. Treat the reporter's described actual/expected behaviour and any cited prior logic as a CLAIM to verify against the real code, not ground truth — confirm the suspect code path actually produces the symptom by tracing its callers. Before declaring a bug, check whether the suspect code is intentional (git blame, comments, other call sites, other countries/configs); distinguish a real defect from code that merely looks wrong but is deliberate. Return a structured result: ROOT CAUSE / EVIDENCE / ALTERNATIVES / FIX / CONFIDENCE / UNVERIFIED. In FIX, state the blast radius: what else calls this code, which other countries/configs/paths are affected, what could regress. In UNVERIFIED, list every claim you could not confirm and why (no DB access, path not found, needs runtime data); never present an inferred gap as fact. Be concise and specific. Do not fabricate findings."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "cron_add", "cron_list",
    "cron_remove", "cron_run", "cron_runs", "cron_update",
    "schedule", "model_switch", "model_routing_config", "claude_code",
    "codex_cli", "gemini_cli", "opencode_cli", "image_gen",
    "image_info", "pdf_read", "screenshot", "sessions_history",
    "sessions_list", "sessions_send", "workspace", "calculator",
    "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations", "sop_advance", "sop_approve",
    "sop_execute", "sop_list", "sop_status", "security_ops",
    "vi_verify", "notion", "jira", "linkedin",
    "google_workspace", "microsoft365", "discord_search", "composio",
    "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query", "lalafo-db__query_file",
    "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases", "lalafo-db__ch_tables",
    "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health", "graylog__health",
    "graylog__count", "graylog__search", "graylog__by_request_id", "graylog__by_user",
    "graylog__search_to_file",
]

[agents.analyst_deepseek_pro]
provider = "deepseek"
model = "deepseek-v4-pro"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are an independent diagnostic analyst. From ONLY the error context in the user message plus the tools available, perform a thorough root-cause analysis. You have NO access to prior conversation, personal files, or stored memory — work strictly from what is given. Investigate with content_search/glob_search/shell, DB (lalafo-db__*), logs (graylog__*) and docs (context7__*) where relevant. Treat the reporter's described actual/expected behaviour and any cited prior logic as a CLAIM to verify against the real code, not ground truth — confirm the suspect code path actually produces the symptom by tracing its callers. Before declaring a bug, check whether the suspect code is intentional (git blame, comments, other call sites, other countries/configs); distinguish a real defect from code that merely looks wrong but is deliberate. Return a structured result: ROOT CAUSE / EVIDENCE / ALTERNATIVES / FIX / CONFIDENCE / UNVERIFIED. In FIX, state the blast radius: what else calls this code, which other countries/configs/paths are affected, what could regress. In UNVERIFIED, list every claim you could not confirm and why (no DB access, path not found, needs runtime data); never present an inferred gap as fact. Be concise and specific. Do not fabricate findings."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "cron_add", "cron_list",
    "cron_remove", "cron_run", "cron_runs", "cron_update",
    "schedule", "model_switch", "model_routing_config", "claude_code",
    "codex_cli", "gemini_cli", "opencode_cli", "image_gen",
    "image_info", "pdf_read", "screenshot", "sessions_history",
    "sessions_list", "sessions_send", "workspace", "calculator",
    "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations", "sop_advance", "sop_approve",
    "sop_execute", "sop_list", "sop_status", "security_ops",
    "vi_verify", "notion", "jira", "linkedin",
    "google_workspace", "microsoft365", "discord_search", "composio",
    "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query", "lalafo-db__query_file",
    "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases", "lalafo-db__ch_tables",
    "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health", "graylog__health",
    "graylog__count", "graylog__search", "graylog__by_request_id", "graylog__by_user",
    "graylog__search_to_file",
]

[agents.analyst_deepseek_flash]
provider = "deepseek"
model = "deepseek-v4-flash"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are an independent diagnostic analyst. From ONLY the error context in the user message plus the tools available, perform a thorough root-cause analysis. You have NO access to prior conversation, personal files, or stored memory — work strictly from what is given. Investigate with content_search/glob_search/shell, DB (lalafo-db__*), logs (graylog__*) and docs (context7__*) where relevant. Treat the reporter's described actual/expected behaviour and any cited prior logic as a CLAIM to verify against the real code, not ground truth — confirm the suspect code path actually produces the symptom by tracing its callers. Before declaring a bug, check whether the suspect code is intentional (git blame, comments, other call sites, other countries/configs); distinguish a real defect from code that merely looks wrong but is deliberate. Return a structured result: ROOT CAUSE / EVIDENCE / ALTERNATIVES / FIX / CONFIDENCE / UNVERIFIED. In FIX, state the blast radius: what else calls this code, which other countries/configs/paths are affected, what could regress. In UNVERIFIED, list every claim you could not confirm and why (no DB access, path not found, needs runtime data); never present an inferred gap as fact. Be concise and specific. Do not fabricate findings."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "cron_add", "cron_list",
    "cron_remove", "cron_run", "cron_runs", "cron_update",
    "schedule", "model_switch", "model_routing_config", "claude_code",
    "codex_cli", "gemini_cli", "opencode_cli", "image_gen",
    "image_info", "pdf_read", "screenshot", "sessions_history",
    "sessions_list", "sessions_send", "workspace", "calculator",
    "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations", "sop_advance", "sop_approve",
    "sop_execute", "sop_list", "sop_status", "security_ops",
    "vi_verify", "notion", "jira", "linkedin",
    "google_workspace", "microsoft365", "discord_search", "composio",
    "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query", "lalafo-db__query_file",
    "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases", "lalafo-db__ch_tables",
    "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health", "graylog__health",
    "graylog__count", "graylog__search", "graylog__by_request_id", "graylog__by_user",
    "graylog__search_to_file",
]

[agents.analyst_glm]
provider = "zai"
model = "glm-5.1"
api_key = ""
agentic = true
max_iterations = 80
system_prompt = "You are an independent diagnostic analyst. From ONLY the error context in the user message plus the tools available, perform a thorough root-cause analysis. You have NO access to prior conversation, personal files, or stored memory — work strictly from what is given. Investigate with content_search/glob_search/shell, DB (lalafo-db__*), logs (graylog__*) and docs (context7__*) where relevant. Treat the reporter's described actual/expected behaviour and any cited prior logic as a CLAIM to verify against the real code, not ground truth — confirm the suspect code path actually produces the symptom by tracing its callers. Before declaring a bug, check whether the suspect code is intentional (git blame, comments, other call sites, other countries/configs); distinguish a real defect from code that merely looks wrong but is deliberate. Return a structured result: ROOT CAUSE / EVIDENCE / ALTERNATIVES / FIX / CONFIDENCE / UNVERIFIED. In FIX, state the blast radius: what else calls this code, which other countries/configs/paths are affected, what could regress. In UNVERIFIED, list every claim you could not confirm and why (no DB access, path not found, needs runtime data); never present an inferred gap as fact. Be concise and specific. Do not fabricate findings."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search",
    "glob_search", "shell", "http_request", "web_fetch",
    "web_search_tool", "text_browser", "memory_recall", "memory_store",
    "memory_forget", "memory_export", "read_skill", "tool_search",
    "knowledge", "delegate", "cron_add", "cron_list",
    "cron_remove", "cron_run", "cron_runs", "cron_update",
    "schedule", "model_switch", "model_routing_config", "claude_code",
    "codex_cli", "gemini_cli", "opencode_cli", "image_gen",
    "image_info", "pdf_read", "screenshot", "sessions_history",
    "sessions_list", "sessions_send", "workspace", "calculator",
    "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations", "sop_advance", "sop_approve",
    "sop_execute", "sop_list", "sop_status", "security_ops",
    "vi_verify", "notion", "jira", "linkedin",
    "google_workspace", "microsoft365", "discord_search", "composio",
    "context7__resolve-library-id", "context7__query-docs", "lalafo-db__query", "lalafo-db__query_file",
    "lalafo-db__databases", "lalafo-db__ch_query", "lalafo-db__ch_databases", "lalafo-db__ch_tables",
    "lalafo-db__query_to_file", "lalafo-db__ch_query_to_file", "lalafo-db__health", "graylog__health",
    "graylog__count", "graylog__search", "graylog__by_request_id", "graylog__by_user",
    "graylog__search_to_file",
]
"""
c = c.rstrip() + "\n\n" + canonical.lstrip("\n")
p.write_text(c, encoding="utf-8")
print(f"[entrypoint] subagents roster v3 applied to {p}")
PY_SUBAGENTS
done

# Patch: wire context compression with per-model context windows
# (max_history_messages 50→200, add max_context_tokens=128_000,
#  add [agent.context_compression] + model_windows registry)
# Idempotent: only patches if old value present / new key absent.
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue

  # Bump max_history_messages from old default 50 → 200 (leave custom values alone)
  sed -i 's/^max_history_messages = 50$/max_history_messages = 200/' "$cfg"

  # Insert max_context_tokens = 128_000 right after max_history_messages, if missing
  if ! grep -q '^max_context_tokens' "$cfg" 2>/dev/null; then
    python3 -c "
import sys, re
p = sys.argv[1]
c = open(p).read()
c = re.sub(
    r'(max_history_messages\s*=\s*\d+)',
    r'\1\nmax_context_tokens = 128_000',
    c,
    count=1,
)
open(p, 'w').write(c)
" "$cfg"
  fi

  # Append [agent.context_compression] base block, if missing.
  # Separate guard from model_windows — handles partial state.
  if ! grep -q '^\[agent\.context_compression\]' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<'BASE_EOF'

[agent.context_compression]
threshold_ratio = 0.70
protect_last_n = 10
BASE_EOF
  fi

  # Append [agent.context_compression.model_windows] registry block, if missing.
  # Separate guard ensures partial state converges to full state on rerun.
  if ! grep -q '^\[agent\.context_compression\.model_windows\]' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<'WINDOWS_EOF'

[agent.context_compression.model_windows]
"mimo-v2.5-pro"           = 800_000
"mimo-v2.5"               = 800_000
"mimo-v2-pro"             = 800_000
"mimo-v2-omni"            = 800_000
"deepseek-v4-flash"       = 800_000
"deepseek-v4-pro"         = 800_000
"gemini-3-flash-preview"  = 800_000
"qwen3.6-plus"            = 800_000
"qwen3.5-plus"            = 800_000
"minimax-m2.7"            = 196_608
"minimax-m2.5"            = 196_608
"kimi-k2.6"               = 256_000
"kimi-k2.5"               = 256_000
"gpt-5.5"                 = 400_000
"gpt-5.4"                 = 400_000
"gpt-5.4-mini"            = 400_000
"glm-5-turbo"             = 128_000
"glm-5"                   = 128_000
"glm-5.1"                 = 202_752
# Capital "GLM-5.1" is a separate case-sensitive key (ZEROCLAW_MODEL ships the
# model string as-is). Same ZhiPu GLM-5.1, same ~200K window (verified 2026-06-02).
"GLM-5.1"                 = 202_752
"Qwen3.5-397B-A17B"       = 262_144
WINDOWS_EOF
  fi

  # Insert wafer-specific entries (capital GLM-5.1 + Qwen3.5-397B-A17B) into
  # existing model_windows section if missing. Idempotent — skips on rerun.
  # Anchored to "glm-5.1" line (guaranteed present in WINDOWS_EOF) — keeps
  # the insertion strictly inside the [agent.context_compression.model_windows]
  # block and never lands in trailing TOML tables.
  # Guard checks for the literal "= 202_752" value (unique to model_windows;
  # not present in legacy reliability inline-table sections).
  if grep -q '^\[agent\.context_compression\.model_windows\]' "$cfg" 2>/dev/null && \
     ! grep -qE '"GLM-5\.1"\s*=\s*202_752' "$cfg" 2>/dev/null; then
    python3 - "$cfg" <<'PY'
import sys, re
p = sys.argv[1]
c = open(p).read()
c = re.sub(
    r'("glm-5\.1"\s*=\s*\d+(?:_\d+)?)',
    r'\1\n"GLM-5.1"                 = 202_752\n"Qwen3.5-397B-A17B"       = 262_144',
    c,
    count=1,
)
open(p, 'w').write(c)
PY
  fi

  # 2026-06-02: fix lowercase glm-5.1 window 128_000 -> 202_752 in EXISTING
  # per-user model_windows blocks (append-if-missing above won't touch them).
  # Idempotent: re.sub is a no-op once value is already 202_752. Anchored to the
  # exact lowercase key so glm-5 / glm-5-turbo (also 128_000) stay untouched.
  python3 - "$cfg" <<'PY_GLM_WINDOW'
import sys, re
from pathlib import Path
p = Path(sys.argv[1])
c = p.read_text(encoding="utf-8")
new = re.sub(r'(?m)^("glm-5\.1"\s*=\s*)128_000\s*$', r'\g<1>202_752', c)
if new != c:
    p.write_text(new, encoding="utf-8")
    print(f"[entrypoint] glm-5.1 window 128_000->202_752 in {p}")
PY_GLM_WINDOW
done

# Patch: agent-browser command + AGENT_BROWSER_* / ZEROCLAW_WORKSPACE passthrough.
# Idempotent: insert "agent-browser" into the multi-line allowed_commands array if
# absent, and append each of the 5 passthrough vars to shell_env_passthrough if
# absent. Applies to template AND every per-user config (in-place loop, no rm).
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_AGENT_BROWSER'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); c = p.read_text(encoding="utf-8")
if '"agent-browser"' not in c:
    c = re.sub(r'(?ms)(^allowed_commands\s*=\s*\[.*?)(\n\])',
               r'\1\n    "agent-browser",\2', c, count=1)
for v in ("AGENT_BROWSER_PROFILE", "AGENT_BROWSER_SESSION",
          "AGENT_BROWSER_EXECUTABLE_PATH", "AGENT_BROWSER_ARGS",
          "ZEROCLAW_WORKSPACE"):
    if f'"{v}"' not in c:
        c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\g<1>"' + v + '", ', c, count=1)
p.write_text(c, encoding="utf-8")
PY_AGENT_BROWSER
done

# Patch: gh + glab commands + GITHUB_*/GITLAB_* passthrough.
# Idempotent: insert "gh"/"glab" into the multi-line allowed_commands array if absent,
# and append each of the 4 passthrough vars to shell_env_passthrough if absent.
# Applies to template AND every per-user config (in-place loop, no rm).
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_GITHUB'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); c = p.read_text(encoding="utf-8")
for cmd in ("gh", "glab"):
    if f'"{cmd}"' not in c:
        c = re.sub(r'(?ms)(^allowed_commands\s*=\s*\[.*?)(\n\])',
                   r'\1\n    "' + cmd + r'",\2', c, count=1)
for v in ("GITHUB_TOKEN", "GITHUB_USER", "GITLAB_TOKEN", "GITLAB_HOST"):
    if f'"{v}"' not in c:
        c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\g<1>"' + v + '", ', c, count=1)
p.write_text(c, encoding="utf-8")
PY_GITHUB
done

# Patch: IMAGE_UPLOAD_AWS_* passthrough for upload-ms s3_inspect.py (read-only S3).
# Idempotent: append each var to shell_env_passthrough if absent. Template + per-user.
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_IMAGE_UPLOAD_AWS'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); c = p.read_text(encoding="utf-8")
for v in ("IMAGE_UPLOAD_AWS_ACCESS_KEY_ID", "IMAGE_UPLOAD_AWS_SECRET_ACCESS_KEY"):
    if f'"{v}"' not in c:
        c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\g<1>"' + v + '", ', c, count=1)
p.write_text(c, encoding="utf-8")
PY_IMAGE_UPLOAD_AWS
done

# Patch: ADMIN_* passthrough for micromarket-db admin_micromarket.py (enable level via admin panel).
# Idempotent: append each var to shell_env_passthrough if absent. Template + per-user.
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  python3 - "$cfg" <<'PY_ADMIN_MM'
import sys, re
from pathlib import Path
p = Path(sys.argv[1]); c = p.read_text(encoding="utf-8")
for v in ("ADMIN_BASIC_USER", "ADMIN_BASIC_PASSWORD", "ADMIN_APP_EMAIL", "ADMIN_APP_PASSWORD", "ADMIN_OAUTH2_COOKIE"):
    if f'"{v}"' not in c:
        c = re.sub(r'(shell_env_passthrough\s*=\s*\[)', r'\g<1>"' + v + '", ', c, count=1)
p.write_text(c, encoding="utf-8")
PY_ADMIN_MM
done

# Migration: ensure workspace/cron_templates/ exists in per-user workspaces.
# Idempotent: skip if already present.
for user_ws in /zeroclaw-data/workspaces/tg_*/workspace; do
    if [ -d "$user_ws" ] && [ ! -d "$user_ws/cron_templates" ]; then
        echo "[fly-entrypoint] copying cron_templates/ to $user_ws"
        cp -r /zeroclaw-data/template/workspace/cron_templates "$user_ws/" || true
    fi
done

# --- OpenVPN ---
if [ -f /zeroclaw-data/vpn/client.ovpn ] && command -v openvpn > /dev/null 2>&1; then
    openvpn --config /zeroclaw-data/vpn/client.ovpn --daemon --log "$openvpn_log_path"
    for i in $(seq 1 15); do
        ip link show tun0 > /dev/null 2>&1 && break
        sleep 1
    done
    if ip link show tun0 > /dev/null 2>&1; then
        echo "[fly-entrypoint] OpenVPN: tun0 is up"
        if vpn_route_ok; then
            echo "[fly-entrypoint] OpenVPN: prod DB routes use tun0"
        else
            echo "[fly-entrypoint] WARNING: OpenVPN tun0 is up but prod DB routes are not ready"
        fi
        start_openvpn_watchdog
    else
        echo "[fly-entrypoint] WARNING: OpenVPN tun0 did not come up, DB tools will be unavailable"
    fi
fi

# --- MCP DB Server ---
if ip link show tun0 > /dev/null 2>&1; then
    python3 /usr/local/bin/mcp_db_server.py &
    MCP_DB_PID=$!
    MCP_DB_READY=0
    for i in $(seq 1 15); do
        if curl -s "http://localhost:${MCP_DB_PORT:-4000}/health" > /dev/null 2>&1; then
            MCP_DB_READY=1
            break
        fi
        sleep 1
    done
    if [ "$MCP_DB_READY" -eq 1 ]; then
        echo "[fly-entrypoint] MCP DB Server started (pid=$MCP_DB_PID)"
    else
        echo "[fly-entrypoint] WARNING: MCP DB Server started (pid=$MCP_DB_PID) but /health is not healthy"
    fi
fi

# --- MCP Graylog Server — independent of VPN ---
echo "[fly-entrypoint] Starting MCP Graylog Server on port ${GRAYLOG_MCP_PORT:-4001}..."
python3 /usr/local/bin/mcp_graylog.py &
MCP_GRAYLOG_PID=$!
MCP_GRAYLOG_READY=0
for i in $(seq 1 10); do
    if curl -s "http://localhost:${GRAYLOG_MCP_PORT:-4001}/health" > /dev/null 2>&1; then
        MCP_GRAYLOG_READY=1
        break
    fi
    sleep 1
done
if [ "$MCP_GRAYLOG_READY" -eq 1 ]; then
    echo "[fly-entrypoint] MCP Graylog Server started (pid=$MCP_GRAYLOG_PID)"
else
    echo "[fly-entrypoint] WARNING: MCP Graylog Server (pid=$MCP_GRAYLOG_PID) /health not yet OK — cookie may be expired/missing"
fi

# --- Lightpanda CDP sidecar (fast read-only parsing engine for agent-browser --cdp) ---
# Shared, stateless, localhost-only. Started like the MCP sidecars; no respawn
# (Chrome path is the fallback if it dies). Plain start-block only — no new shell
# functions/loops (dash + set -eu crash-loop lesson, 2026-05-22). See spec 2026-06-05.
echo "[fly-entrypoint] Starting Lightpanda CDP server on 127.0.0.1:${LIGHTPANDA_PORT:-9222}..."
LIGHTPANDA_DISABLE_TELEMETRY=true lightpanda serve --host 127.0.0.1 --port "${LIGHTPANDA_PORT:-9222}" &
LIGHTPANDA_PID=$!
LIGHTPANDA_READY=0
for i in $(seq 1 10); do
    if curl -s "http://127.0.0.1:${LIGHTPANDA_PORT:-9222}/json/version" > /dev/null 2>&1; then
        LIGHTPANDA_READY=1
        break
    fi
    sleep 1
done
if [ "$LIGHTPANDA_READY" -eq 1 ]; then
    echo "[fly-entrypoint] Lightpanda CDP server started (pid=$LIGHTPANDA_PID)"
else
    echo "[fly-entrypoint] WARNING: Lightpanda (pid=$LIGHTPANDA_PID) /json/version not healthy — parsing falls back to Chrome"
fi

export ZEROCLAW_DATA_ROOT=/zeroclaw-data
exec python3 /usr/local/bin/gateway_manager.py
