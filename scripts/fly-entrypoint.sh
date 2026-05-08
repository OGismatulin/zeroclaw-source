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
baseline_allowed_commands="git npm cargo sh ls cat grep find echo pwd wc head tail date wget python3 pip pip3 node npx ffmpeg convert pandoc curl jq"
baseline_auto_approve="file_read file_write memory_recall shell http_request"

mkdir -p "$config_dir" "$workspace_dir" "$shared_auth_dir" "$manager_dir" "$workspaces_dir"

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

# Patch: append [reliability] section if missing (fallback disabled to surface config errors)
if ! grep -q '^\[reliability\]' "$config_file" 2>/dev/null; then
  cat >> "$config_file" <<'RELIABILITY'

[reliability]
fallback_providers = []

[reliability.model_fallbacks]
RELIABILITY
fi

# Patch: disable fallback in existing configs to surface provider misconfiguration
sed -i 's/fallback_providers = \["openrouter"\]/fallback_providers = []/' "$config_file"

# Patch: fix api_key = "minimax-oauth" literal leak for non-minimax providers
sed -i 's/^api_key = "minimax-oauth"/api_key = ""/' "$config_file"

# Patch: propagate api_key and fallback fix to existing per-user configs
for user_config in "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$user_config" ] || continue
  sed -i 's/^api_key = "minimax-oauth"/api_key = ""/' "$user_config"
  sed -i 's/fallback_providers = \["openrouter"\]/fallback_providers = []/' "$user_config"
done

# Patch: ensure shell_env_passthrough includes NOTIFY vars
if grep -q 'shell_env_passthrough = \[\]' "$config_file" 2>/dev/null; then
  sed -i 's/shell_env_passthrough = \[\]/shell_env_passthrough = ["NOTIFY_URL", "NOTIFY_SECRET"]/' "$config_file"
fi

# Patch: ensure shell_env_passthrough includes CREATIO and PG_PROD env vars
for cvar in CREATIO_BASE_URL CREATIO_USERNAME CREATIO_PASSWORD PG_PROD_HOST PG_PROD_PORT PG_PROD_USER PG_PROD_PASSWORD; do
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
  for cvar in CREATIO_BASE_URL CREATIO_USERNAME CREATIO_PASSWORD PG_PROD_HOST PG_PROD_PORT PG_PROD_USER PG_PROD_PASSWORD; do
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

# Patch: append [delegate] + [agents.worker] + [agents.coder] if missing (subagents for parallel delegation)
for cfg in "$config_file" "$workspaces_dir"/tg_*/.zeroclaw/config.toml; do
  [ -f "$cfg" ] || continue
  if ! grep -q '^\[agents\.worker\]' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<'SUBAGENTS'

[delegate]
timeout_secs = 90
agentic_timeout_secs = 180

[agents.worker]
provider = "openai-codex"
model = "gpt-5.4-mini"
api_key = ""
agentic = true
max_iterations = 15
system_prompt = "You are a fast, focused task executor. Run the delegated sub-task independently using the tools available. Return a concise, structured result."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search", "glob_search",
    "shell", "http_request", "web_fetch", "web_search_tool", "text_browser",
    "memory_recall", "memory_store", "memory_forget", "memory_export",
    "read_skill", "tool_search", "knowledge",
    "delegate", "swarm",
    "cron_add", "cron_list", "cron_remove", "cron_run", "cron_runs", "cron_update", "schedule",
    "model_switch", "model_routing_config",
    "claude_code", "codex_cli", "gemini_cli", "opencode_cli",
    "image_gen", "image_info", "pdf_read", "screenshot",
    "sessions_history", "sessions_list", "sessions_send", "workspace",
    "calculator", "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations",
    "sop_advance", "sop_approve", "sop_execute", "sop_list", "sop_status",
    "security_ops", "vi_verify",
    "notion", "jira", "linkedin", "google_workspace", "microsoft365", "discord_search", "composio",
]

[agents.coder]
provider = "openai-codex"
model = "gpt-5.4"
api_key = ""
agentic = true
max_iterations = 25
system_prompt = "You are a senior engineer. Read code with content_search/glob_search, reason carefully, make precise edits, run tests via shell. Report concisely what you changed and why."
allowed_tools = [
    "file_read", "file_write", "file_edit", "content_search", "glob_search",
    "shell", "http_request", "web_fetch", "web_search_tool", "text_browser",
    "memory_recall", "memory_store", "memory_forget", "memory_export",
    "read_skill", "tool_search", "knowledge",
    "delegate", "swarm",
    "cron_add", "cron_list", "cron_remove", "cron_run", "cron_runs", "cron_update", "schedule",
    "model_switch", "model_routing_config",
    "claude_code", "codex_cli", "gemini_cli", "opencode_cli",
    "image_gen", "image_info", "pdf_read", "screenshot",
    "sessions_history", "sessions_list", "sessions_send", "workspace",
    "calculator", "counting", "project_intel", "llm_task", "report_template",
    "execute_pipeline", "git_operations",
    "sop_advance", "sop_approve", "sop_execute", "sop_list", "sop_status",
    "security_ops", "vi_verify",
    "notion", "jira", "linkedin", "google_workspace", "microsoft365", "discord_search", "composio",
]
SUBAGENTS
  fi
done

# --- OpenVPN ---
if [ -f /zeroclaw-data/vpn/client.ovpn ] && command -v openvpn > /dev/null 2>&1; then
    openvpn --config /zeroclaw-data/vpn/client.ovpn --daemon --log /tmp/openvpn.log
    for i in $(seq 1 15); do
        ip link show tun0 > /dev/null 2>&1 && break
        sleep 1
    done
    if ip link show tun0 > /dev/null 2>&1; then
        echo "[fly-entrypoint] OpenVPN: tun0 is up"
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

export ZEROCLAW_DATA_ROOT=/zeroclaw-data
exec python3 /usr/local/bin/gateway_manager.py
