#!/bin/sh
set -eu

# Thin runtime-only entrypoint (Phase 3 of the V3 config-migration project).
#
# Config is NO LONGER patched/migrated here. The native schema_version=3
# templates (config.toml + config.fly.toml.template) carry every setting the
# entrypoint used to inject, and per-user config cutover now lives in
# scripts/gateway_manager.py (WorkspaceBootstrapper.cutover_peruser_config).
# This file only: seeds the template config from secrets on first boot,
# sanitizes a legacy workspace copy, brings up OpenVPN + sidecars, and execs
# the manager.

legacy_config_dir="/zeroclaw-data/.zeroclaw"
legacy_workspace_dir="/zeroclaw-data/workspace"
config_dir="/zeroclaw-data/template/.zeroclaw"
config_file="$config_dir/config.toml"
workspace_dir="/zeroclaw-data/template/workspace"
shared_auth_dir="/zeroclaw-data/shared-auth"
manager_dir="/zeroclaw-data/manager"
workspaces_dir="/zeroclaw-data/workspaces"
template_file="/seed/config.fly.toml.template"
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

# Legacy single-user -> multi-user template migration: seed the template
# workspace from the old single-user workspace if the template is still empty.
if [ -d "$legacy_workspace_dir" ] && [ -z "$(find "$workspace_dir" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1)" ]; then
  copy_sanitized_workspace_template "$legacy_workspace_dir" "$workspace_dir"
fi

# Carry forward shared auth profiles (codex OAuth etc.) from the legacy layout.
for auth_file in auth-profiles.json .secret_key; do
  if [ -f "$legacy_config_dir/$auth_file" ] && [ ! -f "$shared_auth_dir/$auth_file" ]; then
    cp "$legacy_config_dir/$auth_file" "$shared_auth_dir/$auth_file"
  fi
done

# Seed the template config from the native V3 template on first boot. The
# config is no longer patched after this — all settings are already in the
# template; only the secret placeholders are substituted here.
if [ ! -f "$config_file" ]; then
  if [ -z "${ZEROCLAW_WEBHOOK_SECRET:-}" ]; then
    echo "ZEROCLAW_WEBHOOK_SECRET is required to initialize Fly runtime config." >&2
    exit 1
  fi

  sed -e "s|__ZEROCLAW_WEBHOOK_SECRET__|$ZEROCLAW_WEBHOOK_SECRET|g" \
      -e "s|__OPENROUTER_API_KEY__|${OPENROUTER_API_KEY:-}|g" \
      -e "s|__ZEROCLAW_BEARER_TOKEN__|${ZEROCLAW_BEARER_TOKEN:-}|g" \
      "$template_file" > "$config_file"
  chmod 0600 "$config_file"
fi

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
