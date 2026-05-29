#!/usr/bin/env bash
# activate-slack-observer.sh
#
# Adds [observability] backend = "slack" + slack_webhook_url + token_alert_threshold
# to every zeroclaw agent config.toml that is missing them.
#
# Usage:
#   ./activate-slack-observer.sh [config-dir] [webhook-url] [threshold]
#
# Defaults:
#   config-dir  = /opt/openclaw/agents
#   webhook-url = (no default — must be supplied as $2 or via SLACK_WEBHOOK_URL env var)
#   threshold   = 250000
#
# Idempotent: skips files that already have all three fields correctly set.
# Backup:     each modified file is copied to <file>.bak-slack-observer-<timestamp>
#
# DO NOT RUN until zeroclaw-runtime is deployed on the fleet (PRs #7 / #9 merged).

set -euo pipefail

AGENTS_DIR="${1:-/opt/openclaw/agents}"
# Webhook URL: pass as $2 or set SLACK_WEBHOOK_URL in environment.
# Retrieve the live value from /opt/openclaw.env or sla-config.json on the droplet.
WEBHOOK_URL="${2:-${SLACK_WEBHOOK_URL:-}}"
THRESHOLD="${3:-250000}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# ── Validate inputs ──────────────────────────────────────────────────────────
if [[ ! -d "$AGENTS_DIR" ]]; then
  echo "ERROR: agents directory not found: $AGENTS_DIR" >&2
  exit 1
fi

if [[ -z "$WEBHOOK_URL" || "$WEBHOOK_URL" == "PLACEHOLDER" ]]; then
  echo "ERROR: webhook URL is empty or placeholder." >&2
  exit 1
fi

# Threshold must be a non-negative integer
if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "ERROR: threshold must be a non-negative integer, got: $THRESHOLD" >&2
  exit 1
fi

# ── patch_config ─────────────────────────────────────────────────────────────
# Returns:
#   "PATCHED <path>"  — file was modified
#   "SKIP <path>"     — file was already fully configured
#   "ERROR <path> <reason>" — something went wrong (file unchanged or partially changed)
#
# Writes all output to stdout; caller captures it.
patch_config() {
  local cfg="$1"
  local tag="ERROR $cfg"

  # Must be a regular readable file
  if [[ ! -f "$cfg" || ! -r "$cfg" ]]; then
    echo "$tag not a readable file"
    return 0
  fi

  # ── Idempotency checks ───────────────────────────────────────────────────
  # Use -E (extended regex) + [[:space:]] for POSIX portability; GNU grep only
  # needs -E here for the alternation/quantifier syntax.
  local has_section=0 has_backend_slack=0 has_any_backend=0 has_webhook=0 has_threshold=0

  grep -qE '^\[observability\]'                            "$cfg" && has_section=1        || true
  grep -qE '^[[:space:]]*backend[[:space:]]*=[[:space:]]*"slack"'   "$cfg" && has_backend_slack=1 || true
  grep -qE '^[[:space:]]*backend[[:space:]]*='                       "$cfg" && has_any_backend=1  || true
  grep -qE '^[[:space:]]*slack_webhook_url[[:space:]]*='             "$cfg" && has_webhook=1      || true
  grep -qE '^[[:space:]]*token_alert_threshold[[:space:]]*='         "$cfg" && has_threshold=1    || true

  # All three target fields already set correctly — nothing to do
  if [[ $has_backend_slack -eq 1 && $has_webhook -eq 1 && $has_threshold -eq 1 ]]; then
    echo "SKIP $cfg"
    return 0
  fi

  # ── Backup ───────────────────────────────────────────────────────────────
  local backup="${cfg}.bak-slack-observer-${TIMESTAMP}"
  if ! cp "$cfg" "$backup" 2>/dev/null; then
    echo "$tag could not create backup (check permissions)"
    return 0
  fi

  # ── Case A: [observability] section does not exist — append entire block ──
  if [[ $has_section -eq 0 ]]; then
    # Ensure file ends with a newline before appending
    [[ -s "$cfg" ]] && [[ "$(tail -c1 "$cfg" | wc -c)" -gt 0 ]] && printf '\n' >> "$cfg"
    cat >> "$cfg" <<TOML

[observability]
backend = "slack"
slack_webhook_url = "${WEBHOOK_URL}"
token_alert_threshold = ${THRESHOLD}
TOML
    echo "PATCHED $cfg (appended [observability] section)"
    return 0
  fi

  # ── Case B: [observability] exists — patch individual missing fields ──────
  # Use GNU sed's /pattern/a (append-after) directive instead of s///\n
  # to avoid newline-in-replacement portability issues.

  # Fix backend: if any backend key exists (possibly set to "log" etc.), replace its value.
  # If no backend key at all, insert one after the section header.
  if [[ $has_backend_slack -eq 0 ]]; then
    if [[ $has_any_backend -eq 1 ]]; then
      # Replace whatever value backend has with "slack"
      sed -i -E 's|^([[:space:]]*backend[[:space:]]*=[[:space:]]*).*$|\1"slack"|' "$cfg"
    else
      # Insert new backend = "slack" after [observability]
      sed -i '/^\[observability\]/a backend = "slack"' "$cfg"
    fi
  fi

  if [[ $has_webhook -eq 0 ]]; then
    sed -i "/^\[observability\]/a slack_webhook_url = \"${WEBHOOK_URL}\"" "$cfg"
  fi

  if [[ $has_threshold -eq 0 ]]; then
    sed -i "/^\[observability\]/a token_alert_threshold = ${THRESHOLD}" "$cfg"
  fi

  echo "PATCHED $cfg (patched existing [observability] section)"
  return 0
}

# ── Main loop ────────────────────────────────────────────────────────────────
echo "Scanning: $AGENTS_DIR"
echo "Webhook:  ${WEBHOOK_URL:0:60}..."
echo "Threshold: ${THRESHOLD} tokens"
echo ""

found=0
patched=0
skipped=0
errors=0

while IFS= read -r -d '' cfg; do
  found=$((found + 1))
  result="$(patch_config "$cfg")"
  echo "  $result"
  case "$result" in
    PATCHED*) patched=$((patched + 1)) ;;
    SKIP*)    skipped=$((skipped + 1)) ;;
    ERROR*)   errors=$((errors + 1))   ;;
  esac
done < <(find "$AGENTS_DIR" -name "config.toml" -print0 2>/dev/null)

echo ""
if [[ $found -eq 0 ]]; then
  echo "WARNING: No config.toml files found under $AGENTS_DIR"
  echo "The zeroclaw-runtime may not be deployed yet."
  echo "Run this script after the runtime is deployed and agent configs are generated."
  exit 0
fi

echo "Done.  found=$found  patched=$patched  skipped=$skipped  errors=$errors"
[[ $errors -gt 0 ]] && echo "WARNING: $errors file(s) had errors — check output above" && exit 1
echo "Backups: *.bak-slack-observer-${TIMESTAMP}"
