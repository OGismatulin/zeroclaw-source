# Zeroclaw Runtime — Post-Merge Deploy Runbook

**Status:** DRAFT — execute only after PR #7 (OGismatulin/zeroclaw-source) and PR #9
(kevin-meng/zeroclaw-hindsight-v2) are merged into their respective `master` branches.  
**Last updated:** 2026-05-30  
**Droplet:** 165.232.173.166  
**Branch with changes:** `krispyking/zeroclaw-source:fix/token-accumulation-loop`

---

## Prerequisites

- [ ] PR #7 merged into `OGismatulin/zeroclaw-source:master`
- [ ] PR #9 merged into `kevin-meng/zeroclaw-hindsight-v2:master`
- [ ] Rust toolchain available: `source ~/.cargo/env && rustc --version` (must show ≥ 1.83)
- [ ] Disk space confirmed: `df -h /` — need ≥ 4 GB free for build artifacts

---

## Section A — Build & Install the Binary on the Droplet

```bash
# 1. Confirm disk space
df -h /

# 2. SSH onto the droplet
ssh root@165.232.173.166

# 3. Source the Rust toolchain
source ~/.cargo/env
rustc --version   # expect: rustc 1.93.0 or newer

# 4. Update fork clone to the merged upstream
cd ~/.openclaw/workspace/zeroclaw-source
git fetch origin           # upstream OGismatulin/zeroclaw-source
git checkout master
git merge origin/master    # fast-forward to include the merged PR commits

# 5. Verify the PR commits are present
git log --oneline -5
# Expected top commits include:
#   fix(observability): add missing ObservabilityConfig fields in runtime_trace test helper
#   feat(observability): Slack soft alert when turn tokens >= threshold (default 250k)
#   fix(runtime): accumulate turn-level tokens in run_tool_call_loop

# 6. Build release binary (first build ~10 min; subsequent builds ~2 min)
cargo build --release -p zeroclaw 2>&1 | tail -5
# Expected: Finished `release` profile [optimized] target(s) in Xs

# 7. Install to stable path
install -m 755 target/release/zeroclaw /usr/local/bin/zeroclaw
zeroclaw --version   # confirm it runs

# 8. If zeroclaw is a library crate with no top-level binary, find the correct target:
cargo metadata --no-deps \
  | python3 -c "import json,sys; [print(t['name']) for p in json.load(sys.stdin)['packages']
                for t in p['targets'] if 'bin' in t['kind']]"
# Then: cargo build --release --bin <name>
```

> **Note:** If both repos diverge in future, prefer the repo whose `master` has the
> latest `fix/token-accumulation-loop` commit (check `git log --oneline`).

---

## Section B — Wire Pilot Agents onto ZeroClaw

Start with **3 pilot agents** before rolling out to the full fleet.  
Recommended pilots: `testingnt69`, `testingnt7`, `boxingtool`  
(Low-risk test agents already running on the fleet; easy to verify and roll back.)

### B.1 — Create per-agent `config.toml`

Expected location for each agent's config:

```
/opt/openclaw/agents/{agent_name}/config.toml
```

Minimal viable config for a pilot agent (replace `YOUR_SLACK_WEBHOOK_URL` with the real
value from `/opt/openclaw.env` — do **not** commit the live URL to source control):

```toml
# /opt/openclaw/agents/testingnt69/config.toml
workspace_dir    = "/opt/openclaw/agents/testingnt69"
config_path      = "/opt/openclaw/agents/testingnt69/config.toml"
api_key          = "${ANTHROPIC_API_KEY}"
default_provider = "anthropic"
default_model    = "claude-sonnet-4-6"

[gateway]
port            = 0       # 0 = no HTTP gateway; headless / task-runner mode
require_pairing = false

[agent]
max_tool_iterations = 50

[memory]
backend   = "sqlite"
auto_save = true

[autonomy]
level = "supervised"

[observability]
backend               = "slack"
slack_webhook_url     = "YOUR_SLACK_WEBHOOK_URL"
token_alert_threshold = 250000
```

Create config files for all three pilots:

```bash
# Read the live webhook URL from the fleet env (never hardcode it)
WEBHOOK="$(grep -E '^SLACK_WEBHOOK_URL=' /opt/openclaw.env | cut -d= -f2-)"
# If not in openclaw.env, check sla-config-v2.json:
# WEBHOOK="$(python3 -c "import json; print(json.load(open('/opt/openclaw/services/sla-monitor/sla-config-v2.json'))['slack_webhook_url'])")"

for agent in testingnt69 testingnt7 boxingtool; do
  DIR="/opt/openclaw/agents/$agent"
  CFG="$DIR/config.toml"
  if [[ -f "$CFG" ]]; then
    echo "SKIP $agent — config.toml already exists"
    continue
  fi
  mkdir -p "$DIR"
  cat > "$CFG" <<TOML
workspace_dir    = "$DIR"
config_path      = "$CFG"
api_key          = "\${ANTHROPIC_API_KEY}"
default_provider = "anthropic"
default_model    = "claude-sonnet-4-6"

[gateway]
port            = 0
require_pairing = false

[agent]
max_tool_iterations = 50

[memory]
backend   = "sqlite"
auto_save = true

[autonomy]
level = "supervised"

[observability]
backend               = "slack"
slack_webhook_url     = "${WEBHOOK}"
token_alert_threshold = 250000
TOML
  echo "CREATED $CFG"
done
```

### B.2 — Run a pilot agent via zeroclaw

The 153 non-pilot agents continue running unchanged via `/opt/agent-router/index.js`.

```bash
# Non-interactive single-turn test (stdout only, no Slack)
ANTHROPIC_API_KEY="$(grep ANTHROPIC_API_KEY /opt/openclaw.env | cut -d= -f2)" \
  zeroclaw run \
    --config /opt/openclaw/agents/testingnt69/config.toml \
    --message "What is 2 + 2?" \
    --non-interactive

# If zeroclaw uses a serve/listen mode, start on a dedicated port:
# zeroclaw serve \
#   --config /opt/openclaw/agents/testingnt69/config.toml \
#   --port 19800
# Then update bots-slack.json to point testingnt69 at http://localhost:19800/testingnt69
```

Pilot agents on zeroclaw can coexist with the Node.js router — they use different ports and
separate config paths. Only the Slack gateway's `bots-slack.json` endpoint needs to change.

### B.3 — Update `bots-slack.json` for pilot agents

```bash
# Backup first
cp /opt/agent-router/bots-slack.json \
   /opt/agent-router/bots-slack.json.bak-zeroclaw-pilot-$(date +%Y%m%d-%H%M%S)

# Update each pilot agent's endpoint (example: testingnt69 → zeroclaw on :19800)
python3 -c "
import json
with open('/opt/agent-router/bots-slack.json') as f:
    d = json.load(f)
d['testingnt69']['endpoint'] = 'http://localhost:19800/testingnt69'
with open('/opt/agent-router/bots-slack.json', 'w') as f:
    json.dump(d, f, indent=2)
print('done')
"

# Restart gateway to pick up the change
pm2 restart slack-gateway
pm2 logs slack-gateway --lines 10 --nostream   # verify no startup errors
```

---

## Section C — Verification

### C.1 — Confirm `TurnTokenSummary` events appear in logs

```bash
# Watch the zeroclaw process logs for the new event
journalctl -u zeroclaw-testingnt69 -f 2>/dev/null \
  || tail -f /opt/openclaw/agents/testingnt69/logs/agent.log \
  | grep -E "TurnTokenSummary|turn\.token_summary"
```

Expected log line (LogObserver backend):

```
[INFO] turn.token_summary total_input_tokens=... total_output_tokens=...
```

### C.2 — Confirm Slack token alert fires above threshold

Send a prompt that will exceed 250 000 combined tokens (long conversation or large document
attachment). Monitor `#sla-alerts` for:

```
⚠️ *High token turn* — `X,XXX` in / `X,XXX` out (`Y,YYY` total ≥ 250,000 threshold)
```

To force-trigger at a low threshold without a real expensive call:

```bash
# Temporarily lower the threshold in config.toml to 1, run one turn, verify alert, reset.
sed -i 's/token_alert_threshold = 250000/token_alert_threshold = 1/' \
  /opt/openclaw/agents/testingnt69/config.toml
# ... run the agent once ...
sed -i 's/token_alert_threshold = 1/token_alert_threshold = 250000/' \
  /opt/openclaw/agents/testingnt69/config.toml
```

### C.3 — Confirm non-pilot agents are unaffected

```bash
# Send a message to any non-pilot agent (e.g., cransford) via Slack
# Verify: response arrives, cost footer format unchanged, no extra Slack alerts
pm2 logs agent-router --lines 20 --nostream | grep cransford
# Expected: normal routing log, no errors
```

### C.4 — Rollback (if pilot fails)

```bash
# Restore bots-slack.json from backup
cp /opt/agent-router/bots-slack.json.bak-zeroclaw-pilot-* \
   /opt/agent-router/bots-slack.json
pm2 restart slack-gateway

# Pilot config.toml files are harmless to leave in place;
# they are only active when zeroclaw is invoked with --config pointing at them.
```

---

## Reference

| Item | Path / URL |
|---|---|
| zeroclaw-source fork | `github.com/krispyking/zeroclaw-source` |
| zeroclaw-hindsight-v2 fork | `github.com/krispyking/zeroclaw-hindsight-v2` |
| PR #7 (source) | https://github.com/OGismatulin/zeroclaw-source/pull/7 |
| PR #9 (hindsight-v2) | https://github.com/kevin-meng/zeroclaw-hindsight-v2/pull/9 |
| Activation script | `scripts/activate-slack-observer.sh` |
| Slack webhook (live) | `/opt/openclaw.env` → `SLACK_WEBHOOK_URL` or `sla-config-v2.json` |
| Fleet agent dirs | `/opt/openclaw/agents/` (156 agents) |
| Agent-router | `/opt/agent-router/index.js` (PM2, port 18800) |
| daily-budget-monitor | PM2 id 25 |
