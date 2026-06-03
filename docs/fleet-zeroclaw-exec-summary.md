# Fleet Change Log — ZeroClaw Token Accounting + SlackObserver

**Date:** 2026-05-30  
**Branch:** `krispyking:fix/token-accumulation-loop` (both fork repos)  
**Session log:** Notion CRC-085, CRC-088

---

## What Is Done and Stable

- **Token accumulator fix** is committed, tested, and pushed. `run_tool_call_loop` now sums
  `input_tokens` / `output_tokens` across every LLM call in a turn and emits a single
  `TurnTokenSummary` event at both exit paths. All 26+ agents will show true cumulative
  per-turn token spend once the runtime is deployed.

- **`SlackObserver`** is implemented in `crates/zeroclaw-runtime/src/observability/slack.rs`
  with 14 unit tests and a passing doctest. It fires a webhook POST when combined turn tokens
  hit a configurable threshold (default 250 000). Zero-cost to opt out: `token_alert_threshold = 0`
  or simply don't set `backend = "slack"` in config.

- **Config schema** in `zeroclaw-config` has two new fields with safe defaults:
  `slack_webhook_url: Option<String>` (default `None`) and `token_alert_threshold: u64`
  (default `250_000`). No existing agent or config is affected.

- **`cargo test` is green:** 1 647 passed · 0 failed · 1 ignored. Includes all new
  `observability::slack` tests and the `runtime_trace.rs` test helper fix.

- **Activation script** (`scripts/activate-slack-observer.sh`) is hardened, shellcheck-clean,
  and committed. Reads the Slack webhook from `$SLACK_WEBHOOK_URL` (no hardcoded secret).
  Handles duplicate backend keys, sed portability, permission errors, and integer validation.

- **Owner nudge comments** are live on both upstream PRs:
  - https://github.com/OGismatulin/zeroclaw-source/pull/7
  - https://github.com/kevin-meng/zeroclaw-hindsight-v2/pull/9

- **daily-budget-monitor** (PM2 id 25) is the sole cost alerting service. Healthy: online,
  ~25 h uptime, 3 clean restarts, no instability.

---

## What Is Blocked and By Whom

Both PRs are open and awaiting review by the upstream owners:

| Repo | PR | Owner | Status |
|---|---|---|---|
| OGismatulin/zeroclaw-source | #7 | @OGismatulin | Open, no review |
| kevin-meng/zeroclaw-hindsight-v2 | #9 | @kevin-meng | Open, MERGEABLE |

Until these merge, **no zeroclaw-runtime binary exists on the fleet**. The 156 agents all run
on the Node.js agent-router (`/opt/agent-router/index.js`). The `TurnTokenSummary` events,
SlackObserver alerts, and improved `in / out` token footer are inactive.

---

## Exact Next Steps Once PRs Are Merged

1. **Build:** `cd ~/.openclaw/workspace/zeroclaw-source && cargo build --release -p zeroclaw`
2. **Install:** `install -m 755 target/release/zeroclaw /usr/local/bin/zeroclaw`
3. **Pilot config:** create `config.toml` for `testingnt69`, `testingnt7`, `boxingtool` under
   `/opt/openclaw/agents/{name}/` (see `docs/fleet-zeroclaw-deploy-runbook.md` §B.1 for the
   exact template — webhook is read from `$SLACK_WEBHOOK_URL` in `/opt/openclaw.env`).
4. **Activate:** `SLACK_WEBHOOK_URL="$(grep SLACK_WEBHOOK_URL /opt/openclaw.env | cut -d= -f2)" \
   bash scripts/activate-slack-observer.sh /opt/openclaw/agents`
5. **Verify:** check for `turn.token_summary` in logs and a test Slack alert in `#sla-alerts`.
6. **Roll out** to remaining 153 agents once pilots are confirmed healthy.

See `docs/fleet-zeroclaw-deploy-runbook.md` for the full step-by-step with rollback instructions.

---

## Files Changed (for Fleet Change Log)

| File | Change |
|---|---|
| `crates/zeroclaw-api/src/observability_traits.rs` | New `TurnTokenSummary` variant |
| `crates/zeroclaw-runtime/src/agent/loop_.rs` | Token accumulators + `TurnTokenSummary` emit |
| `crates/zeroclaw-runtime/src/observability/log.rs` | `TurnTokenSummary` match arm |
| `crates/zeroclaw-runtime/src/observability/verbose.rs` | `TurnTokenSummary` match arm |
| `crates/zeroclaw-runtime/src/observability/otel.rs` | OR-pattern arm |
| `crates/zeroclaw-runtime/src/observability/prometheus.rs` | OR-pattern arm |
| `crates/zeroclaw-runtime/src/observability/slack.rs` | **NEW** — `SlackObserver` + 14 tests |
| `crates/zeroclaw-config/src/schema.rs` | Two new `ObservabilityConfig` fields |
| `crates/zeroclaw-runtime/src/observability/mod.rs` | `pub mod slack`, factory arm |
| `crates/zeroclaw-runtime/src/observability/runtime_trace.rs` | Test helper fix |
| `scripts/activate-slack-observer.sh` | **NEW** — fleet activation script |
| `docs/fleet-zeroclaw-deploy-runbook.md` | **NEW** — this runbook |
| `docs/fleet-zeroclaw-exec-summary.md` | **NEW** — this summary |
