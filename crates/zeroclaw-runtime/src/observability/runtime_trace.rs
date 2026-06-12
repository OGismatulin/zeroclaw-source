//! Compatibility shim for the doctor command's log-reading utilities, plus
//! the fork's legacy positional-arg `record_event` emission surface.
//!
//! Upstream retired `record_event` in favor of direct `zeroclaw_log::record!`
//! invocations with the new ECS-flavored `LogEvent` schema. This fork keeps
//! the legacy emitter alongside the new shim because external consumers parse
//! the legacy JSONL shape (`event_type` / `timestamp` / `payload`) from
//! `runtime-trace.jsonl`:
//!
//! - `scripts/gateway_manager.py` ProgressNotifier watchdog reads our
//!   `context_state` events (`tokens_before`, `context_window`, `percent`,
//!   `passes`, `session_id`),
//! - the nightly-retrospective skill's `extract_day.py`,
//! - the prompt-trace tooling.
//!
//! New-format lines written by `zeroclaw_log` and legacy lines written here
//! coexist in the same file: the `zeroclaw_log` reader skips lines that fail
//! `LogEvent` parse, rolling rotation on both sides is line-count based, and
//! `migrate_legacy_jsonl_in_place` only fires when the FIRST line of the file
//! is legacy-shaped (one-shot conversion of pre-merge history).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use chrono::{Local, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zeroclaw_log::LogEvent;

pub use zeroclaw_log::{LogEvent as RuntimeTraceEvent, LogFilter, LogPage};

fn to_log_config(config: &zeroclaw_config::schema::ObservabilityConfig) -> zeroclaw_log::LogConfig {
    zeroclaw_log::LogConfig {
        log_persistence: config.log_persistence.clone(),
        log_persistence_path: config.log_persistence_path.clone(),
        log_persistence_max_entries: config.log_persistence_max_entries,
        log_tool_io: config.log_tool_io.clone(),
        log_tool_io_truncate_bytes: config.log_tool_io_truncate_bytes,
        log_tool_io_denylist: config.log_tool_io_denylist.clone(),
    }
}

/// Initialize log persistence from the observability config.
///
/// Fork: also installs the legacy trace logger so `record_event` /
/// `record_turn_cancelled` keep appending legacy-shape lines to the same
/// JSONL file.
pub fn init_from_config(
    config: &zeroclaw_config::schema::ObservabilityConfig,
    workspace_dir: &Path,
) {
    zeroclaw_log::init_from_config(&to_log_config(config), workspace_dir);

    let mode = LegacyStorageMode::from_raw(&config.log_persistence);
    let path = resolve_trace_path(config, workspace_dir);
    let logger = match mode {
        LegacyStorageMode::None => None,
        _ => Some(Arc::new(LegacyTraceLogger::new(
            mode,
            config.log_persistence_max_entries,
            path,
        ))),
    };
    let mut guard = TRACE_LOGGER.write().unwrap_or_else(|e| e.into_inner());
    *guard = logger;
}

/// Resolve the configured log path (used by the doctor command).
pub fn resolve_trace_path(
    config: &zeroclaw_config::schema::ObservabilityConfig,
    workspace_dir: &Path,
) -> std::path::PathBuf {
    let policy = zeroclaw_log::ResolvedPolicy::from_config(&to_log_config(config), workspace_dir);
    policy.path
}

/// Load a page of events. Replaces the old `load_events` shape with a
/// thin wrapper around the new paginated reader. The legacy
/// `event_filter` (single action match) and `contains` (substring) args
/// map straight onto the new [`LogFilter`] fields.
pub fn load_events(
    path: &Path,
    limit: usize,
    event_filter: Option<&str>,
    contains: Option<&str>,
) -> anyhow::Result<Vec<LogEvent>> {
    let filter = LogFilter {
        action: event_filter.map(str::to_string),
        q: contains.map(str::to_string),
        ..LogFilter::default()
    };
    let page = zeroclaw_log::load_page(path, &filter, limit)?;
    Ok(page.events)
}

/// Lookup a single event by id.
pub fn find_event_by_id(path: &Path, id: &str) -> anyhow::Result<Option<LogEvent>> {
    zeroclaw_log::find_event_by_id(path, id)
}

// ---------------------------------------------------------------------------
// Fork: legacy trace emitter (see module docs).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyStorageMode {
    None,
    Rolling,
    Full,
}

impl LegacyStorageMode {
    fn from_raw(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "rolling" => Self::Rolling,
            "full" => Self::Full,
            _ => Self::None,
        }
    }
}

/// Legacy-shape trace event. Field set and serialization MUST stay
/// byte-compatible with the pre-v0.8.0 `RuntimeTraceEvent`: external Python
/// consumers parse these exact keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyTraceEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

struct LegacyTraceLogger {
    mode: LegacyStorageMode,
    max_entries: usize,
    path: PathBuf,
    write_lock: std::sync::Mutex<()>,
}

impl LegacyTraceLogger {
    fn new(mode: LegacyStorageMode, max_entries: usize, path: PathBuf) -> Self {
        Self {
            mode,
            max_entries: max_entries.max(1),
            path,
            write_lock: std::sync::Mutex::new(()),
        }
    }

    fn append(&self, event: &LegacyTraceEvent) -> anyhow::Result<()> {
        if self.mode == LegacyStorageMode::None {
            return Ok(());
        }

        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(event)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&self.path)?;
        writeln!(file, "{line}")?;
        file.sync_data()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }

        if self.mode == LegacyStorageMode::Rolling {
            self.trim_to_last_entries()?;
        }

        Ok(())
    }

    fn trim_to_last_entries(&self) -> anyhow::Result<()> {
        let raw = fs::read_to_string(&self.path).unwrap_or_default();
        let lines: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();

        if lines.len() <= self.max_entries {
            return Ok(());
        }

        let keep_from = lines.len().saturating_sub(self.max_entries);
        let kept = &lines[keep_from..];
        let mut rewritten = kept.join("\n");
        rewritten.push('\n');

        let tmp = self.path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::write(&tmp, rewritten)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }

        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

static TRACE_LOGGER: LazyLock<RwLock<Option<Arc<LegacyTraceLogger>>>> =
    LazyLock::new(|| RwLock::new(None));

/// Record a runtime trace event in the legacy JSONL shape.
pub fn record_event(
    event_type: &str,
    channel: Option<&str>,
    provider: Option<&str>,
    model: Option<&str>,
    turn_id: Option<&str>,
    success: Option<bool>,
    message: Option<&str>,
    payload: Value,
) {
    let logger = TRACE_LOGGER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(logger) = logger else {
        return;
    };

    let event = LegacyTraceEvent {
        id: Uuid::new_v4().to_string(),
        timestamp: Local::now().to_rfc3339(),
        event_type: event_type.to_string(),
        channel: channel.map(str::to_string),
        provider: provider.map(str::to_string),
        model: model.map(str::to_string),
        turn_id: turn_id.map(str::to_string),
        success,
        message: message.map(str::to_string),
        payload,
    };

    if let Err(err) = logger.append(&event) {
        tracing::warn!("Failed to write runtime trace event: {err}");
    }
}

/// Record a "turn cancelled" trace event from the gateway webhook path.
///
/// `iterations_completed` and `tool_calls_executed` are best-effort counters;
/// the current `run_tool_call_loop` does not return them, so MVP callers may
/// pass 0. The fields are reserved in the trace payload for future plumbing.
pub fn record_turn_cancelled(
    session_id: &str,
    iterations_completed: u32,
    tool_calls_executed: u32,
    reason: &str,
) {
    record_event(
        "turn_cancelled",
        None,
        None,
        None,
        None,
        None,
        None,
        serde_json::json!({
            "session_id": session_id,
            "iterations_completed": iterations_completed,
            "tool_calls_executed": tool_calls_executed,
            "reason": reason,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_config::schema::ObservabilityConfig;

    fn test_observability_config(dir: &Path) -> ObservabilityConfig {
        ObservabilityConfig {
            log_persistence: "rolling".to_string(),
            log_persistence_path: dir
                .join("trace.jsonl")
                .to_string_lossy()
                .into_owned(),
            log_persistence_max_entries: 2,
            ..ObservabilityConfig::default()
        }
    }

    #[test]
    fn legacy_record_event_writes_legacy_shape_and_rolls() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_observability_config(tmp.path());
        init_from_config(&cfg, tmp.path());

        for i in 0..4 {
            record_event(
                "context_state",
                Some("webhook"),
                Some("opencode-go"),
                Some("deepseek-v4-flash"),
                None,
                Some(true),
                None,
                serde_json::json!({ "i": i, "tokens_before": 100 + i }),
            );
        }

        let raw = std::fs::read_to_string(tmp.path().join("trace.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "rolling mode keeps last max_entries lines");

        let last: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(last["event_type"], "context_state");
        assert_eq!(last["channel"], "webhook");
        assert_eq!(last["payload"]["tokens_before"], 103);
        assert!(last["timestamp"].is_string(), "legacy key is `timestamp`");
        assert!(
            last.get("@timestamp").is_none(),
            "must NOT be the new LogEvent shape"
        );
    }
}
