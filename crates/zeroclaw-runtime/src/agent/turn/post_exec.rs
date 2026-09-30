//! Post-execution recording: result log line, the `after_tool_call` hook, the
//! completion Status, and filling the executed calls' `ordered_results` slots.

use super::context::TurnCtx;
use super::events::StreamDelta;
use super::redact::scrub_credentials;
use crate::agent::tool_execution::ToolExecutionOutcome;
use crate::util::truncate_with_ellipsis;
use zeroclaw_tool_call_parser::ParsedToolCall;

/// Record each executed tool call's outcome (upstream loop body,
/// post-execution section): one `tool_call_result` log line, the
/// `after_tool_call` hook, a completion Status to the draft, and the
/// call's slot in `ordered_results`.
pub(crate) async fn record_executed_outcomes(
    ctx: &TurnCtx<'_>,
    executable_indices: &[usize],
    executable_calls: &[ParsedToolCall],
    executed_outcomes: Vec<ToolExecutionOutcome>,
    ordered_results: &mut [Option<(String, Option<String>, ToolExecutionOutcome)>],
    iteration: usize,
) {
    for ((idx, call), outcome) in executable_indices
        .iter()
        .zip(executable_calls.iter())
        .zip(executed_outcomes)
    {
        // The pending ToolCall and terminal ToolResult are emitted by the
        // executor (execute_one_tool) at dispatch and completion time so serial
        // batches interleave call->result per tool. Post-exec only records the
        // outcome to history, logs, hooks, and ordered_results.

        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Complete)
                .with_category(::zeroclaw_log::EventCategory::Tool)
                .with_outcome(if outcome.success {
                    ::zeroclaw_log::EventOutcome::Success
                } else {
                    ::zeroclaw_log::EventOutcome::Failure
                })
                .with_duration(u64::try_from(outcome.duration.as_millis()).unwrap_or(u64::MAX))
                .with_attrs(::serde_json::json!({
                    "model": ctx.model,
                    "iteration": iteration + 1,
                    "tool": call.name.clone(),
                    "tool_call_id": call.tool_call_id.clone(),
                    "tool_diagnostic": tool_diagnostic(&outcome),
                    "error_reason": outcome.error_reason.as_deref().map(scrub_credentials),
                    "output": scrub_credentials(&outcome.output),
                    "trace_id": ctx.turn_id,
                })),
            "tool_call_result"
        );

        // ── Hook: after_tool_call (void) ─────────────────
        if let Some(hooks) = ctx.hooks {
            let tool_result_obj = crate::tools::ToolResult {
                success: outcome.success,
                output: outcome.output.clone().into(),
                error: None,
            };
            hooks
                .fire_after_tool_call(&call.name, &tool_result_obj, outcome.duration)
                .await;
        }

        // ── Progress: tool completion ───────────────────────
        if let Some(tx) = ctx.on_delta {
            let secs = outcome.duration.as_secs();
            let progress_msg = render_completion_progress(
                &call.name,
                secs,
                outcome.success,
                outcome.error_reason.as_deref(),
            );
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_category(::zeroclaw_log::EventCategory::Tool)
                    .with_attrs(::serde_json::json!({"tool": call.name, "secs": secs})),
                "Sending progress complete to draft"
            );
            let _ = tx.send(StreamDelta::Status(progress_msg)).await;
        }

        // Capture into the innermost live SOP step scope (no-op otherwise).
        if crate::sop::executor::step_capture_active() {
            crate::sop::executor::record_step_tool_call(
                &call.name,
                &call.arguments,
                outcome.success,
                outcome.output.clone(),
                outcome.output_data.clone(),
                outcome.error_reason.as_deref(),
                u64::try_from(outcome.duration.as_millis()).unwrap_or(u64::MAX),
            );
        }

        ordered_results[*idx] = Some((call.name.clone(), call.tool_call_id.clone(), outcome));
    }
}

const TOOL_DIAGNOSTIC_KEYS: [&str; 8] = [
    "status",
    "policy_reason",
    "blocked_command",
    "path",
    "completed",
    "pending",
    "missing",
    "failed",
];

fn tool_diagnostic(outcome: &ToolExecutionOutcome) -> Option<serde_json::Value> {
    if outcome.success {
        return None;
    }
    let map = outcome.output_data.as_ref()?.as_object()?;
    let projected: serde_json::Map<String, serde_json::Value> = map
        .iter()
        .filter(|(key, _)| TOOL_DIAGNOSTIC_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), scrub_diagnostic_value(value)))
        .collect();
    if projected.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(projected))
    }
}

fn scrub_diagnostic_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(scrub_credentials(text)),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(scrub_diagnostic_value).collect())
        }
        other => other.clone(),
    }
}

/// Build the CLI completion-progress line. Failure text is scrubbed here
/// because the progress channel is a human-facing rendering surface; the
/// source `error_reason` carries raw bytes on the data path.
fn render_completion_progress(
    tool: &str,
    secs: u64,
    success: bool,
    error_reason: Option<&str>,
) -> String {
    if success {
        format!("\u{2705} {tool} ({secs}s)\n")
    } else if let Some(reason) = error_reason {
        format!(
            "\u{274c} {tool} ({secs}s): {}\n",
            truncate_with_ellipsis(&scrub_credentials(reason), 200)
        )
    } else {
        format!("\u{274c} {tool} ({secs}s)\n")
    }
}

#[cfg(test)]
mod tests {
    use super::render_completion_progress;

    #[test]
    fn completion_progress_scrubs_credential_error_reason() {
        let line = render_completion_progress(
            "config_read",
            2,
            false,
            Some("api_key = \"sk-live-abcd1234efgh5678\""),
        );
        assert!(
            line.contains("[REDACTED]"),
            "expected scrubbed line: {line}"
        );
        assert!(
            !line.contains("abcd1234efgh5678"),
            "raw secret leaked: {line}"
        );
    }

    #[test]
    fn completion_progress_success_has_no_error_text() {
        let line = render_completion_progress("echo", 0, true, None);
        assert!(line.starts_with('\u{2705}'));
        assert!(!line.contains(':'));
    }
}
