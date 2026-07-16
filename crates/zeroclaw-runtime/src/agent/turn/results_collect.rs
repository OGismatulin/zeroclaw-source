//! Results collection: build per-tool outputs (with receipts and truncation),
//! feed the pattern-based loop detector, and run the time-gated
//! identical-output abort.

use crate::agent::history::{
    append_or_merge_system_message, canonicalize_tool_result_media_markers_for,
    truncate_tool_result,
};
use crate::agent::loop_detector::LoopDetector;
use crate::agent::tool_execution::ToolExecutionOutcome;
use anyhow::Result;
use std::collections::HashSet;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroclaw_config::schema::PacingConfig;
use zeroclaw_providers::ChatMessage;
use zeroclaw_tool_call_parser::ParsedToolCall;

/// True only when `cmd` is a bare wait with no other side effects:
/// `python[3] -c "import time; time.sleep(N)"` (the form the runtime agent can
/// actually run) or `sleep N` (defense-in-depth; bare `sleep` is policy-blocked
/// for the agent). Anything with extra statements/commands is NOT a pure sleep,
/// so real loops around sleeps stay detectable. Deliberately does not match
/// exotic phrasings (e.g. `import time as t`) — those fall back to detection;
/// the stopgap sleep-bump keeps their frequency low. See design §4/§8.
fn is_pure_sleep_command(cmd: &str) -> bool {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r#"^\s*(sleep\s+\d+(\.\d+)?|python3?\s+-c\s+["']\s*import time\s*;\s*time\.sleep\(\s*\d+(\.\d+)?\s*\)\s*["'])\s*$"#,
        )
        .expect("static sleep-command regex is valid")
    });
    re.is_match(cmd)
}

/// A tool call that is *waiting for* async work rather than *doing* work.
/// Polling a background delegate legitimately repeats these; feeding them to
/// the loop detector would trip the circuit breaker on a healthy wait. Narrow
/// by design — real work (`delegate` action, arbitrary `shell`) still counts.
fn is_wait_poll_call(tool: &str, args: &serde_json::Value) -> bool {
    match tool {
        "delegate" => matches!(
            args.get("action").and_then(|v| v.as_str()),
            Some("check_result") | Some("list_results")
        ),
        "shell" => args
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(is_pure_sleep_command),
        _ => false,
    }
}

/// One round's collected tool results.
pub(crate) struct CollectedResults {
    /// Per-call `(tool_call_id, output)` so native-mode history can emit one
    /// `role=tool` message per call with the correct ID.
    pub(crate) individual_results: Vec<(Option<String>, String)>,
    /// XML `<tool_result>` blocks for prompt-mode history.
    pub(crate) tool_results: String,
    /// Concatenated non-ignored outputs feeding the identical-output hash.
    pub(crate) detection_relevant_output: String,
}

/// Collect this round's tool results (upstream loop body, results-collection
/// section): feed the loop detector (Warning/Block append system messages;
/// Break bails), canonicalize media markers, truncate, append receipts, and
/// build the per-call and XML result forms.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_tool_results(
    ordered_results: Vec<Option<(String, Option<String>, ToolExecutionOutcome)>>,
    tool_calls: &[ParsedToolCall],
    history: &mut Vec<ChatMessage>,
    loop_detector: &mut LoopDetector,
    loop_ignore_tools: &HashSet<&str>,
    max_tool_result_chars: usize,
    collected_receipts: Option<&Mutex<Vec<String>>>,
    model: &str,
    iteration: usize,
    turn_id: &str,
) -> Result<CollectedResults> {
    let mut tool_results = String::new();
    let mut individual_results: Vec<(Option<String>, String)> = Vec::new();
    let mut detection_relevant_output = String::new();
    // Use enumerate *before* filter_map so result_index stays aligned with
    // tool_calls even when some ordered_results entries are None.
    for (result_index, (tool_name, tool_call_id, outcome)) in ordered_results
        .into_iter()
        .enumerate()
        .filter_map(|(i, opt)| opt.map(|v| (i, v)))
    {
        // fork: bind args before the guard — needed for the wait/poll (#25)
        // exemption as well as the loop detector.
        let args = tool_calls
            .get(result_index)
            .map(|c| &c.arguments)
            .unwrap_or(&serde_json::Value::Null);
        // Skip loop detection for (a) explicitly ignored tools and (b) wait/poll
        // calls that legitimately repeat while polling a background delegate
        // (fork #25). Putting the skip on this guard also skips
        // detection_relevant_output, which is correct (a wait produced no
        // progress signal).
        if !loop_ignore_tools.contains(tool_name.as_str()) && !is_wait_poll_call(&tool_name, args) {
            // Keep failed outputs out of the hash-based identical-output abort
            // (check_identical_output_abort) too, for the same reason the
            // pattern detector below is gated: a burst of identical,
            // argument-independent error strings (rate-limit / action-budget)
            // would otherwise hash identically and hard-abort the turn — the
            // exact misfire upstream 78067a86e8 removes. Successful output still
            // feeds the hash so the #7143 productive-loop guard (identical
            // *successful* output) still aborts.
            if outcome.success {
                detection_relevant_output.push_str(&outcome.output);
            }

            // Feed the pattern-based loop detector with name + args + result —
            // but only for *successful* calls. Failed calls (e.g. rate-limit /
            // action-budget errors, not-found, permission denials) return
            // identical, path-independent error strings; counting them as
            // "no progress" (different args, identical result) escalates a
            // transient, recoverable failure into a hard turn abort and hides
            // the real cause. The detector exists to catch productive-but-stuck
            // loops — identical *successful* output (see #7143) — not walls of
            // identical errors the model can still react to.
            let det_result = if outcome.success {
                loop_detector.record(&tool_name, args, &outcome.output)
            } else {
                crate::agent::loop_detector::LoopDetectionResult::Ok
            };
            match det_result {
                crate::agent::loop_detector::LoopDetectionResult::Ok => {}
                crate::agent::loop_detector::LoopDetectionResult::Warning(ref msg) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                            .with_category(::zeroclaw_log::EventCategory::Tool)
                            .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                            .with_attrs(
                                ::serde_json::json!({"tool": tool_name, "msg": msg.to_string()})
                            ),
                        "loop detector warning"
                    );
                    append_or_merge_system_message(history, format!("[Loop Detection] {msg}"));
                }
                crate::agent::loop_detector::LoopDetectionResult::Block(ref msg) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_category(::zeroclaw_log::EventCategory::Tool)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(
                                ::serde_json::json!({"tool": tool_name, "msg": msg.to_string()})
                            ),
                        "loop detector blocked tool call"
                    );
                    // Replace the tool output with the block message.
                    // We still continue the loop so the LLM sees the block feedback.
                    append_or_merge_system_message(
                        history,
                        format!("[Loop Detection — BLOCKED] {msg}"),
                    );
                }
                crate::agent::loop_detector::LoopDetectionResult::Break(msg) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                            .with_category(::zeroclaw_log::EventCategory::Tool)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({
                                "model": model,
                                "iteration": iteration + 1,
                                "tool": tool_name,
                                "message": msg,
                                "trace_id": turn_id,
                            })),
                        "loop_detector_circuit_breaker"
                    );
                    anyhow::bail!("Agent loop aborted by loop detector: {msg}");
                }
            }
        }
        // Provenance-gated: search/listing tools (content_search, glob_search)
        // must not have incidental image paths promoted to routable [IMAGE:...]
        // markers, or they falsely trigger vision routing on a text-only
        // provider. Image-producing/fetching tools keep canonicalization.
        // See PR #7345.
        let canonical_output =
            canonicalize_tool_result_media_markers_for(&tool_name, &outcome.output);
        let mut result_output = truncate_tool_result(&canonical_output, max_tool_result_chars);
        // Append HMAC receipt to tool result when receipts are enabled
        if let Some(ref receipt) = outcome.receipt {
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_category(::zeroclaw_log::EventCategory::Tool)
                    .with_attrs(::serde_json::json!({"tool": tool_name, "receipt": receipt})),
                "Tool receipt generated"
            );
            result_output = format!("{result_output}\n\n[receipt: {receipt}]");
            if let Some(store) = collected_receipts
                && let Ok(mut v) = store.lock()
            {
                v.push(format!("{tool_name}: {receipt}"));
            }
        }
        individual_results.push((tool_call_id, result_output.clone()));
        let _ = writeln!(
            tool_results,
            "<tool_result name=\"{}\">\n{}\n</tool_result>",
            tool_name, result_output
        );
    }

    Ok(CollectedResults {
        individual_results,
        tool_results,
        detection_relevant_output,
    })
}

/// Time-gated identical-output abort (upstream loop body): when
/// `pacing.loop_detection_min_elapsed_secs` has elapsed, hash the
/// detection-relevant output and bail after 3+ consecutive identical rounds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_identical_output_abort(
    detection_relevant_output: &str,
    loop_started_at: Instant,
    pacing: &PacingConfig,
    consecutive_identical_outputs: &mut usize,
    last_tool_output_hash: &mut Option<u64>,
    model: &str,
    iteration: usize,
    turn_id: &str,
) -> Result<()> {
    // ── Time-gated loop detection ──────────────────────────
    // When pacing.loop_detection_min_elapsed_secs is set, identical-output
    // loop detection activates after the task has been running that long.
    // This avoids false-positive aborts on long-running browser/research
    // workflows while keeping aggressive protection for quick tasks.
    // When not configured, identical-output detection is disabled (preserving
    // existing behavior where only max_iterations prevents runaway loops).
    let loop_detection_active = match pacing.loop_detection_min_elapsed_secs {
        Some(min_secs) => loop_started_at.elapsed() >= Duration::from_secs(min_secs),
        None => false, // disabled when not configured (backwards compatible)
    };

    if loop_detection_active && !detection_relevant_output.is_empty() {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        detection_relevant_output.hash(&mut hasher);
        let current_hash = hasher.finish();

        if *last_tool_output_hash == Some(current_hash) {
            *consecutive_identical_outputs += 1;
        } else {
            *consecutive_identical_outputs = 0;
            *last_tool_output_hash = Some(current_hash);
        }

        // Bail if we see 3+ consecutive identical tool outputs (clear runaway).
        if *consecutive_identical_outputs >= 3 {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_category(::zeroclaw_log::EventCategory::Tool)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "model": model,
                        "iteration": iteration + 1,
                        "consecutive_identical": *consecutive_identical_outputs,
                        "trace_id": turn_id,
                    })),
                "tool_loop_identical_output_abort"
            );
            anyhow::bail!(
                "Agent loop aborted: identical tool output detected {} consecutive times",
                *consecutive_identical_outputs
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::loop_detector::LoopDetectorConfig;

    const RATE_LIMIT_ERR: &str = "Rate limit exceeded: too many actions in the last hour";

    // ── fork #25: wait-protocol loop-detector exemption ───────────────────
    #[test]
    fn pure_sleep_command_matches_only_bare_waits() {
        // reachable form (python one-liner)
        assert!(is_pure_sleep_command(
            r#"python3 -c "import time; time.sleep(30)""#
        ));
        assert!(is_pure_sleep_command(
            r#"python -c 'import time; time.sleep(120)'"#
        ));
        assert!(is_pure_sleep_command(
            "  python3 -c \"import time; time.sleep(5)\"  "
        ));
        // defense-in-depth bare sleep
        assert!(is_pure_sleep_command("sleep 30"));
        assert!(is_pure_sleep_command("sleep 0.5"));
        // NOT pure sleeps — must stay detectable
        assert!(!is_pure_sleep_command("ls"));
        assert!(!is_pure_sleep_command("rm -rf /tmp/x"));
        assert!(!is_pure_sleep_command("echo hi; sleep 5"));
        assert!(!is_pure_sleep_command("sleep 5 && do_thing"));
        assert!(!is_pure_sleep_command(
            r#"python3 -c "import os; os.system('x')""#
        ));
        assert!(!is_pure_sleep_command(
            r#"python3 -c "import time; time.sleep(5); hack()""#
        ));
    }

    #[test]
    fn wait_poll_call_covers_delegate_polls_and_sleep_only() {
        use serde_json::json;
        // delegate poll actions -> exempt
        assert!(is_wait_poll_call(
            "delegate",
            &json!({"action": "check_result", "task_id": "t1"})
        ));
        assert!(is_wait_poll_call(
            "delegate",
            &json!({"action": "list_results"})
        ));
        // delegate real work / cancel -> NOT exempt
        assert!(!is_wait_poll_call(
            "delegate",
            &json!({"action": "delegate", "agent": "coder"})
        ));
        assert!(!is_wait_poll_call(
            "delegate",
            &json!({"action": "cancel_task", "task_id": "t1"})
        ));
        assert!(!is_wait_poll_call("delegate", &json!({}))); // absent action == default "delegate"
        // shell: only pure sleeps exempt
        assert!(is_wait_poll_call(
            "shell",
            &json!({"command": r#"python3 -c "import time; time.sleep(30)""#})
        ));
        assert!(!is_wait_poll_call("shell", &json!({"command": "ls -la"})));
        // unrelated tools -> never exempt
        assert!(!is_wait_poll_call("file_read", &json!({"path": "x"})));
    }

    fn detector() -> LoopDetector {
        LoopDetector::new(crate::agent::loop_detector::LoopDetectorConfig {
            enabled: true,
            window_size: 20,
            max_repeats: 3,
        })
    }

    fn run_round(
        det: &mut LoopDetector,
        tool: &str,
        args: serde_json::Value,
        out: &str,
    ) -> anyhow::Result<()> {
        let call = ParsedToolCall {
            name: tool.to_string(),
            arguments: args,
            tool_call_id: None,
        };
        let outcome = ToolExecutionOutcome {
            output: out.to_string(),
            output_data: None,
            success: true,
            error_reason: None,
            duration: std::time::Duration::from_secs(0),
            receipt: None,
        };
        let ordered = vec![Some((tool.to_string(), Some("id".to_string()), outcome))];
        let mut history = Vec::new();
        let ignore: HashSet<&str> = HashSet::new();
        collect_tool_results(
            ordered,
            std::slice::from_ref(&call),
            &mut history,
            det,
            &ignore,
            8192,
            None,
            "test-model",
            0,
            "test-turn",
        )
        .map(|_| ())
    }

    #[test]
    fn polling_a_delegate_does_not_trip_the_circuit_breaker() {
        let mut det = detector();
        for _ in 0..8 {
            run_round(
                &mut det,
                "delegate",
                serde_json::json!({"action": "check_result", "task_id": "t1"}),
                "(no output)",
            )
            .expect("poll must never bail");
            run_round(
                &mut det,
                "shell",
                serde_json::json!({"command": r#"python3 -c "import time; time.sleep(30)""#}),
                "(no output)",
            )
            .expect("sleep must never bail");
        }
    }

    #[test]
    fn a_real_identical_result_loop_still_breaks() {
        let mut det = detector();
        let mut bailed = false;
        for i in 0..8 {
            // real work: shell with a non-sleep command, DIFFERENT args each
            // round, IDENTICAL output -> detect_no_progress must fire.
            let r = run_round(
                &mut det,
                "shell",
                serde_json::json!({"command": format!("ls /x/{i}")}),
                "same output",
            );
            if r.is_err() {
                bailed = true;
                break;
            }
        }
        assert!(
            bailed,
            "real no-progress loop must still trip the circuit breaker"
        );
    }

    // ── upstream 78067a86e8: failed tool results are not no-progress ──────
    fn outcome(output: &str, success: bool) -> ToolExecutionOutcome {
        ToolExecutionOutcome {
            output: output.to_string(),
            success,
            error_reason: if success {
                None
            } else {
                Some(output.to_string())
            },
            duration: Duration::from_millis(1),
            receipt: None,
            output_data: None,
        }
    }

    /// Run one results-collection pass over `n` `file_read` calls that each use
    /// different args but return an identical `output` string, with the given
    /// `success` flag.
    fn run(n: usize, output: &str, success: bool) -> Result<CollectedResults> {
        let mut detector = LoopDetector::new(LoopDetectorConfig::default());
        let ignore: HashSet<&str> = HashSet::new();
        let mut history: Vec<ChatMessage> = Vec::new();
        let mut tool_calls: Vec<ParsedToolCall> = Vec::new();
        let mut ordered: Vec<Option<(String, Option<String>, ToolExecutionOutcome)>> = Vec::new();
        for i in 0..n {
            tool_calls.push(ParsedToolCall {
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": format!("file_{i}.rs") }),
                tool_call_id: None,
            });
            ordered.push(Some((
                "file_read".to_string(),
                None,
                outcome(output, success),
            )));
        }
        collect_tool_results(
            ordered,
            &tool_calls,
            &mut history,
            &mut detector,
            &ignore,
            10_000,
            None,
            "test-model",
            0,
            "turn-test",
        )
    }

    #[test]
    fn failed_tool_results_do_not_trip_no_progress_breaker() {
        // Many failed reads (different paths, identical rate-limit error) must
        // NOT abort the turn: a recoverable rate-limit/budget error is not a
        // "no progress" exploration loop. Regression for the circuit breaker
        // firing on `file_read` "called N times ... identical results".
        assert!(run(8, RATE_LIMIT_ERR, false).is_ok());
    }

    #[test]
    fn successful_identical_results_still_trip_no_progress_breaker() {
        // Identical *successful* output across different args is the genuine
        // stuck-loop signal (#7143) and must still hard-abort the turn.
        let err = match run(8, "byte-identical successful output", true) {
            Ok(_) => panic!("expected the no-progress circuit breaker to abort the turn"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("loop detector"), "got: {err}");
    }

    /// Drive the *hash-based* identical-output abort
    /// (`check_identical_output_abort`) directly, with loop detection ACTIVE
    /// (pacing configured + elapsed), over `n` iterations whose `file_read`
    /// calls each use different args but return an identical `output` with the
    /// given `success` flag. Mirrors `run`, but exercises the *second*
    /// loop-detection mechanism (the hash path) rather than the pattern
    /// detector.
    fn run_hash_path(n: usize, output: &str, success: bool) -> Result<()> {
        // `Some(0)` => loop detection active immediately (`elapsed() >= 0s`).
        let pacing = PacingConfig {
            loop_detection_min_elapsed_secs: Some(0),
            ..PacingConfig::default()
        };
        let loop_started_at = Instant::now();
        let mut consecutive_identical_outputs = 0usize;
        let mut last_tool_output_hash: Option<u64> = None;
        let mut detector = LoopDetector::new(LoopDetectorConfig::default());
        let ignore: HashSet<&str> = HashSet::new();
        for iteration in 0..n {
            let mut history: Vec<ChatMessage> = Vec::new();
            let tool_calls = vec![ParsedToolCall {
                name: "file_read".to_string(),
                arguments: serde_json::json!({ "path": format!("file_{iteration}.rs") }),
                tool_call_id: None,
            }];
            let ordered = vec![Some((
                "file_read".to_string(),
                None,
                outcome(output, success),
            ))];
            let collected = collect_tool_results(
                ordered,
                &tool_calls,
                &mut history,
                &mut detector,
                &ignore,
                10_000,
                None,
                "test-model",
                iteration,
                "turn-test",
            )?;
            check_identical_output_abort(
                &collected.detection_relevant_output,
                loop_started_at,
                &pacing,
                &mut consecutive_identical_outputs,
                &mut last_tool_output_hash,
                "test-model",
                iteration,
                "turn-test",
            )?;
        }
        Ok(())
    }

    #[test]
    fn failed_identical_outputs_do_not_trip_hash_based_abort() {
        // The *other* loop-detection mechanism: with loop detection active
        // (pacing configured + elapsed), a wall of identical *failed* outputs
        // must not trip the hash-based `check_identical_output_abort`. Gating
        // `detection_relevant_output` on `outcome.success` keeps failures out
        // of the hash entirely, so the breaker never fires. Without the gate
        // this aborts at the third identical failure.
        assert!(run_hash_path(8, RATE_LIMIT_ERR, false).is_ok());
    }
}
