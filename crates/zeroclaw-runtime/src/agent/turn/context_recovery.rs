//! LLM-failure recording and in-loop context-overflow recovery.

use super::context::TurnCtx;
use super::outcome::is_tool_loop_cancelled;
use crate::agent::history::estimate_history_tokens;
use crate::agent::history_trim::trim_to_recent_turns;
use crate::observability::{Observer, ObserverEvent};
use std::time::Instant;
use zeroclaw_providers::ChatMessage;

/// Record a failed provider call: observer `LlmResponse` (failure) and the
/// `llm_response` failure log line.
pub(crate) fn record_llm_failure(
    ctx: &TurnCtx<'_>,
    llm_started_at: Instant,
    iteration: usize,
    e: &anyhow::Error,
) {
    // User cancellation gets the fixed message the streaming consumers have
    // always seen (and pin), never a raw error string.
    let safe_error = if is_tool_loop_cancelled(e) {
        "request cancelled by user".to_string()
    } else {
        zeroclaw_providers::sanitize_api_error(&e.to_string())
    };
    ctx.observer.record_event(&ObserverEvent::LlmResponse {
        model_provider: ctx.provider_name.to_string(),
        model: ctx.model.to_string(),
        duration: llm_started_at.elapsed(),
        success: false,
        error_message: Some(safe_error.clone()),
        input_tokens: None,
        output_tokens: None,
        channel: Some(ctx.channel_name.to_string()),
        agent_alias: ctx.agent_alias.map(|s| s.to_string()),
        turn_id: Some(ctx.turn_id.to_string()),
        // Error path: no prompt/completion content captured.
        messages: None,
    });
    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
            .with_category(::zeroclaw_log::EventCategory::Provider)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
            .with_duration(u64::try_from(llm_started_at.elapsed().as_millis()).unwrap_or(u64::MAX))
            .with_attrs(::serde_json::json!({
                "model": ctx.model,
                "iteration": iteration + 1,
                "error": safe_error,
                "trace_id": ctx.turn_id,
            })),
        "llm_response"
    );
}

/// Config slice for the emergency tool-result retrim fallback in
/// `try_recover_context_overflow`. Built by the caller; the current turn-loop
/// caller uses `ContextCompressionConfig` serde defaults because the resolved
/// config is unreachable in the `turn/` module (plan Task 0). Post-turn
/// compaction still honors user overrides; this recovery path uses defaults.
pub(crate) struct ToolRetrimParams {
    pub retrim_chars: usize,
    pub protect_first_n: usize,
    pub emergency_protect_last_n: usize,
    pub exempt: Vec<String>,
}

/// Context overflow recovery: trim history and retry.
///
/// Returns `true` when the history was trimmed and the caller should
/// `continue` the loop; the orchestrator keeps
/// `if recovered { continue; } return Err(e);` inline.
///
/// Emits `TurnEvent::HistoryTrimmed` and `ObserverEvent::HistoryTrimmed` on the
/// trimmed branch so the 400-recovery cut is never silent to ACP / WS / SSE
/// subscribers, matching the preemptive turn-boundary path.
pub(crate) async fn try_recover_context_overflow(
    history: &mut Vec<ChatMessage>,
    e: &anyhow::Error,
    iteration: usize,
    event_tx: Option<&tokio::sync::mpsc::Sender<zeroclaw_api::agent::TurnEvent>>,
    observer: &dyn Observer,
    context_token_budget: usize,
    tool_retrim: &ToolRetrimParams,
) -> bool {
    if zeroclaw_providers::reliable::is_context_window_exceeded(e) {
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Retry)
                .with_category(::zeroclaw_log::EventCategory::Agent)
                .with_attrs(::serde_json::json!({"iteration": iteration + 1})),
            "Context window exceeded, attempting in-loop recovery"
        );

        // One rule: drop oldest whole turns until we are under a budget
        // forced below the current size. Never splits a tool_use/tool_result
        // pair, never silently shrinks a result. Whole turns or nothing.
        let tokens_now = estimate_history_tokens(history);
        let budget = tokens_now.saturating_mul(2) / 3;
        let owned = std::mem::take(history);
        let result = trim_to_recent_turns(owned, budget);
        let trimmed = result.trimmed;
        let dropped_turns = result.dropped_turns;
        let dropped_messages = result.dropped_messages;
        let kept_turns = result.kept_turns;
        let tokens_after = result.tokens_after;
        let mut recovered_history = result.history;
        if trimmed {
            // Insert the same model-visible breadcrumb the turn-boundary path
            // uses, after the leading system messages, so the retried provider
            // call tells the model earlier turns were dropped (never silent to
            // the model, not just to clients).
            let system_count = recovered_history
                .iter()
                .take_while(|m| m.role == "system")
                .count();
            recovered_history.insert(system_count, crate::agent::history_trim::breadcrumb());
        }
        *history = recovered_history;
        if trimmed {
            ::zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Retry)
                    .with_category(::zeroclaw_log::EventCategory::Agent)
                    .with_attrs(::serde_json::json!({
                        "dropped_turns": dropped_turns,
                        "dropped_messages": dropped_messages,
                        "tokens_before": tokens_now,
                        "tokens_after": tokens_after,
                    })),
                "Context recovery: dropped oldest whole turns, retrying"
            );
            let reason = crate::i18n::get_required_cli_string("history-trim-reason-budget");
            if let Some(tx) = event_tx {
                let _ = tx
                    .send(zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                        dropped_messages,
                        kept_turns,
                        reason: reason.clone(),
                    })
                    .await;
            }
            observer.record_event(&ObserverEvent::HistoryTrimmed {
                dropped_messages,
                kept_turns,
                reason,
                channel: None,
                agent_alias: None,
                turn_id: None,
            });
            return true;
        }

        // Whole-turn dropping yielded nothing (e.g. a single turn whose oversized
        // tool results dominate). Before declaring unrecoverable, escalate an
        // emergency tool-result retrim on the surviving history, reusing the same
        // truncation the post-turn compaction uses (fork-patch #31).
        let tokens_before_retrim = estimate_history_tokens(history);
        let mut retrim_saved = 0usize;
        let mut protect = tool_retrim.emergency_protect_last_n;
        loop {
            retrim_saved += crate::agent::history_trim::trim_oversized_tool_results_in_range(
                history,
                tool_retrim.retrim_chars,
                tool_retrim.protect_first_n,
                protect,
                &tool_retrim.exempt,
            );
            if estimate_history_tokens(history) <= budget || protect == 0 {
                break;
            }
            protect -= 1;
        }
        if retrim_saved > 0 && estimate_history_tokens(history) < tokens_before_retrim {
            // Dedup breadcrumb (unlike the raw .insert() on the whole-turn path
            // above): repeated retrim recoveries in one turn must not stack crumbs.
            // The two branches never fire in the same call.
            crate::agent::history_trim::insert_breadcrumb_deduped(history);
            let tokens_after_retrim = estimate_history_tokens(history);
            ::zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Retry)
                    .with_category(::zeroclaw_log::EventCategory::Agent)
                    .with_attrs(::serde_json::json!({
                        "retrim_saved": retrim_saved,
                        "tokens_before": tokens_before_retrim,
                        "tokens_after": tokens_after_retrim,
                        "budget": budget,
                    })),
                "Context recovery: retrimmed oversized tool results, retrying"
            );
            let reason = crate::i18n::get_required_cli_string("history-trim-reason-budget");
            if let Some(tx) = event_tx {
                let _ = tx
                    .send(zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                        dropped_messages: 0,
                        kept_turns,
                        reason: reason.clone(),
                    })
                    .await;
            }
            observer.record_event(&ObserverEvent::HistoryTrimmed {
                dropped_messages: 0,
                kept_turns,
                reason,
                channel: None,
                agent_alias: None,
                turn_id: None,
            });
            return true;
        }

        // Nothing left to trim — truly unrecoverable. When the system prompt +
        // inlined tool definitions alone dominate the budget, the single
        // remaining turn can never fit no matter how much history is dropped;
        // surface the actionable root cause and remedy instead of a generic
        // unrecoverable error (#5808).
        // Gate on the resolved effective budget (the same `N` the message
        // displays), not the local 2/3-of-current recovery budget — otherwise a
        // provider whose real window is below the configured budget could fire a
        // message stating floor >= N while numerically floor < N. The recovery
        // trim above still uses the local `budget`; only the remediation
        // predicate and the displayed value key on the resolved budget (#5808).
        let system_floor = crate::agent::history::estimate_system_floor_tokens(history);
        if system_floor >= context_token_budget {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_category(::zeroclaw_log::EventCategory::Agent)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "system_floor": system_floor,
                        "budget": context_token_budget,
                        "error_key": "context_floor_exceeds_budget",
                    })),
                crate::agent::history::context_floor_remediation(
                    system_floor,
                    context_token_budget,
                )
            );
        } else {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_category(::zeroclaw_log::EventCategory::Agent)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                "Context overflow unrecoverable: only one turn left, cannot trim further"
            );
        }
    }
    false
}

/// Shape of one assistant history entry — diagnostics only, never content.
///
/// Returns `(has_reasoning, has_tool_calls, content_kind)`.
fn assistant_shape(content: &str) -> (bool, bool, &'static str) {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(value) if value.is_object() => (
            value.get("reasoning_content").is_some() || value.get("reasoning").is_some(),
            value.get("tool_calls").is_some(),
            "json",
        ),
        _ if content.trim().is_empty() => (false, false, "empty"),
        _ => (false, false, "text"),
    }
}

/// Reasoning-round-trip recovery (fork patch #33).
///
/// Thinking-mode providers reject a request whose previous assistant turn lost
/// its `reasoning_content` ("The `reasoning_content` in the thinking mode must be
/// passed back to the API"). The lost value cannot be reconstructed — it is gone
/// from the history by the time the rejection arrives, or the model never sent
/// one — so the repair drops that single plain assistant turn and retries.
///
/// The candidate is the last assistant entry carrying neither reasoning nor
/// `tool_calls`: plain text that no `role=tool` message references, so removing
/// it cannot orphan a tool_call/tool pair. At most one repair per turn
/// (`repaired`), otherwise a persistently broken history would spin the loop.
///
/// Returns `true` when the caller should `continue` the loop.
pub(crate) async fn try_recover_reasoning_roundtrip(
    history: &mut Vec<ChatMessage>,
    e: &anyhow::Error,
    iteration: usize,
    repaired: &mut bool,
    ctx: &TurnCtx<'_>,
) -> bool {
    if !zeroclaw_providers::reliable::is_reasoning_roundtrip_rejected(e) {
        return false;
    }

    // Diagnostics first, and unconditionally: the shape of the last assistant
    // messages is the only way the NEXT occurrence is provable. `runtime-trace`
    // is a rolling window and daemon-stderr at floor=warn carries no request
    // shapes, so the incident window is gone before anyone looks. Shape only —
    // no message content, no credentials.
    let shapes: Vec<serde_json::Value> = history
        .iter()
        .enumerate()
        .filter(|(_, message)| message.role == "assistant")
        .rev()
        .take(5)
        .map(|(index, message)| {
            let (has_reasoning, has_tool_calls, content_kind) = assistant_shape(&message.content);
            ::serde_json::json!({
                "index": index,
                "has_reasoning": has_reasoning,
                "has_tool_calls": has_tool_calls,
                "content_kind": content_kind,
            })
        })
        .collect();

    let candidate = history.iter().rposition(|message| {
        message.role == "assistant" && {
            let (has_reasoning, has_tool_calls, _) = assistant_shape(&message.content);
            !has_reasoning && !has_tool_calls
        }
    });
    let repair_index = candidate.filter(|_| !*repaired);

    ::zeroclaw_log::record!(
        WARN,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_category(::zeroclaw_log::EventCategory::Provider)
            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
            .with_attrs(::serde_json::json!({
                "model": ctx.model,
                "iteration": iteration + 1,
                "repaired": repair_index.is_some(),
                "already_repaired_this_turn": *repaired,
                "assistant_shapes": shapes,
                // Attribution: one daemon runs the coordinator and every
                // delegate, so without these the event cannot be tied to the
                // turn that produced it.
                "agent_alias": ctx.agent_alias,
                "trace_id": ctx.turn_id,
            })),
        "reasoning_roundtrip_rejected"
    );

    let Some(index) = repair_index else {
        return false;
    };
    history.remove(index);
    *repaired = true;

    let reason = crate::i18n::get_required_cli_string("history-trim-reason-reasoning-roundtrip");
    if let Some(tx) = ctx.event_tx {
        let _ = tx
            .send(zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                dropped_messages: 1,
                kept_turns: 0,
                reason: reason.clone(),
            })
            .await;
    }
    ctx.observer.record_event(&ObserverEvent::HistoryTrimmed {
        dropped_messages: 1,
        kept_turns: 0,
        reason,
        channel: Some(ctx.channel_name.to_string()),
        agent_alias: ctx.agent_alias.map(ToString::to_string),
        turn_id: Some(ctx.turn_id.to_string()),
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::NoopObserver;
    use zeroclaw_providers::ChatMessage;

    fn overflowing_history() -> Vec<ChatMessage> {
        let big = "x".repeat(4000);
        let mut h = vec![ChatMessage::system("system")];
        for i in 0..6 {
            h.push(ChatMessage::user(format!("turn {i} {big}").as_str()));
            h.push(ChatMessage::assistant(format!("reply {i} {big}").as_str()));
        }
        h
    }

    /// Minimal `TurnCtx` for the repair tests: only observer/model/turn_id/
    /// event_tx are read by the code under test.
    fn repair_ctx<'a>(
        pacing: &'a zeroclaw_config::schema::PacingConfig,
        dedup_exempt_tools: &'a [String],
        event_tx: Option<&'a tokio::sync::mpsc::Sender<zeroclaw_api::agent::TurnEvent>>,
    ) -> TurnCtx<'a> {
        TurnCtx {
            observer: &NoopObserver,
            provider_name: "deepseek",
            model: "deepseek-v4-pro",
            temperature: None,
            approval: None,
            channel_name: "test-channel",
            channel_reply_target: None,
            cancellation_token: None,
            on_delta: None,
            event_tx,
            hooks: None,
            dedup_exempt_tools,
            pacing,
            strict_tool_parsing: false,
            channel: None,
            turn_id: "turn-roundtrip-test",
            agent_alias: Some("analyst_deepseek_pro"),
        }
    }

    fn roundtrip_error() -> anyhow::Error {
        anyhow::Error::msg(
            r#"DeepSeek API error (400 Bad Request): {"error":{"message":"The `reasoning_content` in the thinking mode must be passed back to the API.","type":"invalid_request_error"}}"#,
        )
    }

    // Fork patch #33: a plain-text assistant turn is what the thinking provider
    // rejects; dropping it is the only available repair (the lost reasoning cannot
    // be reconstructed) and it cannot orphan a tool_call/tool pair.
    #[tokio::test]
    async fn drops_last_plain_assistant_turn_and_retries() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let mut history = vec![
            ChatMessage::system("system"),
            ChatMessage::user("u1"),
            ChatMessage::assistant("plain text turn"),
            ChatMessage::user("u2"),
        ];
        let mut repaired = false;
        let recovered = try_recover_reasoning_roundtrip(
            &mut history,
            &roundtrip_error(),
            3,
            &mut repaired,
            &repair_ctx(&pacing, &dedup_exempt_tools, None),
        )
        .await;

        assert!(recovered, "the turn must be retried after the repair");
        assert!(repaired, "the per-turn repair budget must be consumed");
        assert_eq!(history.len(), 3);
        assert!(
            history.iter().all(|m| m.content != "plain text turn"),
            "the offending assistant turn must be gone"
        );
    }

    #[tokio::test]
    async fn repairs_at_most_once_per_turn() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let mut history = vec![
            ChatMessage::user("u"),
            ChatMessage::assistant("a1"),
            ChatMessage::assistant("a2"),
        ];
        let mut repaired = true; // already repaired earlier in this same turn
        let recovered = try_recover_reasoning_roundtrip(
            &mut history,
            &roundtrip_error(),
            4,
            &mut repaired,
            &repair_ctx(&pacing, &dedup_exempt_tools, None),
        )
        .await;

        assert!(!recovered, "a second repair in one turn would risk a loop");
        assert_eq!(history.len(), 3, "history must be untouched");
    }

    #[tokio::test]
    async fn no_candidate_means_no_repair() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let mut history = vec![
            ChatMessage::user("u"),
            ChatMessage::assistant(
                r#"{"content":"x","tool_calls":[{"id":"1","name":"t","arguments":"{}"}]}"#,
            ),
            ChatMessage::assistant(r#"{"content":"y","reasoning_content":"r"}"#),
        ];
        let mut repaired = false;
        let recovered = try_recover_reasoning_roundtrip(
            &mut history,
            &roundtrip_error(),
            5,
            &mut repaired,
            &repair_ctx(&pacing, &dedup_exempt_tools, None),
        )
        .await;

        assert!(
            !recovered,
            "nothing to repair: every assistant turn is well formed"
        );
        assert!(!repaired);
        assert_eq!(history.len(), 3);
    }

    #[tokio::test]
    async fn ignores_other_error_classes() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let mut history = vec![ChatMessage::user("u"), ChatMessage::assistant("a")];
        let mut repaired = false;
        let err =
            anyhow::Error::msg("API error (400 Bad Request): maximum context length exceeded");
        let recovered = try_recover_reasoning_roundtrip(
            &mut history,
            &err,
            6,
            &mut repaired,
            &repair_ctx(&pacing, &dedup_exempt_tools, None),
        )
        .await;

        assert!(
            !recovered,
            "context-window failures belong to the other recovery"
        );
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn repair_emits_history_trimmed_event_with_its_own_reason() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let mut history = vec![ChatMessage::user("u"), ChatMessage::assistant("plain")];
        let mut repaired = false;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        assert!(
            try_recover_reasoning_roundtrip(
                &mut history,
                &roundtrip_error(),
                7,
                &mut repaired,
                &repair_ctx(&pacing, &dedup_exempt_tools, Some(&tx)),
            )
            .await
        );

        match rx
            .try_recv()
            .expect("repair must not be silent to subscribers")
        {
            zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                dropped_messages,
                reason,
                ..
            } => {
                assert_eq!(dropped_messages, 1);
                assert_eq!(
                    reason,
                    crate::i18n::get_required_cli_string("history-trim-reason-reasoning-roundtrip")
                );
            }
            other => panic!("expected HistoryTrimmed, got {other:?}"),
        }
    }

    // G13: the emitted record itself must be attributable (model, trace_id,
    // agent_alias) and must carry SHAPE only — never message content. Asserting
    // on the helper alone would not prove what actually lands in the log.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn diagnostic_record_carries_attribution_and_no_message_content() {
        let pacing = zeroclaw_config::schema::PacingConfig::default();
        let dedup_exempt_tools: Vec<String> = Vec::new();
        let secret_prose = "SENSITIVE-ASSISTANT-PROSE-42";
        let mut history = vec![ChatMessage::user("u"), ChatMessage::assistant(secret_prose)];
        let mut repaired = false;

        let _writer_guard = zeroclaw_log::__private_test_writer_lock();
        let _hook_guard = zeroclaw_log::__private_test_hook_lock();
        zeroclaw_log::try_install_capture_subscriber();
        let mut log_rx = zeroclaw_log::subscribe_or_install();
        while log_rx.try_recv().is_ok() {}

        assert!(
            try_recover_reasoning_roundtrip(
                &mut history,
                &roundtrip_error(),
                7,
                &mut repaired,
                &repair_ctx(&pacing, &dedup_exempt_tools, None),
            )
            .await
        );

        let mut record: Option<serde_json::Value> = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while record.is_none() && std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let step = remaining.min(std::time::Duration::from_millis(50));
            match tokio::time::timeout(step, log_rx.recv()).await {
                Ok(Ok(value)) => {
                    if value.get("message").and_then(|v| v.as_str())
                        == Some("reasoning_roundtrip_rejected")
                    {
                        record = Some(value);
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                Err(_elapsed) => {}
            }
        }
        let record = record.expect("no reasoning_roundtrip_rejected record observed");
        let attrs = record
            .get("attributes")
            .expect("record must carry attributes");
        assert_eq!(
            attrs.get("model").and_then(|v| v.as_str()),
            Some("deepseek-v4-pro")
        );
        assert_eq!(
            attrs.get("trace_id").and_then(|v| v.as_str()),
            Some("turn-roundtrip-test")
        );
        assert_eq!(
            attrs.get("agent_alias").and_then(|v| v.as_str()),
            Some("analyst_deepseek_pro")
        );
        assert_eq!(attrs.get("repaired").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(attrs.get("iteration").and_then(|v| v.as_u64()), Some(8));
        let shapes = attrs
            .get("assistant_shapes")
            .and_then(|v| v.as_array())
            .expect("shapes array");
        assert_eq!(shapes.len(), 1);
        assert_eq!(
            shapes[0].get("content_kind").and_then(|v| v.as_str()),
            Some("text")
        );
        assert_eq!(
            shapes[0].get("has_reasoning").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            shapes[0].get("has_tool_calls").and_then(|v| v.as_bool()),
            Some(false)
        );

        let serialized = record.to_string();
        assert!(
            !serialized.contains(secret_prose),
            "the diagnostic record must never carry message content: {serialized}"
        );

        zeroclaw_log::clear_broadcast_hook();
    }

    #[test]
    fn assistant_shape_classifies_history_forms_without_leaking_content() {
        assert_eq!(assistant_shape("plain text"), (false, false, "text"));
        assert_eq!(assistant_shape("   "), (false, false, "empty"));
        assert_eq!(
            assistant_shape(r#"{"content":"x","reasoning_content":"r"}"#),
            (true, false, "json")
        );
        assert_eq!(
            assistant_shape(r#"{"content":"x","reasoning":"r"}"#),
            (true, false, "json")
        );
        assert_eq!(
            assistant_shape(r#"{"content":null,"tool_calls":[{"id":"1"}]}"#),
            (false, true, "json")
        );
    }

    #[tokio::test]
    async fn recovery_emits_history_trimmed_event_on_trim() {
        let mut history = overflowing_history();
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            Some(&tx),
            &observer,
            32_000,
            &ToolRetrimParams {
                retrim_chars: 2000,
                protect_first_n: 3,
                emergency_protect_last_n: 2,
                exempt: vec![],
            },
        )
        .await;

        assert!(recovered, "an overflowing history must trim and recover");
        // The retried history must carry the model-visible breadcrumb after the
        // leading system messages, matching the turn-boundary contract.
        let breadcrumb_text = crate::i18n::get_required_cli_string("history-trim-breadcrumb");
        assert!(
            history.iter().any(|m| m.content == breadcrumb_text),
            "recovery must insert the breadcrumb so the model sees the trim"
        );
        let event = rx.try_recv().expect("recovery must emit a TurnEvent");
        match event {
            zeroclaw_api::agent::TurnEvent::HistoryTrimmed {
                dropped_messages,
                kept_turns,
                reason,
            } => {
                assert!(dropped_messages > 0, "must report dropped messages");
                assert!(kept_turns >= 1, "must keep at least the current turn");
                assert_eq!(
                    reason,
                    crate::i18n::get_required_cli_string("history-trim-reason-budget")
                );
            }
            other => panic!("expected HistoryTrimmed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn floor_exceeds_budget_single_turn_does_not_recover() {
        // #5808 regression: the system prompt + tool definitions alone dominate
        // the budget and only one turn exists. Recovery must NOT loop — it
        // returns false (nothing left to drop) so the caller breaks instead of
        // re-running the same turn forever.
        let big = "x".repeat(8000);
        let mut history = vec![
            ChatMessage::system(format!("system {big}").as_str()),
            ChatMessage::user("only turn"),
            ChatMessage::assistant("reply"),
        ];
        let err = anyhow::Error::msg("maximum context length exceeded");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            Some(&tx),
            &observer,
            100,
            &ToolRetrimParams {
                retrim_chars: 2000,
                protect_first_n: 3,
                emergency_protect_last_n: 2,
                exempt: vec![],
            },
        )
        .await;

        assert!(
            !recovered,
            "single-turn floor overflow must not retry (no #5808 loop)"
        );
        assert!(
            rx.try_recv().is_err(),
            "no trim event when nothing can be dropped"
        );
        // The system floor must dominate the recovery budget — this is what
        // makes the new remediation branch fire.
        assert!(
            crate::agent::history::estimate_system_floor_tokens(&history)
                >= estimate_history_tokens(&history) * 2 / 3,
            "system floor should dominate the recovery budget in the #5808 case"
        );
    }

    #[tokio::test]
    async fn non_overflow_error_is_not_recovered_and_emits_nothing() {
        let mut history = overflowing_history();
        let err = anyhow::Error::msg("some unrelated provider error");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let observer = NoopObserver;

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            Some(&tx),
            &observer,
            32_000,
            &ToolRetrimParams {
                retrim_chars: 2000,
                protect_first_n: 3,
                emergency_protect_last_n: 2,
                exempt: vec![],
            },
        )
        .await;

        assert!(!recovered, "a non-overflow error must not trigger recovery");
        assert!(rx.try_recv().is_err(), "no event on the non-overflow path");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn floor_exceeds_budget_emits_event_with_resolved_budget_and_remediation() {
        // Serialize against the broadcast-hook tests for the whole test: we drive
        // `record!` -> LogCaptureLayer -> broadcast hook, and a parallel
        // `clear_broadcast_hook` would otherwise drop our event.
        let _hook_guard = zeroclaw_log::__private_test_hook_lock();
        zeroclaw_log::try_install_capture_subscriber();
        let mut rx = zeroclaw_log::subscribe_or_install();

        // System prompt + tool definitions dominate; a single turn means nothing
        // can be trimmed, so the floor-dominates-budget remediation branch fires.
        let big = "x".repeat(8000);
        let mut history = vec![
            ChatMessage::system(format!("system {big}").as_str()),
            ChatMessage::user("only turn"),
            ChatMessage::assistant("reply"),
        ];
        let err = anyhow::Error::msg("maximum context length exceeded");
        let observer = NoopObserver;
        let budget = 100usize;

        // Drain any pre-existing broadcast traffic from parallel tests.
        while rx.try_recv().is_ok() {}

        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            None,
            &observer,
            budget,
            &ToolRetrimParams {
                retrim_chars: 2000,
                protect_first_n: 3,
                emergency_protect_last_n: 2,
                exempt: vec![],
            },
        )
        .await;
        assert!(!recovered, "floor-dominates overflow must not recover");

        // Read the emitted `context_floor_exceeds_budget` record within a 2s
        // deadline, tolerating `Lagged` from parallel broadcast traffic.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let record = loop {
            if std::time::Instant::now() >= deadline {
                panic!("did not observe the context_floor_exceeds_budget record in time");
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let step = remaining.min(std::time::Duration::from_millis(50));
            match tokio::time::timeout(step, rx.recv()).await {
                Ok(Ok(value)) => {
                    if value
                        .get("attributes")
                        .and_then(|a| a.get("error_key"))
                        .and_then(|v| v.as_str())
                        == Some("context_floor_exceeds_budget")
                    {
                        break value;
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    panic!("broadcast closed before the record arrived")
                }
                Err(_elapsed) => {}
            }
        };

        let attrs = record.get("attributes").expect("record carries attributes");
        // The recorded budget is the RESOLVED budget passed in, not the local
        // 2/3-of-current recovery budget.
        assert_eq!(
            attrs.get("budget").and_then(|v| v.as_u64()),
            Some(budget as u64),
            "emitted budget must be the resolved effective budget"
        );
        assert!(
            attrs.get("system_floor").and_then(|v| v.as_u64()).unwrap() >= budget as u64,
            "system_floor must meet or exceed the resolved budget in this branch"
        );
        // The visible message names the resolved budget and the runtime-profile
        // surface, and never the inert agent.max_context_tokens wording.
        let message = record
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            message.contains("100"),
            "remediation message must name the resolved budget: {message}"
        );
        assert!(
            message.contains("[runtime_profiles"),
            "remediation message must name the runtime-profile surface: {message}"
        );
        assert!(
            !message.contains("agent.max_context_tokens"),
            "remediation message must not reference the inert knob: {message}"
        );

        zeroclaw_log::clear_broadcast_hook();
    }

    // Test 1 (terra-replay): ONE turn dominated by oversized role=="tool"; whole-turn drop
    // can't drop the last turn (trimmed==false) → tool-retrim fallback truncates → true.
    #[tokio::test]
    async fn recovery_retrims_tool_results_when_no_turns_to_drop() {
        let observer = NoopObserver;
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let big = "X".repeat(60_000);
        let mut history = vec![
            ChatMessage::system("sys"),
            ChatMessage::user("go"),
            ChatMessage::tool(big.clone()),
            ChatMessage::tool(big.clone()),
        ];
        let params = ToolRetrimParams {
            retrim_chars: 100,
            protect_first_n: 1,
            emergency_protect_last_n: 1,
            exempt: vec![],
        };
        let err = anyhow::Error::msg("maximum context length exceeded");
        let before = estimate_history_tokens(&history);
        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            Some(&tx),
            &observer,
            1_000_000,
            &params,
        )
        .await;
        assert!(recovered, "tool-retrim fallback must recover");
        assert!(estimate_history_tokens(&history) < before, "tokens dropped");
        let crumb = crate::i18n::get_required_cli_string("history-trim-breadcrumb");
        assert!(
            history.iter().any(|m| m.content.contains(&crumb)),
            "breadcrumb inserted"
        );
    }

    // Test 2 (assistant-bloat residual): mass in role=="assistant" → saved==0 → false,
    // unrecoverable still (no regression).
    #[tokio::test]
    async fn recovery_no_retrim_on_assistant_bloat() {
        let observer = NoopObserver;
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let big = "X".repeat(60_000);
        let mut history = vec![
            ChatMessage::system("sys"),
            ChatMessage::user("go"),
            ChatMessage::assistant(big.clone()),
        ];
        let params = ToolRetrimParams {
            retrim_chars: 100,
            protect_first_n: 1,
            emergency_protect_last_n: 1,
            exempt: vec![],
        };
        let err = anyhow::Error::msg("maximum context length exceeded");
        let recovered =
            try_recover_context_overflow(&mut history, &err, 1, Some(&tx), &observer, 100, &params)
                .await;
        assert!(!recovered, "no tool to trim → unrecoverable");
        assert_eq!(history[2].content.len(), 60_000, "assistant untouched");
    }

    // Test 3 (multi-turn no-change): several turns → whole-turn drop fires, fallback not reached.
    #[tokio::test]
    async fn recovery_multi_turn_still_drops_whole_turns() {
        let observer = NoopObserver;
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut history = overflowing_history(); // existing helper in this test module
        let params = ToolRetrimParams {
            retrim_chars: 100,
            protect_first_n: 1,
            emergency_protect_last_n: 1,
            exempt: vec![],
        };
        let err = anyhow::Error::msg("maximum context length exceeded");
        let recovered = try_recover_context_overflow(
            &mut history,
            &err,
            1,
            Some(&tx),
            &observer,
            32_000,
            &params,
        )
        .await;
        assert!(recovered, "whole-turn drop recovers as before");
    }
}
