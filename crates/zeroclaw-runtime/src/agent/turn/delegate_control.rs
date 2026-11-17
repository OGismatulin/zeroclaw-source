//! Invocation-local context compaction and work-deadline control for agentic delegates.

use super::context::TurnCtx;
use super::execution::ResolvedModelAccess;
use super::max_iter::FinalizationReason;
use super::outcome::ToolLoopCancelled;
use crate::agent::context_compressor::{
    ContextCompressor, DelegateCompressionCalibration, estimate_tokens,
};
use crate::tools::ToolSpec;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zeroclaw_api::observability_traits::ObserverEvent;
use zeroclaw_config::scattered_types::ContextCompressionConfig;
use zeroclaw_providers::ChatMessage;

#[derive(Debug, Clone)]
pub struct DelegateRunControl {
    pub started_at: tokio::time::Instant,
    pub hard_deadline: tokio::time::Instant,
    pub work_deadline: tokio::time::Instant,
    pub compression: Arc<ContextCompressionConfig>,
    pub fallback_context_window: usize,
    pub history_pruning_max_tokens: Option<usize>,
}

impl DelegateRunControl {
    #[must_use]
    pub fn new(
        total_timeout: Duration,
        started_at: tokio::time::Instant,
        compression: ContextCompressionConfig,
        fallback_context_window: usize,
        history_pruning_max_tokens: Option<usize>,
    ) -> Self {
        let hard_deadline = started_at + total_timeout;
        let reserve = Duration::from_secs(300).min(total_timeout / 4);
        let work_deadline = hard_deadline.checked_sub(reserve).unwrap_or(started_at);
        Self {
            started_at,
            hard_deadline,
            work_deadline,
            compression: Arc::new(compression),
            fallback_context_window,
            history_pruning_max_tokens,
        }
    }

    #[must_use]
    pub fn context_window_for_model(&self, model: &str) -> usize {
        self.compression
            .model_windows
            .get(model)
            .copied()
            .filter(|window| *window > 0)
            .unwrap_or(self.fallback_context_window)
    }

    #[must_use]
    pub fn threshold_for_model(&self, model: &str) -> usize {
        let window = self.context_window_for_model(model);
        let ratio = self.compression.threshold_ratio;
        let mut threshold = if ratio > 0.0 && ratio < 1.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ((window as f64) * ratio).round() as usize
            }
        } else {
            window
        };
        if let Some(cap) = self.history_pruning_max_tokens
            && cap > 0
        {
            threshold = threshold.min(cap);
        }
        threshold.max(1)
    }

    #[must_use]
    pub fn is_work_deadline_reached(&self) -> bool {
        tokio::time::Instant::now() >= self.work_deadline
    }

    #[must_use]
    pub fn remaining_work_time(&self) -> Duration {
        self.work_deadline
            .saturating_duration_since(tokio::time::Instant::now())
    }

    #[must_use]
    pub(crate) fn work_deadline_reason(&self) -> FinalizationReason {
        let now = tokio::time::Instant::now();
        FinalizationReason::WorkDeadline {
            elapsed_secs: now.saturating_duration_since(self.started_at).as_secs(),
            reserve_secs: self
                .hard_deadline
                .saturating_duration_since(self.work_deadline)
                .as_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RequestPopulationSnapshot {
    snapshot_total_est: usize,
    tools_est: usize,
    media_overhead_tokens: usize,
}

impl RequestPopulationSnapshot {
    pub(crate) fn snapshot_request(
        raw_history: &[ChatMessage],
        prepared_messages: &[ChatMessage],
        request_tools: Option<&[ToolSpec]>,
    ) -> Self {
        let raw_history_est = estimate_tokens(raw_history);
        let prepared_messages_est = estimate_tokens(prepared_messages);
        let tools_est = estimate_tool_specs_tokens(request_tools);
        let media_overhead_tokens = prepared_messages_est.saturating_sub(raw_history_est);
        let snapshot_total_est = prepared_messages_est.saturating_add(tools_est);
        Self {
            snapshot_total_est,
            tools_est,
            media_overhead_tokens,
        }
    }

    pub(crate) fn build_calibration(
        &self,
        reported_input_tokens: Option<u64>,
    ) -> DelegateCompressionCalibration {
        let scale = match reported_input_tokens {
            Some(reported) if reported > 0 && self.snapshot_total_est > 0 => {
                (reported as f64) / (self.snapshot_total_est as f64)
            }
            _ => 1.0,
        };
        DelegateCompressionCalibration {
            scale,
            tools_tokens: self.tools_est,
            media_overhead_tokens: self.media_overhead_tokens,
        }
    }
}

fn estimate_tool_specs_tokens(request_tools: Option<&[ToolSpec]>) -> usize {
    let Some(specs) = request_tools.filter(|s| !s.is_empty()) else {
        return 0;
    };
    let serialized_bytes = serde_json::to_string(specs).map_or(0, |s| s.len());
    if serialized_bytes == 0 {
        return 0;
    }
    let raw = serialized_bytes.div_ceil(4) + 4;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (raw as f64 * 1.2) as usize
    }
}

pub(crate) enum PostRoundAction {
    Continue,
    Finalize(FinalizationReason),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn maintain_context_after_round(
    history: &mut Vec<ChatMessage>,
    control: &DelegateRunControl,
    model_access: &ResolvedModelAccess<'_>,
    snapshot: Option<&RequestPopulationSnapshot>,
    reported_input_tokens: Option<u64>,
    cancellation_token: Option<&CancellationToken>,
    ctx: &TurnCtx<'_>,
    iteration: usize,
) -> Result<PostRoundAction> {
    if cancellation_token.is_some_and(CancellationToken::is_cancelled) {
        return Err(ToolLoopCancelled.into());
    }

    if control.is_work_deadline_reached() {
        return Ok(PostRoundAction::Finalize(control.work_deadline_reason()));
    }

    let calibration = snapshot.map_or_else(DelegateCompressionCalibration::default, |snap| {
        snap.build_calibration(reported_input_tokens)
    });
    let context_window = control.context_window_for_model(model_access.model);
    let threshold = control.threshold_for_model(model_access.model);
    let tokens_before = calibration.estimate(history);
    if tokens_before <= threshold {
        return Ok(PostRoundAction::Continue);
    }

    if !control.compression.enabled {
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_category(::zeroclaw_log::EventCategory::Agent)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({
                    "target_agent": ctx.agent_alias,
                    "model": model_access.model,
                    "iteration": iteration + 1,
                    "reason": "context_pressure",
                    "outcome": "compression_disabled",
                    "tokens_before": tokens_before,
                    "threshold": threshold,
                    "context_window": context_window,
                    "trace_id": ctx.turn_id,
                })),
            "delegate_context_maintenance"
        );
        return Ok(PostRoundAction::Finalize(
            FinalizationReason::ContextPressure {
                tokens: tokens_before,
                threshold,
            },
        ));
    }

    let remaining_work = control.remaining_work_time();
    let max_budget = Duration::from_secs(control.compression.timeout_secs).min(remaining_work);
    if max_budget.is_zero() {
        return Ok(PostRoundAction::Finalize(control.work_deadline_reason()));
    }

    let started = tokio::time::Instant::now();
    let mut candidate = history.clone();
    let compressor = ContextCompressor::new((*control.compression).clone(), context_window);
    let outcome = compressor
        .compress_for_delegate(
            &mut candidate,
            threshold,
            model_access,
            &calibration,
            max_budget,
            cancellation_token,
        )
        .await?;

    if cancellation_token.is_some_and(CancellationToken::is_cancelled) {
        return Err(ToolLoopCancelled.into());
    }

    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status_label = if outcome.fits_threshold {
        "compressed"
    } else if outcome.made_progress {
        "still_over_threshold"
    } else {
        "no_progress"
    };

    if outcome.made_progress {
        let dropped_messages = history.len().saturating_sub(candidate.len());
        *history = candidate;
        let reason_label = if outcome.used_fallback_excerpt {
            "delegate_context_fallback_excerpt"
        } else {
            "delegate_context_compacted"
        };
        ctx.observer.record_event(&ObserverEvent::HistoryTrimmed {
            dropped_messages,
            kept_turns: 1,
            reason: reason_label.to_string(),
            channel: Some(ctx.channel_name.to_string()),
            agent_alias: ctx.agent_alias.map(str::to_string),
            turn_id: Some(ctx.turn_id.to_string()),
        });
    }

    ::zeroclaw_log::record!(
        INFO,
        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
            .with_category(::zeroclaw_log::EventCategory::Agent)
            .with_outcome(::zeroclaw_log::EventOutcome::Success)
            .with_duration(elapsed_ms)
            .with_attrs(::serde_json::json!({
                "target_agent": ctx.agent_alias,
                "model": model_access.model,
                "iteration": iteration + 1,
                "reason": "context_pressure",
                "outcome": status_label,
                "tokens_before": outcome.tokens_before,
                "tokens_after": outcome.tokens_after,
                "threshold": threshold,
                "context_window": context_window,
                "passes_used": outcome.passes_used,
                "fast_trimmed_chars": outcome.fast_trimmed_chars,
                "emergency_trimmed_chars": outcome.emergency_trimmed_chars,
                "used_fallback_excerpt": outcome.used_fallback_excerpt,
                "fallback_reason": outcome.fallback_reason,
                "elapsed_ms": elapsed_ms,
                "trace_id": ctx.turn_id,
            })),
        "delegate_context_maintenance"
    );

    if control.is_work_deadline_reached() {
        return Ok(PostRoundAction::Finalize(control.work_deadline_reason()));
    }

    if !outcome.fits_threshold || !outcome.made_progress {
        return Ok(PostRoundAction::Finalize(
            FinalizationReason::ContextPressure {
                tokens: outcome.tokens_after,
                threshold,
            },
        ));
    }

    Ok(PostRoundAction::Continue)
}
