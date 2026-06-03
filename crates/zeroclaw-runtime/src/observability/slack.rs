use super::traits::{Observer, ObserverEvent, ObserverMetric};
use std::any::Any;

/// Slack webhook observer — fires a warning message when a single turn
/// consumes tokens at or above the configured threshold.
///
/// Uses an incoming-webhook URL so no bot token is required.  The HTTP call
/// is dispatched on a dedicated OS thread so `record_event` never blocks the
/// caller (important: `reqwest::blocking` must not be invoked directly inside
/// an async tokio context).
pub struct SlackObserver {
    webhook_url: String,
    threshold: u64,
}

impl SlackObserver {
    /// Create a new `SlackObserver`.
    ///
    /// # Arguments
    /// * `webhook_url` – Slack incoming-webhook URL.
    /// * `threshold`   – Combined (input + output) token count that triggers
    ///                   an alert.  Pass `0` to disable all alerts.
    pub fn new(webhook_url: impl Into<String>, threshold: u64) -> Self {
        Self {
            webhook_url: webhook_url.into(),
            threshold,
        }
    }
}

/// Format a `u64` with comma separators every three digits.
///
/// ```
/// # use zeroclaw_runtime::observability::slack::fmt_tokens;
/// assert_eq!(fmt_tokens(0),         "0");
/// assert_eq!(fmt_tokens(999),       "999");
/// assert_eq!(fmt_tokens(1_000),     "1,000");
/// assert_eq!(fmt_tokens(1_234_567), "1,234,567");
/// ```
pub fn fmt_tokens(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    // How many digits land in the first (possibly short) group.
    let first_group = match len % 3 {
        0 => 3,
        r => r,
    };
    let mut out = String::with_capacity(len + (len - 1) / 3);
    // Safety: all bytes are ASCII decimal digits → valid UTF-8.
    out.push_str(std::str::from_utf8(&bytes[..first_group]).unwrap_or_default());
    for chunk in bytes[first_group..].chunks(3) {
        out.push(',');
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

impl Observer for SlackObserver {
    fn record_event(&self, event: &ObserverEvent) {
        let ObserverEvent::TurnTokenSummary {
            total_input_tokens,
            total_output_tokens,
        } = event
        else {
            return;
        };

        // Zero threshold means the alert is disabled.
        if self.threshold == 0 {
            return;
        }

        let total = total_input_tokens.saturating_add(*total_output_tokens);
        if total < self.threshold {
            return;
        }

        let in_fmt = fmt_tokens(*total_input_tokens);
        let out_fmt = fmt_tokens(*total_output_tokens);
        let total_fmt = fmt_tokens(total);
        let threshold_fmt = fmt_tokens(self.threshold);

        let text = format!(
            "\u{26a0}\u{fe0f} *High token turn* \u{2014} `{in_fmt}` in / `{out_fmt}` out \
             (`{total_fmt}` total \u{2265} {threshold_fmt} threshold)"
        );

        let webhook_url = self.webhook_url.clone();
        std::thread::spawn(move || {
            let body = serde_json::json!({ "text": text });
            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("SlackObserver: failed to build HTTP client: {e}");
                    return;
                }
            };
            match client.post(&webhook_url).json(&body).send() {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    tracing::warn!(
                        status = resp.status().as_u16(),
                        "SlackObserver: webhook POST returned non-success"
                    );
                }
                Err(e) => {
                    tracing::warn!("SlackObserver: webhook POST failed: {e}");
                }
            }
        });
    }

    #[inline(always)]
    fn record_metric(&self, _metric: &ObserverMetric) {}

    fn name(&self) -> &str {
        "slack"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── fmt_tokens ────────────────────────────────────────────────────────────

    #[test]
    fn fmt_tokens_zero() {
        assert_eq!(fmt_tokens(0), "0");
    }

    #[test]
    fn fmt_tokens_one_digit() {
        assert_eq!(fmt_tokens(7), "7");
    }

    #[test]
    fn fmt_tokens_three_digits() {
        assert_eq!(fmt_tokens(999), "999");
    }

    #[test]
    fn fmt_tokens_four_digits() {
        assert_eq!(fmt_tokens(1_000), "1,000");
    }

    #[test]
    fn fmt_tokens_six_digits() {
        assert_eq!(fmt_tokens(123_456), "123,456");
    }

    #[test]
    fn fmt_tokens_seven_digits() {
        assert_eq!(fmt_tokens(1_234_567), "1,234,567");
    }

    #[test]
    fn fmt_tokens_exact_millions() {
        assert_eq!(fmt_tokens(1_000_000), "1,000,000");
    }

    #[test]
    fn fmt_tokens_max() {
        assert_eq!(fmt_tokens(u64::MAX), "18,446,744,073,709,551,615");
    }

    // ── SlackObserver basics ──────────────────────────────────────────────────

    #[test]
    fn slack_observer_name() {
        let obs = SlackObserver::new("https://hooks.slack.com/services/test", 250_000);
        assert_eq!(obs.name(), "slack");
    }

    #[test]
    fn slack_observer_ignores_non_summary_events() {
        let obs = SlackObserver::new("https://hooks.slack.com/services/test", 250_000);
        // None of these should panic or attempt an HTTP call.
        obs.record_event(&ObserverEvent::TurnComplete);
        obs.record_event(&ObserverEvent::HeartbeatTick);
        obs.record_event(&ObserverEvent::AgentStart {
            provider: "openrouter".into(),
            model: "claude".into(),
        });
    }

    #[test]
    fn slack_observer_record_metric_no_panic() {
        let obs = SlackObserver::new("https://hooks.slack.com/services/test", 250_000);
        obs.record_metric(&ObserverMetric::TokensUsed(9_999_999));
    }

    #[test]
    fn slack_observer_below_threshold_no_panic() {
        let obs = SlackObserver::new("https://hooks.slack.com/services/test", 250_000);
        // 100k in + 50k out = 150k < 250k → no HTTP call, no panic.
        obs.record_event(&ObserverEvent::TurnTokenSummary {
            total_input_tokens: 100_000,
            total_output_tokens: 50_000,
        });
    }

    #[test]
    fn slack_observer_zero_threshold_disabled_no_panic() {
        // threshold=0 means disabled — even 1M tokens must not fire.
        let obs = SlackObserver::new("https://hooks.slack.com/services/test", 0);
        obs.record_event(&ObserverEvent::TurnTokenSummary {
            total_input_tokens: 1_000_000,
            total_output_tokens: 1_000_000,
        });
    }

    #[test]
    fn slack_observer_at_threshold_attempts_post() {
        // Exactly at threshold: should spawn a thread and attempt the POST.
        // The URL is intentionally bogus so the thread fails silently (no panic).
        let obs = SlackObserver::new("https://127.0.0.1:0/nonexistent", 250_000);
        obs.record_event(&ObserverEvent::TurnTokenSummary {
            total_input_tokens: 200_000,
            total_output_tokens: 50_000, // total = 250_000 == threshold
        });
        // Give the background thread a moment to finish so the test process
        // doesn't exit before it completes (avoids flaky TSAN noise).
        std::thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn slack_observer_above_threshold_attempts_post() {
        let obs = SlackObserver::new("https://127.0.0.1:0/nonexistent", 250_000);
        obs.record_event(&ObserverEvent::TurnTokenSummary {
            total_input_tokens: 300_000,
            total_output_tokens: 100_000, // total = 400_000 > threshold
        });
        std::thread::sleep(Duration::from_millis(50));
    }
}
