//! Global tracing-subscriber installation. The only public entry
//! point a daemon binary needs. Owns the agent-alias-prefixed
//! formatter and the `LogCaptureLayer` wiring so the rest of the
//! workspace never names a `tracing` or `tracing_subscriber` type.

use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::field::{RecordFields, VisitOutput};
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::{DefaultVisitor, Writer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;

use crate::event::ZeroclawAttribution;
use crate::layer::{F_EPHEMERAL_ATTRS, LogCaptureLayer};

/// Install the global tracing subscriber. Two independent axes:
///
/// * **Recording floor** — what reaches the `LogCaptureLayer` (and thus
///   the JSONL writer, broadcast hook, and Observer bridge). Resolved
///   as: `recording_override` (the `--log-level` flag) if `Some`,
///   else `RUST_LOG` from the environment, else `default_filter`.
///
/// * **Terminal display** — the stderr fmt layer. Gated by `verbose`:
///   when `false` only WARN+ log lines reach the terminal (fork:
///   ZEROCLAW_STDERR_FLOOR overrides the floor; direct `println!`/stdout
///   is untouched). When `true` it surfaces events down to the same
///   recording floor.
///
/// All filter strings are `RUST_LOG`-compatible directives (e.g.
/// `"info"` or `"debug,matrix_sdk=warn"`).
///
/// Both axes are fixed for the process lifetime — the global subscriber
/// is installed once and cannot be reconfigured without a restart.
///
/// Panics on subscriber install failure — the daemon cannot operate
/// without logging.
pub fn install_global_subscriber(
    recording_override: Option<&str>,
    default_filter: &str,
    verbose: bool,
) {
    // Recording floor: explicit flag wins, then RUST_LOG, then default.
    let recording_filter = match recording_override {
        Some(flag) => EnvFilter::new(flag),
        None => {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter))
        }
    };

    // The fmt (terminal) layer carries its own filter so display can be
    // muted without touching what the capture layer records. When
    // verbose is off, a WARN floor (fork; ZEROCLAW_STDERR_FLOOR overrides)
    // discards lower-severity events before they format — stdout (println!)
    // is unaffected because it never routes through tracing.
    let fmt_filter = if verbose {
        match recording_override {
            Some(flag) => EnvFilter::new(flag),
            None => {
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter))
            }
        }
    } else {
        // fork(v0.8.0 regressions): upstream mutes the fmt layer entirely when
        // not --verbose, leaving daemon stderr (our only prod channel for
        // panics and provider WARN/ERRORs -- the manager redirects fd2 to
        // daemon-stderr.log) permanently silent. Float WARN+ by default;
        // ZEROCLAW_STDERR_FLOOR re-mutes ("off") or widens ("info"). The
        // uppercase tail keeps the var invisible to the lowercase-only
        // env-override grammar walker (env_overrides.rs:63-68).
        let floor = std::env::var("ZEROCLAW_STDERR_FLOOR").unwrap_or_else(|_| "warn".to_string());
        EnvFilter::try_new(&floor).unwrap_or_else(|_| EnvFilter::new("warn"))
    };

    let fmt_layer = fmt::layer()
        .fmt_fields(RedactEphemeralFields)
        .with_writer(std::io::stderr)
        .event_format(AgentAliasFormatter::new())
        .with_filter(fmt_filter);

    let subscriber = tracing_subscriber::registry()
        .with(LogCaptureLayer.with_filter(recording_filter))
        .with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

#[doc(hidden)]
pub fn try_install_capture_subscriber() {
    use tracing_subscriber::Registry;
    let subscriber = Registry::default().with(LogCaptureLayer);
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Field formatter that renders event fields exactly like the default
/// formatter but drops the `zc_ephemeral_attrs` transport field, so
/// short-lived pairing credentials (QR payloads, pair codes) never reach the
/// terminal in verbose mode. The field still rides the event to the
/// `LogCaptureLayer`, which routes it onto the broadcast-only ephemeral path;
/// only the human-readable stderr display is redacted. All other fields keep
/// the default rendering (the delegated `DefaultVisitor` handles `message`
/// escaping, error sources, etc.).
struct RedactEphemeralFields;

impl<'writer> FormatFields<'writer> for RedactEphemeralFields {
    fn format_fields<R: RecordFields>(
        &self,
        writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        let mut visitor = RedactEphemeralVisitor {
            inner: DefaultVisitor::new(writer, true),
        };
        fields.record(&mut visitor);
        visitor.inner.finish()
    }
}

/// Visitor wrapper that forwards every field to the default visitor except
/// the ephemeral-attributes transport field, which it swallows. The current
/// transport records the credential via `%Display` (`record_debug`), but the
/// guard is applied uniformly across *every* visitor method so the redaction
/// stays fail-closed if the field's recorded representation ever changes
/// (numeric, boolean, error, str) — a leak must not reappear just because the
/// call site swapped `%` for `?` or a typed value.
struct RedactEphemeralVisitor<'a> {
    inner: DefaultVisitor<'a>,
}

impl RedactEphemeralVisitor<'_> {
    /// True when the field is the ephemeral-attributes transport field and
    /// must therefore be dropped from the human-readable stderr rendering.
    fn is_ephemeral(field: &Field) -> bool {
        field.name() == F_EPHEMERAL_ATTRS
    }
}

impl Visit for RedactEphemeralVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_debug(field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_str(field, value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_error(field, value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_f64(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_i64(field, value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_u64(field, value);
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_i128(field, value);
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_u128(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if Self::is_ephemeral(field) {
            return;
        }
        self.inner.record_bool(field, value);
    }
}

/// Tracing event formatter that prefixes each log line with the most
/// specific alias-bound label available in the current span scope.
/// `agent_alias` wins; falls back to the channel composite; finally
/// to `[system]` for boot / migration / install-wide messages.
struct AgentAliasFormatter {
    inner: fmt::format::Format<fmt::format::Full, fmt::time::SystemTime>,
}

impl AgentAliasFormatter {
    fn new() -> Self {
        Self {
            inner: fmt::format::Format::default(),
        }
    }
}

impl<S, N> fmt::FormatEvent<S, N> for AgentAliasFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let label = ctx
            .event_scope()
            .and_then(|scope| {
                scope.into_iter().find_map(|span| {
                    span.extensions()
                        .get::<ZeroclawAttribution>()
                        .and_then(|attribution| {
                            attribution
                                .get("agent_alias")
                                .or_else(|| attribution.get("channel"))
                                .map(str::to_string)
                        })
                })
            })
            .unwrap_or_else(|| "system".to_string());
        write!(writer, "[{label}] ")?;
        self.inner.format_event(ctx, writer, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// In-memory `MakeWriter` so a test can capture what the fmt layer would
    /// have written to stderr in verbose mode.
    #[derive(Clone, Default)]
    struct BufMakeWriter(Arc<Mutex<Vec<u8>>>);

    struct BufGuard(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufGuard {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufMakeWriter {
        type Writer = BufGuard;
        fn make_writer(&'a self) -> Self::Writer {
            BufGuard(self.0.clone())
        }
    }

    /// Regression for the ephemeral-credential-at-verbose-stderr leak: the
    /// terminal fmt layer must render the login event but never print the
    /// `zc_ephemeral_attrs` transport field (which carries the QR payload /
    /// pair code), so a supervisor or log collector scraping stderr in
    /// verbose mode cannot retain the pairing secret.
    #[test]
    fn verbose_terminal_output_redacts_ephemeral_credentials() {
        let buf = BufMakeWriter::default();
        let fmt_layer = fmt::layer()
            .fmt_fields(RedactEphemeralFields)
            .with_writer(buf.clone())
            .with_ansi(false)
            .event_format(AgentAliasFormatter::new());
        let subscriber = tracing_subscriber::registry().with(fmt_layer);

        tracing::subscriber::with_default(subscriber, || {
            crate::record!(
                INFO,
                crate::Event::new(module_path!(), crate::Action::Note)
                    .with_attrs(::serde_json::json!({"login": {"state": "qr"}}))
                    .with_ephemeral_attrs(::serde_json::json!({
                        "login": {"qr_payload": "SUPER-SECRET-QR-MARKER"}
                    })),
                "qr pairing login event"
            );
        });

        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("qr pairing login event"),
            "the login event should still be logged: {out:?}"
        );
        assert!(
            !out.contains("SUPER-SECRET-QR-MARKER"),
            "verbose stderr must not contain the ephemeral pairing credential: {out:?}"
        );
        assert!(
            !out.contains(F_EPHEMERAL_ATTRS),
            "the ephemeral transport field must be dropped entirely: {out:?}"
        );
    }

    /// Fail-closed across representations: even if the ephemeral transport
    /// field were ever recorded as a typed value (str / integer / bool) rather
    /// than the current `%Display` debug form, the redactor must still drop it.
    /// Guards against a future call-site change silently reintroducing the
    /// leak through an unguarded visitor method.
    #[test]
    fn verbose_terminal_output_redacts_ephemeral_across_representations() {
        fn render_with<F: FnOnce()>(emit: F) -> String {
            let buf = BufMakeWriter::default();
            let fmt_layer = fmt::layer()
                .fmt_fields(RedactEphemeralFields)
                .with_writer(buf.clone())
                .with_ansi(false)
                .event_format(AgentAliasFormatter::new());
            let subscriber = tracing_subscriber::registry().with(fmt_layer);
            tracing::subscriber::with_default(subscriber, emit);
            String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
        }

        // str representation (record_str)
        let out = render_with(|| {
            tracing::info!(zc_ephemeral_attrs = "SECRET-STR-MARKER", "str ephemeral");
        });
        assert!(out.contains("str ephemeral"), "event still logged: {out:?}");
        assert!(
            !out.contains("SECRET-STR-MARKER"),
            "str-recorded ephemeral field leaked: {out:?}"
        );
        assert!(
            !out.contains(F_EPHEMERAL_ATTRS),
            "field name leaked: {out:?}"
        );

        // integer representation (record_i64)
        let out = render_with(|| {
            tracing::info!(zc_ephemeral_attrs = 424242i64, "int ephemeral");
        });
        assert!(out.contains("int ephemeral"), "event still logged: {out:?}");
        assert!(
            !out.contains("424242"),
            "integer-recorded ephemeral field leaked: {out:?}"
        );
        assert!(
            !out.contains(F_EPHEMERAL_ATTRS),
            "field name leaked: {out:?}"
        );

        // bool representation (record_bool)
        let out = render_with(|| {
            tracing::info!(zc_ephemeral_attrs = true, "bool ephemeral");
        });
        assert!(
            out.contains("bool ephemeral"),
            "event still logged: {out:?}"
        );
        assert!(
            !out.contains(F_EPHEMERAL_ATTRS),
            "bool-recorded ephemeral field leaked: {out:?}"
        );
    }
}
