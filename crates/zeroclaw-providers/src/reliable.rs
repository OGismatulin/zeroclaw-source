use super::ModelProvider;
use super::dispatch::ProviderDispatch;
use super::stream_guard::AbortOnDrop;
use super::traits::{
    ChatMessage, ChatRequest, ChatResponse, StreamChunk, StreamEvent, StreamOptions, StreamResult,
};
use async_trait::async_trait;
use futures_util::{StreamExt, stream};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ── ModelProvider Fallback Notification ──────────────────────────────────────
// When ReliableModelProvider uses a fallback (different model_provider or model than
// requested), it records the details here so channel code can notify the user.
// Uses tokio::task_local to avoid cross-request leakage between concurrent
// users (the old global static had a race window).

/// Info about a model_provider fallback that occurred during a request.
#[derive(Debug, Clone)]
pub struct ProviderFallbackInfo {
    /// ModelProvider that was originally requested.
    pub requested_provider: String,
    /// Model that was originally requested.
    pub requested_model: String,
    /// ModelProvider that actually served the request.
    pub actual_provider: String,
    /// Model that actually served the request.
    pub actual_model: String,
}

tokio::task_local! {
    static PROVIDER_FALLBACK: RefCell<Option<ProviderFallbackInfo>>;
}

/// Take (consume) the last model_provider fallback info, if any.
/// Must be called within a `scope_provider_fallback` scope.
pub fn take_last_provider_fallback() -> Option<ProviderFallbackInfo> {
    PROVIDER_FALLBACK
        .try_with(|cell| cell.borrow_mut().take())
        .ok()
        .flatten()
}

/// Run the given future within a provider-fallback scope.
/// Both `record_provider_fallback` (inside ReliableModelProvider) and
/// `take_last_provider_fallback` (post-loop channel code) must execute
/// within this scope for the data to be visible.
pub async fn scope_provider_fallback<F: std::future::Future>(future: F) -> F::Output {
    PROVIDER_FALLBACK.scope(RefCell::new(None), future).await
}

/// Record a model_provider fallback event.
fn record_provider_fallback(
    requested_provider: &str,
    requested_model: &str,
    actual_provider: &str,
    actual_model: &str,
) {
    let _ = PROVIDER_FALLBACK.try_with(|cell| {
        *cell.borrow_mut() = Some(ProviderFallbackInfo {
            requested_provider: requested_provider.to_string(),
            requested_model: requested_model.to_string(),
            actual_provider: actual_provider.to_string(),
            actual_model: actual_model.to_string(),
        });
    });
}

// ── Error Classification ─────────────────────────────────────────────────
// Errors are split into retryable (transient server/network failures) and
// non-retryable (permanent client errors). This distinction drives whether
// the retry loop continues, falls back to the next model_provider, or aborts
// immediately — avoiding wasted latency on errors that cannot self-heal.

/// Check if an error is non-retryable (client errors that won't resolve with retries).
pub fn is_non_retryable(err: &anyhow::Error) -> bool {
    // Context-window ownership lives outside this reliability wrapper. Keep
    // the legacy predicate false for callers that distinguish it separately;
    // every reliability loop detects the typed kind first and returns it.
    if is_context_window_exceeded(err) {
        return false;
    }

    // Terminal failures intentionally hide the raw provider cause. Their
    // diagnostic disposition is the authoritative downstream retry contract.
    if let Some(failure) = terminal_provider_failure(err) {
        return matches!(
            failure.diagnostic().disposition(),
            ProviderErrorDisposition::NonRetryable
                | ProviderErrorDisposition::RateLimitedNonRetryable
        );
    }

    // Tool schema validation errors are NOT non-retryable — the model_provider's
    // built-in fallback in compatible.rs can recover by switching to
    // prompt-guided tool instructions.
    if is_tool_schema_error(err) {
        return false;
    }

    // 4xx errors are generally non-retryable (bad request, auth failure, etc.),
    // except 429 (rate-limit — transient) and 408 (timeout — worth retrying).
    if let Some(code) = typed_http_status(err) {
        return (400..500).contains(&code) && code != 429 && code != 408;
    }
    // Fallback: parse status codes from stringified errors (some model_providers
    // embed codes in error messages rather than returning typed HTTP errors).
    let msg = error_chain_text(err);
    for word in msg.split(|c: char| !c.is_ascii_digit()) {
        if let Ok(code) = word.parse::<u16>()
            && (400..500).contains(&code)
        {
            return code != 429 && code != 408;
        }
    }

    // Heuristic: detect auth/model failures by keyword when no HTTP status
    // is available (e.g. gRPC or custom transport errors).
    let msg_lower = msg.to_lowercase();
    let auth_failure_hints = [
        "invalid api key",
        "incorrect api key",
        "missing api key",
        "api key not set",
        "authentication failed",
        "auth failed",
        "unauthorized",
        "forbidden",
        "permission denied",
        "access denied",
        "invalid token",
    ];

    if auth_failure_hints
        .iter()
        .any(|hint| msg_lower.contains(hint))
    {
        return true;
    }

    msg_lower.contains("model")
        && (msg_lower.contains("not found")
            || msg_lower.contains("unknown")
            || msg_lower.contains("unsupported")
            || msg_lower.contains("does not exist")
            || msg_lower.contains("invalid"))
}

/// Check if an error indicates an authentication/authorization failure.
/// Used by channels to evict cached model_providers whose OAuth tokens may have
/// expired so the next request triggers a fresh credential resolution.
pub fn is_auth_error(err: &anyhow::Error) -> bool {
    // Terminal failures intentionally have no raw provider source. Preserve
    // auth eviction semantics from their safe diagnostic instead.
    if let Some(failure) = terminal_provider_failure(err) {
        let diagnostic = failure.diagnostic();
        return matches!(diagnostic.kind(), "auth" | "provider_auth")
            || matches!(diagnostic.status(), Some(401 | 403));
    }

    if let Some(code) = typed_http_status(err) {
        return code == 401 || code == 403;
    }

    let msg_lower = error_chain_text(err).to_lowercase();
    let hints = [
        "401 unauthorized",
        "403 forbidden",
        "invalid api key",
        "incorrect api key",
        "authentication failed",
        "auth failed",
        "unauthorized",
        "invalid token",
        "token expired",
        "access_token",
    ];

    hints.iter().any(|hint| msg_lower.contains(hint))
}

/// Check if an error is a tool schema validation failure (e.g. Groq returning
/// "tool call validation failed: attempted to call tool '...' which was not in request").
/// These errors should NOT be classified as non-retryable because the model_provider's
/// built-in fallback logic (`compatible.rs::is_native_tool_schema_unsupported`)
/// can recover by switching to prompt-guided tool instructions.
pub fn is_tool_schema_error(err: &anyhow::Error) -> bool {
    let hints = [
        "tool call validation failed",
        "was not in request",
        "not found in tool list",
        "invalid_tool_call",
    ];
    if typed_provider_http_error(err).is_some_and(|provider_err| {
        let lower = provider_err.detail().to_lowercase();
        hints.iter().any(|hint| lower.contains(hint))
    }) {
        return true;
    }

    let lower = error_chain_text(err).to_lowercase();
    hints.iter().any(|hint| lower.contains(hint))
}

pub fn is_context_window_exceeded(err: &anyhow::Error) -> bool {
    if terminal_provider_failure(err)
        .is_some_and(|failure| failure.diagnostic().kind() == "context_window")
    {
        return true;
    }

    let hints = [
        "exceeds the context window",
        "exceeds the available context size",
        "context window of this model",
        "maximum context length",
        "context length exceeded",
        "too many tokens",
        "token limit exceeded",
        "prompt is too long",
        "input is too long",
        "prompt exceeds max length",
    ];
    if typed_provider_http_error(err).is_some_and(|provider_err| {
        let lower = provider_err.detail().to_lowercase();
        hints.iter().any(|hint| lower.contains(hint))
    }) {
        return true;
    }

    let lower = error_chain_text(err).to_lowercase();
    hints.iter().any(|hint| lower.contains(hint))
}

/// Check if an error is a rate-limit (429) error.
fn is_rate_limited(err: &anyhow::Error) -> bool {
    if let Some(code) = typed_http_status(err) {
        return code == 429;
    }
    let msg = error_chain_text(err);
    msg.contains("429")
        && (msg.contains("Too Many") || msg.contains("rate") || msg.contains("limit"))
}

/// Check if a 429 is a business/quota-plan error that retries cannot fix.
///
/// Examples:
/// - plan does not include requested model
/// - insufficient balance / package not active
/// - known model_provider business codes (e.g. Z.AI: 1311, 1113)
fn is_non_retryable_rate_limit(err: &anyhow::Error) -> bool {
    if !is_rate_limited(err) {
        return false;
    }

    let business_hints = [
        "plan does not include",
        "doesn't include",
        "not include",
        "insufficient balance",
        "insufficient_balance",
        "insufficient quota",
        "insufficient_quota",
        "quota exhausted",
        "out of credits",
        "no available package",
        "package not active",
        "purchase package",
        "model not available for your plan",
    ];

    fn matches_business_failure(lower: &str, business_hints: &[&str]) -> bool {
        if business_hints.iter().any(|hint| lower.contains(hint)) {
            return true;
        }

        lower.split(|c: char| !c.is_ascii_digit()).any(|token| {
            token
                .parse::<u16>()
                .is_ok_and(|code| matches!(code, 1113 | 1311))
        })
    }

    if typed_provider_http_error(err).is_some_and(|provider_err| {
        matches_business_failure(&provider_err.detail().to_lowercase(), &business_hints)
    }) {
        return true;
    }

    matches_business_failure(&error_chain_text(err).to_lowercase(), &business_hints)
}

const MAX_RETRY_AFTER_SECS: f64 = 86_400.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedRetryAfter {
    public_secs: u64,
    millis: u64,
}

/// Legacy compatibility parser used only for retry scheduling when an older
/// provider still collapses response headers into its error text. Public
/// diagnostics never consume this reconstructed metadata.
fn parse_legacy_retry_after(err: &anyhow::Error) -> Option<ParsedRetryAfter> {
    let msg = err.to_string();
    let lower = msg.to_lowercase();

    // Look for "retry-after: <number>" or "retry_after: <number>"
    for prefix in &[
        "retry-after:",
        "retry_after:",
        "retry-after ",
        "retry_after ",
    ] {
        if let Some(pos) = lower.find(prefix) {
            let after = &msg[pos + prefix.len()..];
            let token = after
                .trim_start()
                .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ')'))
                .next()
                .unwrap_or("");
            let secs = token.parse::<f64>().ok()?;
            if !secs.is_finite() || secs < 0.0 {
                return None;
            }
            let clamped = secs.min(MAX_RETRY_AFTER_SECS);
            return Some(ParsedRetryAfter {
                public_secs: clamped.ceil() as u64,
                millis: (clamped * 1_000.0).ceil() as u64,
            });
        }
    }
    None
}

fn parse_legacy_retry_after_ms(err: &anyhow::Error) -> Option<u64> {
    parse_legacy_retry_after(err).map(|value| value.millis)
}

fn failure_reason(rate_limited: bool, non_retryable: bool) -> &'static str {
    if rate_limited && non_retryable {
        "rate_limited_non_retryable"
    } else if rate_limited {
        "rate_limited"
    } else if non_retryable {
        "non_retryable"
    } else {
        "retryable"
    }
}

fn compact_error_detail(err: &anyhow::Error) -> String {
    super::sanitize_api_error(&format!("{err:#}"))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderErrorDisposition {
    Retryable,
    NonRetryable,
    RateLimited,
    RateLimitedNonRetryable,
}

impl ProviderErrorDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::NonRetryable => "non_retryable",
            Self::RateLimited => "rate_limited",
            Self::RateLimitedNonRetryable => "rate_limited_non_retryable",
        }
    }
}

impl std::fmt::Display for ProviderErrorDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderRoute {
    #[default]
    Main,
    Vision,
}

impl ProviderRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Vision => "vision",
        }
    }
}

impl std::fmt::Display for ProviderRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCandidateDescriptor {
    provider_family: String,
    configured_alias: Option<String>,
    pinned_model: Option<String>,
}

impl ProviderCandidateDescriptor {
    pub fn requested(provider_family: &str, configured_alias: Option<&str>) -> Self {
        Self {
            provider_family: provider_family.to_string(),
            configured_alias: configured_alias.map(ToString::to_string),
            pinned_model: None,
        }
    }

    pub fn pinned(
        provider_family: &str,
        configured_alias: Option<&str>,
        effective_model: &str,
    ) -> Self {
        Self {
            provider_family: provider_family.to_string(),
            configured_alias: configured_alias.map(ToString::to_string),
            pinned_model: Some(effective_model.to_string()),
        }
    }

    pub fn provider_family(&self) -> &str {
        &self.provider_family
    }

    pub fn configured_alias(&self) -> Option<&str> {
        self.configured_alias.as_deref()
    }

    pub fn pinned_model(&self) -> Option<&str> {
        self.pinned_model.as_deref()
    }

    pub fn uses_requested_model(&self) -> bool {
        self.pinned_model.is_none()
    }

    pub fn actual_provider(&self) -> &str {
        self.configured_alias()
            .unwrap_or_else(|| self.provider_family())
    }

    fn as_str(&self) -> &str {
        self.actual_provider()
    }

    fn effective_model<'a>(&'a self, requested_model: &'a str) -> &'a str {
        self.pinned_model().unwrap_or(requested_model)
    }
}

impl std::ops::Deref for ProviderCandidateDescriptor {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.actual_provider()
    }
}

impl serde::Serialize for ProviderCandidateDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.actual_provider())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderErrorDiagnostic {
    kind: &'static str,
    disposition: ProviderErrorDisposition,
    phase: &'static str,
    hint: &'static str,
    endpoint: Option<String>,
    status: Option<u16>,
    retry_after_secs: Option<u64>,
}

impl ProviderErrorDiagnostic {
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub const fn disposition(&self) -> ProviderErrorDisposition {
        self.disposition
    }

    pub fn phase(&self) -> &'static str {
        self.phase
    }

    pub fn hint(&self) -> &'static str {
        self.hint
    }

    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    pub const fn retry_after_secs(&self) -> Option<u64> {
        self.retry_after_secs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalProviderFailure {
    candidate: ProviderCandidateDescriptor,
    actual_model: String,
    route: ProviderRoute,
    attempts_for_call: u32,
    diagnostic: ProviderErrorDiagnostic,
}

impl TerminalProviderFailure {
    fn new(
        candidate: &ProviderCandidateDescriptor,
        requested_model: &str,
        route: ProviderRoute,
        attempts_for_call: u32,
        diagnostic: ProviderErrorDiagnostic,
    ) -> Self {
        Self {
            candidate: candidate.clone(),
            actual_model: candidate.effective_model(requested_model).to_string(),
            route,
            attempts_for_call,
            diagnostic,
        }
    }

    pub fn actual_provider(&self) -> &str {
        self.candidate.actual_provider()
    }

    pub fn provider_family(&self) -> &str {
        self.candidate.provider_family()
    }

    pub fn configured_alias(&self) -> Option<&str> {
        self.candidate.configured_alias()
    }

    pub fn actual_model(&self) -> &str {
        &self.actual_model
    }

    pub const fn route(&self) -> ProviderRoute {
        self.route
    }

    pub const fn attempts_for_call(&self) -> u32 {
        self.attempts_for_call
    }

    pub fn diagnostic(&self) -> &ProviderErrorDiagnostic {
        &self.diagnostic
    }
}

impl std::fmt::Display for TerminalProviderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider call failed: provider={} family={} model={} route={} attempts={} kind={} disposition={}",
            self.actual_provider(),
            self.provider_family(),
            self.actual_model(),
            self.route,
            self.attempts_for_call,
            self.diagnostic.kind,
            self.diagnostic.disposition,
        )
    }
}

impl std::error::Error for TerminalProviderFailure {}

pub fn terminal_provider_failure(err: &anyhow::Error) -> Option<&TerminalProviderFailure> {
    err.downcast_ref::<TerminalProviderFailure>()
}

fn terminal_provider_error(
    candidate: &ProviderCandidateDescriptor,
    requested_model: &str,
    route: ProviderRoute,
    attempts_for_call: u32,
    err: &anyhow::Error,
) -> anyhow::Error {
    TerminalProviderFailure::new(
        candidate,
        requested_model,
        route,
        attempts_for_call,
        provider_error_diagnostic(err),
    )
    .into()
}

fn typed_http_status(err: &anyhow::Error) -> Option<u16> {
    typed_provider_http_error(err)
        .map(|provider_err| provider_err.status().as_u16())
        .or_else(|| {
            typed_reqwest_error(err)
                .and_then(|reqwest_err| reqwest_err.status().map(|status| status.as_u16()))
        })
}

fn typed_provider_http_error(err: &anyhow::Error) -> Option<&super::ProviderHttpError> {
    err.chain()
        .find_map(|source| source.downcast_ref::<super::ProviderHttpError>())
}

fn typed_reqwest_error(err: &anyhow::Error) -> Option<&reqwest::Error> {
    err.chain()
        .find_map(|source| source.downcast_ref::<reqwest::Error>())
}

fn error_chain_text(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

/// Legacy text-only providers still need status-shaped classification for
/// retry policy. This value must never be copied into public diagnostics.
fn legacy_http_status_for_classification(error_detail: &str) -> Option<u16> {
    error_detail
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|token| token.parse::<u16>().ok())
        .find(|code| (400..=599).contains(code))
}

fn typed_retry_after_secs(err: &anyhow::Error) -> Option<u64> {
    typed_provider_http_error(err).and_then(super::ProviderHttpError::retry_after_secs)
}

fn sanitized_url_endpoint(mut url: reqwest::Url) -> String {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    super::sanitize_api_error(url.as_ref())
}

fn endpoint_from_error_text(text: &str) -> Option<String> {
    let start = text.find("https://").or_else(|| text.find("http://"))?;
    let raw = text[start..]
        .split(|c: char| c.is_whitespace() || matches!(c, ')' | ',' | ';' | '"'))
        .next()
        .unwrap_or("");
    let url = reqwest::Url::parse(raw)
        .or_else(|_| reqwest::Url::parse(raw.trim_end_matches([':', '.'])))
        .ok()?;
    Some(sanitized_url_endpoint(url))
}

fn provider_error_diagnostic(err: &anyhow::Error) -> ProviderErrorDiagnostic {
    let error_detail = compact_error_detail(err);
    let lower = error_detail.to_lowercase();
    let endpoint = typed_reqwest_error(err)
        .and_then(|reqwest_err| reqwest_err.url().cloned().map(sanitized_url_endpoint))
        .or_else(|| endpoint_from_error_text(&error_detail));
    let status = typed_http_status(err);
    let rate_limited = is_rate_limited(err);
    let non_retryable_rate_limit = is_non_retryable_rate_limit(err);
    let non_retryable = is_non_retryable(err) || non_retryable_rate_limit;
    let disposition = match (rate_limited, non_retryable) {
        (true, true) => ProviderErrorDisposition::RateLimitedNonRetryable,
        (true, false) => ProviderErrorDisposition::RateLimited,
        (false, true) => ProviderErrorDisposition::NonRetryable,
        (false, false) => ProviderErrorDisposition::Retryable,
    };
    let retry_after_secs = (disposition == ProviderErrorDisposition::RateLimited)
        .then(|| typed_retry_after_secs(err))
        .flatten();

    if is_context_window_exceeded(err) {
        return ProviderErrorDiagnostic {
            kind: "context_window",
            disposition,
            phase: "request_validation",
            hint: "reduce context or use a larger-context model",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if is_auth_error(err) {
        return ProviderErrorDiagnostic {
            kind: "auth",
            disposition,
            phase: "http_response",
            hint: "check provider credentials",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if is_rate_limited(err) {
        return ProviderErrorDiagnostic {
            kind: "rate_limited",
            disposition,
            phase: "http_response",
            hint: "wait, change key/quota, or switch provider",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if let Some(code) = status.or_else(|| legacy_http_status_for_classification(&error_detail)) {
        let (kind, hint) = if (500..=599).contains(&code) {
            (
                "provider_server",
                "provider returned a server error; retry or switch provider",
            )
        } else if code == 404 {
            (
                "model_not_found",
                "check the configured model id for this provider",
            )
        } else if (400..=499).contains(&code) {
            (
                "client_error",
                "provider rejected the request; check config, model, or request shape",
            )
        } else {
            ("http_error", "inspect provider response or switch provider")
        };
        return ProviderErrorDiagnostic {
            kind,
            disposition,
            phase: "http_response",
            hint,
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if let Some(reqwest_err) = typed_reqwest_error(err) {
        if let Some(status) = reqwest_err.status() {
            let code = status.as_u16();
            let (kind, hint) = if status.is_server_error() {
                (
                    "provider_server",
                    "provider returned a server error; retry or switch provider",
                )
            } else if code == 404 {
                (
                    "model_not_found",
                    "check the configured model id for this provider",
                )
            } else if status.is_client_error() {
                (
                    "client_error",
                    "provider rejected the request; check config, model, or request shape",
                )
            } else {
                ("http_error", "inspect provider response or switch provider")
            };
            return ProviderErrorDiagnostic {
                kind,
                disposition,
                phase: "http_response",
                hint,
                endpoint,
                status: Some(code),
                retry_after_secs,
            };
        }

        if reqwest_err.is_timeout() && reqwest_err.is_connect() {
            return ProviderErrorDiagnostic {
                kind: "connect_timeout",
                disposition,
                phase: "tls_or_connect",
                hint: "connection reached the host but timed out during connect/TLS; check VPN, firewall, routing, or switch provider",
                endpoint,
                status,
                retry_after_secs,
            };
        }

        if reqwest_err.is_timeout() {
            return ProviderErrorDiagnostic {
                kind: "timeout",
                disposition,
                phase: "request",
                hint: "provider request timed out; retry or switch provider",
                endpoint,
                status,
                retry_after_secs,
            };
        }

        if reqwest_err.is_connect() {
            return ProviderErrorDiagnostic {
                kind: "connect",
                disposition,
                phase: "connect",
                hint: "could not open provider connection; check network, VPN, or firewall",
                endpoint,
                status,
                retry_after_secs,
            };
        }
    }

    if (lower.contains("client error (connect)") && lower.contains("timed out"))
        || lower.contains("ssl connection timeout")
        || (lower.contains("tls") && lower.contains("timeout"))
    {
        return ProviderErrorDiagnostic {
            kind: "connect_timeout",
            disposition,
            phase: "tls_or_connect",
            hint: "connection reached the host but timed out during connect/TLS; check VPN, firewall, routing, or switch provider",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if lower.contains("timed out") || lower.contains("timeout") {
        return ProviderErrorDiagnostic {
            kind: "timeout",
            disposition,
            phase: "request",
            hint: "provider request timed out; retry or switch provider",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if lower.contains("dns") || lower.contains("resolve") {
        return ProviderErrorDiagnostic {
            kind: "dns",
            disposition,
            phase: "dns",
            hint: "DNS resolution failed; check network or provider host",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    if lower.contains("model")
        && (lower.contains("not found")
            || lower.contains("unknown")
            || lower.contains("unsupported")
            || lower.contains("does not exist")
            || lower.contains("invalid"))
    {
        return ProviderErrorDiagnostic {
            kind: "model_not_found",
            disposition,
            phase: "http_response",
            hint: "check the configured model id for this provider",
            endpoint,
            status,
            retry_after_secs,
        };
    }

    ProviderErrorDiagnostic {
        kind: "provider_error",
        disposition,
        phase: "unknown",
        hint: "inspect provider error or switch provider",
        endpoint,
        status,
        retry_after_secs,
    }
}

fn provider_failure_attrs(
    provider_name: &str,
    model: &str,
    error_detail: &str,
    diagnostic: &ProviderErrorDiagnostic,
) -> serde_json::Value {
    serde_json::json!({
        "model_provider": provider_name,
        "model": model,
        "error": error_detail,
        "error_kind": diagnostic.kind,
        "error_disposition": diagnostic.disposition.as_str(),
        "error_phase": diagnostic.phase,
        "endpoint": diagnostic.endpoint.as_deref(),
        "hint": diagnostic.hint,
        "status": diagnostic.status,
        "retry_after_secs": diagnostic.retry_after_secs,
    })
}

fn provider_retry_attrs(
    provider_name: &str,
    model: &str,
    attempt: u32,
    backoff_ms: u64,
    reason: &str,
    error_detail: &str,
    diagnostic: &ProviderErrorDiagnostic,
) -> serde_json::Value {
    serde_json::json!({
        "model_provider": provider_name,
        "model": model,
        "attempt": attempt,
        "backoff_ms": backoff_ms,
        "reason": reason,
        "error": error_detail,
        "error_kind": diagnostic.kind,
        "error_disposition": diagnostic.disposition.as_str(),
        "error_phase": diagnostic.phase,
        "endpoint": diagnostic.endpoint.as_deref(),
        "hint": diagnostic.hint,
        "status": diagnostic.status,
        "retry_after_secs": diagnostic.retry_after_secs,
    })
}

fn provider_exhausted_attrs(
    provider_name: &str,
    model: &str,
    last_error_detail: Option<&str>,
    last_diagnostic: Option<&ProviderErrorDiagnostic>,
) -> serde_json::Value {
    serde_json::json!({
        "model_provider": provider_name,
        "model": model,
        "error": last_error_detail,
        "error_kind": last_diagnostic.map(|diagnostic| diagnostic.kind),
        "error_disposition": last_diagnostic.map(|diagnostic| diagnostic.disposition.as_str()),
        "error_phase": last_diagnostic.map(|diagnostic| diagnostic.phase),
        "endpoint": last_diagnostic.and_then(|diagnostic| diagnostic.endpoint.as_deref()),
        "hint": last_diagnostic.map(|diagnostic| diagnostic.hint),
        "status": last_diagnostic.and_then(|diagnostic| diagnostic.status),
        "retry_after_secs": last_diagnostic.and_then(|diagnostic| diagnostic.retry_after_secs),
    })
}

fn push_failure(
    failures: &mut Vec<String>,
    provider_name: &str,
    model: &str,
    attempt: u32,
    max_attempts: u32,
    reason: &str,
    error_detail: &str,
    diagnostic: Option<&ProviderErrorDiagnostic>,
) {
    let mut failure = format!(
        "model_provider={provider_name} model={model} attempt {attempt}/{max_attempts}: {reason}; error={error_detail}"
    );
    if let Some(diagnostic) = diagnostic {
        failure.push_str(&format!(
            "; kind={}; phase={}; hint={}",
            diagnostic.kind, diagnostic.phase, diagnostic.hint
        ));
        if let Some(endpoint) = diagnostic.endpoint.as_deref() {
            failure.push_str(&format!("; endpoint={endpoint}"));
        }
    }
    failures.push(failure);
}

/// True when a syntactically-successful response carries no usable content:
/// no text, no tool calls, and no reasoning. Such "empty completions" (a 2xx
/// with a null/blank message, a 0-token sample, a content-filter soft block, or
/// a truncated stream) are never a legitimate final answer — they are almost
/// always a transient provider hiccup — so callers re-roll them like a
/// retryable error instead of surfacing a blank turn.
///
/// Prompt-guided tool calls embed the call in `text`, so a response carrying
/// `<tool_call>…` is non-empty here and is never misclassified.
fn is_empty_completion(resp: &ChatResponse) -> bool {
    resp.text_or_empty().trim().is_empty()
        && resp.tool_calls.is_empty()
        && resp
            .reasoning_content
            .as_deref()
            .is_none_or(|r| r.trim().is_empty())
}

// ── Resilient ModelProvider Wrapper ────────────────────────────────────────────
// Two-level strategy: model_provider chain → retry loop.
//   Outer loop: iterate registered model_providers in priority order. The production
//               caller always wires a single primary; tests construct multi-
//               element chains directly to exercise failover semantics.
//   Inner loop: retry the same (model_provider, model) pair with exponential backoff,
//               rotating API keys on rate-limit errors.
// Loop invariant: `failures` accumulates every failed attempt so the final
// error message gives operators a complete diagnostic trail.

/// ModelProvider wrapper with retry + auth-key rotation. The model_provider Vec exists
/// for tests to exercise multi-provider failover; production wiring always
/// passes a single primary. Per-model failover chains are also test-only —
/// the schema no longer surfaces them.
pub struct ReliableModelProvider {
    /// `[providers.models.<family>.<alias>]` config-key alias.
    alias: String,
    model_providers: Vec<(ProviderCandidateDescriptor, Box<dyn ModelProvider>)>,
    max_retries: u32,
    base_backoff_ms: u64,
    /// Extra API keys for rotation (index tracks round-robin position).
    api_keys: Vec<String>,
    key_index: AtomicUsize,
    /// Per-model failover chains. Test-only: model_name → [alt1, alt2, ...].
    model_fallbacks: HashMap<String, Vec<String>>,
    route: ProviderRoute,
}

impl ReliableModelProvider {
    pub fn new(
        alias: &str,
        model_providers: Vec<(String, Box<dyn ModelProvider>)>,
        max_retries: u32,
        base_backoff_ms: u64,
    ) -> Self {
        let candidates = model_providers
            .into_iter()
            .map(|(family, provider)| {
                (
                    ProviderCandidateDescriptor::requested(&family, None),
                    provider,
                )
            })
            .collect();
        Self::new_with_candidates(alias, candidates, max_retries, base_backoff_ms)
    }

    pub fn new_with_candidates(
        alias: &str,
        model_providers: Vec<(ProviderCandidateDescriptor, Box<dyn ModelProvider>)>,
        max_retries: u32,
        base_backoff_ms: u64,
    ) -> Self {
        Self {
            alias: alias.to_string(),
            model_providers,
            max_retries,
            base_backoff_ms: base_backoff_ms.max(50),
            api_keys: Vec::new(),
            key_index: AtomicUsize::new(0),
            model_fallbacks: HashMap::new(),
            route: ProviderRoute::Main,
        }
    }

    pub fn with_route(mut self, route: ProviderRoute) -> Self {
        self.route = route;
        self
    }
    /// Set additional API keys for round-robin rotation on rate-limit errors.
    pub fn with_api_keys(mut self, keys: Vec<String>) -> Self {
        self.api_keys = keys;
        self
    }

    /// Install per-model failover chains. Fork: production surface — the
    /// fork's V3 `ReliabilityConfig` keeps `model_fallbacks` (see
    /// docs/architecture/reliability.md), so the factory wires the 16-model
    /// production map through here. Upstream had demoted this to test-only.
    pub fn with_model_fallbacks(mut self, fallbacks: HashMap<String, Vec<String>>) -> Self {
        self.model_fallbacks = fallbacks;
        self
    }

    /// Build the list of models to try: [original, alt1, alt2, ...]
    fn model_chain<'a>(&'a self, model: &'a str) -> Vec<&'a str> {
        let mut chain = vec![model];
        if let Some(fallbacks) = self.model_fallbacks.get(model) {
            chain.extend(fallbacks.iter().map(|s| s.as_str()));
        }
        chain
    }

    /// Advance to the next API key and return it, or None if no extra keys configured.
    fn rotate_key(&self) -> Option<&str> {
        if self.api_keys.is_empty() {
            return None;
        }
        let idx = self.key_index.fetch_add(1, Ordering::Relaxed) % self.api_keys.len();
        Some(&self.api_keys[idx])
    }

    /// Compute backoff duration, respecting Retry-After if present.
    fn compute_backoff(&self, base: u64, err: &anyhow::Error) -> u64 {
        let typed_retry_after_ms = typed_retry_after_secs(err)
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(|millis| millis.min(MAX_RETRY_AFTER_SECS as u64 * 1_000));
        if let Some(retry_after) = typed_retry_after_ms.or_else(|| parse_legacy_retry_after_ms(err))
        {
            // Use Retry-After but cap at 30s to avoid indefinite waits
            retry_after.min(30_000).max(base)
        } else {
            base
        }
    }

    /// Shared tail of the empty-completion retry path used by every chat method:
    /// record the empty attempt, warn, sleep the current backoff, then double it
    /// (capped). The caller keeps the emptiness check (it differs per return
    /// type) and the `continue`. See [`is_empty_completion`].
    async fn backoff_after_empty_completion(
        &self,
        failures: &mut Vec<String>,
        provider_name: &str,
        model: &str,
        attempt: u32,
        backoff_ms: &mut u64,
    ) {
        push_failure(
            failures,
            provider_name,
            model,
            attempt + 1,
            self.max_retries + 1,
            "empty_response",
            "model_provider returned an empty completion",
            None,
        );
        ::zeroclaw_log::record!(
            WARN,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                .with_attrs(::serde_json::json!({
                    "model_provider": provider_name,
                    "model": model,
                    "attempt": attempt + 1,
                    "backoff_ms": *backoff_ms
                })),
            "Empty completion; retrying"
        );
        tokio::time::sleep(Duration::from_millis(*backoff_ms)).await;
        *backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
    }
}

#[async_trait]
impl ModelProvider for ReliableModelProvider {
    async fn warmup(&self) -> anyhow::Result<()> {
        for (name, model_provider) in &self.model_providers {
            ::zeroclaw_log::record!(
                INFO,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({"model_provider": name})),
                "Warming up model_provider connection pool"
            );
            if ProviderDispatch::from_ref(&**model_provider)
                .warmup()
                .await
                .is_err()
            {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(::serde_json::json!({"model_provider": name})),
                    "Warmup failed (non-fatal)"
                );
            }
        }
        Ok(())
    }

    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        let models = self.model_chain(model);
        let mut failures = Vec::new();
        let mut attempts_for_call = 0;
        let mut terminal_failure = None;

        // Outer: model fallback chain. Middle: model_provider priority. Inner: retries.
        // Each iteration: attempt one (model_provider, model) call. On success, return
        // immediately. On non-retryable error, break to next model_provider. On
        // retryable error, sleep with exponential backoff and retry.
        for current_model in &models {
            for (provider_name, model_provider) in &self.model_providers {
                let effective_model = provider_name.effective_model(current_model);
                let mut backoff_ms = self.base_backoff_ms;
                let mut last_error_detail: Option<String> = None;
                let mut last_diagnostic: Option<ProviderErrorDiagnostic> = None;

                for attempt in 0..=self.max_retries {
                    attempts_for_call += 1;
                    match ProviderDispatch::from_ref(&**model_provider)
                        .chat_with_system(system_prompt, message, effective_model, temperature)
                        .await
                    {
                        Ok(resp) => {
                            // Re-roll a transient empty completion instead of
                            // returning a blank turn (bounded by `max_retries`).
                            if attempt < self.max_retries && resp.trim().is_empty() {
                                self.backoff_after_empty_completion(
                                    &mut failures,
                                    provider_name,
                                    effective_model,
                                    attempt,
                                    &mut backoff_ms,
                                )
                                .await;
                                continue;
                            }
                            if attempt > 0
                                || effective_model != model
                                || self.model_providers.first().map(|(n, _)| n.as_str())
                                    != Some(provider_name)
                            {
                                ::zeroclaw_log::record!(INFO, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(::serde_json::json!({"model_provider": provider_name, "model": effective_model, "attempt": attempt, "original_model": model})), "ModelProvider recovered (failover/retry)");
                                let primary = self
                                    .model_providers
                                    .first()
                                    .map(|(n, _)| n.as_str())
                                    .unwrap_or("");
                                record_provider_fallback(
                                    primary,
                                    model,
                                    provider_name,
                                    effective_model,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(e) => {
                            // Context window exceeded: no history to truncate
                            // in chat_with_system, bail immediately.
                            if is_context_window_exceeded(&e) {
                                return Err(terminal_provider_error(
                                    provider_name,
                                    current_model,
                                    self.route,
                                    attempts_for_call,
                                    &e,
                                ));
                            }

                            let non_retryable_rate_limit = is_non_retryable_rate_limit(&e);
                            let non_retryable = is_non_retryable(&e) || non_retryable_rate_limit;
                            let rate_limited = is_rate_limited(&e);
                            let failure_reason = failure_reason(rate_limited, non_retryable);
                            let error_detail = compact_error_detail(&e);
                            let diagnostic = provider_error_diagnostic(&e);
                            last_error_detail = Some(error_detail.clone());
                            last_diagnostic = Some(diagnostic.clone());
                            terminal_failure = Some(TerminalProviderFailure::new(
                                provider_name,
                                current_model,
                                self.route,
                                attempts_for_call,
                                diagnostic.clone(),
                            ));

                            push_failure(
                                &mut failures,
                                provider_name,
                                effective_model,
                                attempt + 1,
                                self.max_retries + 1,
                                failure_reason,
                                &error_detail,
                                Some(&diagnostic),
                            );

                            // Rate-limit with rotatable keys: cycle to the next API key
                            // so the retry hits a different quota bucket.
                            if rate_limited
                                && !non_retryable_rate_limit
                                && let Some(new_key) = self.rotate_key()
                            {
                                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_name, "error": error_detail})), &format!("Rate limited; key rotation selected key ending ...{} \
                                     but cannot apply (ModelProvider trait has no set_api_key). \
                                     Retrying with original key.", &new_key[new_key.len().saturating_sub(4)..]));
                            }

                            if non_retryable {
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_failure_attrs(
                                            provider_name,
                                            effective_model,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "Non-retryable error, moving on"
                                );
                                break;
                            }

                            if attempt < self.max_retries {
                                let wait = self.compute_backoff(backoff_ms, &e);
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_retry_attrs(
                                            provider_name,
                                            effective_model,
                                            attempt + 1,
                                            wait,
                                            failure_reason,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "ModelProvider call failed, retrying"
                                );
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                                backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
                            }
                        }
                    }
                }

                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(provider_exhausted_attrs(
                            provider_name,
                            effective_model,
                            last_error_detail.as_deref(),
                            last_diagnostic.as_ref(),
                        )),
                    "Exhausted retries, trying next model_provider/model"
                );
            }

            if *current_model != model {
                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"original_model": model, "fallback_model": *current_model})), "Model fallback exhausted all model_providers, trying next fallback model");
            }
        }

        terminal_failure.map_or_else(
            || anyhow::bail!("No model provider candidates were configured"),
            |failure| Err(failure.into()),
        )
    }

    async fn chat_with_history(
        &self,
        messages: &[ChatMessage],
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        let models = self.model_chain(model);
        let mut failures = Vec::new();
        let mut attempts_for_call = 0;
        let mut terminal_failure = None;

        for current_model in &models {
            for (provider_name, model_provider) in &self.model_providers {
                let effective_model = provider_name.effective_model(current_model);
                let mut backoff_ms = self.base_backoff_ms;
                let mut last_error_detail: Option<String> = None;
                let mut last_diagnostic: Option<ProviderErrorDiagnostic> = None;

                for attempt in 0..=self.max_retries {
                    attempts_for_call += 1;
                    match ProviderDispatch::from_ref(&**model_provider)
                        .chat_with_history(messages, effective_model, temperature)
                        .await
                    {
                        Ok(resp) => {
                            // Re-roll a transient empty completion instead of
                            // returning a blank turn (bounded by `max_retries`).
                            if attempt < self.max_retries && resp.trim().is_empty() {
                                self.backoff_after_empty_completion(
                                    &mut failures,
                                    provider_name,
                                    effective_model,
                                    attempt,
                                    &mut backoff_ms,
                                )
                                .await;
                                continue;
                            }
                            if attempt > 0
                                || effective_model != model
                                || self.model_providers.first().map(|(n, _)| n.as_str())
                                    != Some(provider_name)
                            {
                                ::zeroclaw_log::record!(INFO, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(::serde_json::json!({"model_provider": provider_name, "model": effective_model, "attempt": attempt, "original_model": model})), "ModelProvider recovered (failover/retry)");
                                let primary = self
                                    .model_providers
                                    .first()
                                    .map(|(n, _)| n.as_str())
                                    .unwrap_or("");
                                record_provider_fallback(
                                    primary,
                                    model,
                                    provider_name,
                                    effective_model,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(e) => {
                            if is_context_window_exceeded(&e) {
                                return Err(terminal_provider_error(
                                    provider_name,
                                    current_model,
                                    self.route,
                                    attempts_for_call,
                                    &e,
                                ));
                            }

                            let non_retryable_rate_limit = is_non_retryable_rate_limit(&e);
                            let non_retryable = is_non_retryable(&e) || non_retryable_rate_limit;
                            let rate_limited = is_rate_limited(&e);
                            let failure_reason = failure_reason(rate_limited, non_retryable);
                            let error_detail = compact_error_detail(&e);
                            let diagnostic = provider_error_diagnostic(&e);
                            last_error_detail = Some(error_detail.clone());
                            last_diagnostic = Some(diagnostic.clone());
                            terminal_failure = Some(TerminalProviderFailure::new(
                                provider_name,
                                current_model,
                                self.route,
                                attempts_for_call,
                                diagnostic.clone(),
                            ));

                            push_failure(
                                &mut failures,
                                provider_name,
                                effective_model,
                                attempt + 1,
                                self.max_retries + 1,
                                failure_reason,
                                &error_detail,
                                Some(&diagnostic),
                            );

                            if rate_limited
                                && !non_retryable_rate_limit
                                && let Some(new_key) = self.rotate_key()
                            {
                                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_name, "error": error_detail})), &format!("Rate limited; key rotation selected key ending ...{} \
                                     but cannot apply (ModelProvider trait has no set_api_key). \
                                     Retrying with original key.", &new_key[new_key.len().saturating_sub(4)..]));
                            }

                            if non_retryable {
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_failure_attrs(
                                            provider_name,
                                            effective_model,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "Non-retryable error, moving on"
                                );
                                break;
                            }

                            if attempt < self.max_retries {
                                let wait = self.compute_backoff(backoff_ms, &e);
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_retry_attrs(
                                            provider_name,
                                            effective_model,
                                            attempt + 1,
                                            wait,
                                            failure_reason,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "ModelProvider call failed, retrying"
                                );
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                                backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
                            }
                        }
                    }
                }

                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(provider_exhausted_attrs(
                            provider_name,
                            effective_model,
                            last_error_detail.as_deref(),
                            last_diagnostic.as_ref(),
                        )),
                    "Exhausted retries, trying next model_provider/model"
                );
            }
        }

        terminal_failure.map_or_else(
            || anyhow::bail!("No model provider candidates were configured"),
            |failure| Err(failure.into()),
        )
    }

    fn supports_native_tools(&self) -> bool {
        self.model_providers
            .first()
            .map(|(_, p)| p.supports_native_tools())
            .unwrap_or(false)
    }

    fn supports_vision(&self) -> bool {
        self.model_providers
            .first()
            .map(|(_, p)| p.supports_vision())
            .unwrap_or(false)
    }

    async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        let models = self.model_chain(model);
        let mut failures = Vec::new();
        let mut attempts_for_call = 0;
        let mut terminal_failure = None;

        for current_model in &models {
            for (provider_name, model_provider) in &self.model_providers {
                let effective_model = provider_name.effective_model(current_model);
                let mut backoff_ms = self.base_backoff_ms;
                let mut last_error_detail: Option<String> = None;
                let mut last_diagnostic: Option<ProviderErrorDiagnostic> = None;

                for attempt in 0..=self.max_retries {
                    attempts_for_call += 1;
                    match ProviderDispatch::from_ref(&**model_provider)
                        .chat_with_tools(messages, tools, effective_model, temperature)
                        .await
                    {
                        Ok(resp) => {
                            // Re-roll a transient empty completion instead of
                            // returning a blank turn (bounded by `max_retries`;
                            // see `is_empty_completion`).
                            if attempt < self.max_retries && is_empty_completion(&resp) {
                                self.backoff_after_empty_completion(
                                    &mut failures,
                                    provider_name,
                                    effective_model,
                                    attempt,
                                    &mut backoff_ms,
                                )
                                .await;
                                continue;
                            }
                            if attempt > 0
                                || effective_model != model
                                || self.model_providers.first().map(|(n, _)| n.as_str())
                                    != Some(provider_name)
                            {
                                ::zeroclaw_log::record!(INFO, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(::serde_json::json!({"model_provider": provider_name, "model": effective_model, "attempt": attempt, "original_model": model})), "ModelProvider recovered (failover/retry)");
                                let primary = self
                                    .model_providers
                                    .first()
                                    .map(|(n, _)| n.as_str())
                                    .unwrap_or("");
                                record_provider_fallback(
                                    primary,
                                    model,
                                    provider_name,
                                    effective_model,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(e) => {
                            if is_context_window_exceeded(&e) {
                                return Err(terminal_provider_error(
                                    provider_name,
                                    current_model,
                                    self.route,
                                    attempts_for_call,
                                    &e,
                                ));
                            }

                            let non_retryable_rate_limit = is_non_retryable_rate_limit(&e);
                            let non_retryable = is_non_retryable(&e) || non_retryable_rate_limit;
                            let rate_limited = is_rate_limited(&e);
                            let failure_reason = failure_reason(rate_limited, non_retryable);
                            let error_detail = compact_error_detail(&e);
                            let diagnostic = provider_error_diagnostic(&e);
                            last_error_detail = Some(error_detail.clone());
                            last_diagnostic = Some(diagnostic.clone());
                            terminal_failure = Some(TerminalProviderFailure::new(
                                provider_name,
                                current_model,
                                self.route,
                                attempts_for_call,
                                diagnostic.clone(),
                            ));

                            push_failure(
                                &mut failures,
                                provider_name,
                                effective_model,
                                attempt + 1,
                                self.max_retries + 1,
                                failure_reason,
                                &error_detail,
                                Some(&diagnostic),
                            );

                            if rate_limited
                                && !non_retryable_rate_limit
                                && let Some(new_key) = self.rotate_key()
                            {
                                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_name, "error": error_detail})), &format!("Rate limited; key rotation selected key ending ...{} \
                                     but cannot apply (ModelProvider trait has no set_api_key). \
                                     Retrying with original key.", &new_key[new_key.len().saturating_sub(4)..]));
                            }

                            if non_retryable {
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_failure_attrs(
                                            provider_name,
                                            effective_model,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "Non-retryable error, moving on"
                                );
                                break;
                            }

                            if attempt < self.max_retries {
                                let wait = self.compute_backoff(backoff_ms, &e);
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_retry_attrs(
                                            provider_name,
                                            effective_model,
                                            attempt + 1,
                                            wait,
                                            failure_reason,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "ModelProvider call failed, retrying"
                                );
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                                backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
                            }
                        }
                    }
                }

                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(provider_exhausted_attrs(
                            provider_name,
                            effective_model,
                            last_error_detail.as_deref(),
                            last_diagnostic.as_ref(),
                        )),
                    "Exhausted retries, trying next model_provider/model"
                );
            }
        }

        terminal_failure.map_or_else(
            || anyhow::bail!("No model provider candidates were configured"),
            |failure| Err(failure.into()),
        )
    }

    async fn chat(
        &self,
        request: ChatRequest<'_>,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        let models = self.model_chain(model);
        let mut failures = Vec::new();
        let mut attempts_for_call = 0;
        let mut terminal_failure = None;

        for current_model in &models {
            for (provider_name, model_provider) in &self.model_providers {
                let effective_model = provider_name.effective_model(current_model);
                let mut backoff_ms = self.base_backoff_ms;
                let mut last_error_detail: Option<String> = None;
                let mut last_diagnostic: Option<ProviderErrorDiagnostic> = None;

                for attempt in 0..=self.max_retries {
                    attempts_for_call += 1;
                    let req = ChatRequest {
                        messages: request.messages,
                        tools: request.tools,
                        thinking: request.thinking,
                    };
                    match ProviderDispatch::from_ref(&**model_provider)
                        .chat(req, effective_model, temperature)
                        .await
                    {
                        Ok(resp) => {
                            // Re-roll a transient empty completion instead of
                            // returning a blank turn (bounded by `max_retries`;
                            // see `is_empty_completion`).
                            if attempt < self.max_retries && is_empty_completion(&resp) {
                                self.backoff_after_empty_completion(
                                    &mut failures,
                                    provider_name,
                                    effective_model,
                                    attempt,
                                    &mut backoff_ms,
                                )
                                .await;
                                continue;
                            }
                            if attempt > 0
                                || effective_model != model
                                || self.model_providers.first().map(|(n, _)| n.as_str())
                                    != Some(provider_name)
                            {
                                ::zeroclaw_log::record!(INFO, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_attrs(::serde_json::json!({"model_provider": provider_name, "model": effective_model, "attempt": attempt, "original_model": model})), "ModelProvider recovered (failover/retry)");
                                let primary = self
                                    .model_providers
                                    .first()
                                    .map(|(n, _)| n.as_str())
                                    .unwrap_or("");
                                record_provider_fallback(
                                    primary,
                                    model,
                                    provider_name,
                                    effective_model,
                                );
                            }
                            return Ok(resp);
                        }
                        Err(e) => {
                            if is_context_window_exceeded(&e) {
                                return Err(terminal_provider_error(
                                    provider_name,
                                    current_model,
                                    self.route,
                                    attempts_for_call,
                                    &e,
                                ));
                            }

                            let non_retryable_rate_limit = is_non_retryable_rate_limit(&e);
                            let non_retryable = is_non_retryable(&e) || non_retryable_rate_limit;
                            let rate_limited = is_rate_limited(&e);
                            let failure_reason = failure_reason(rate_limited, non_retryable);
                            let error_detail = compact_error_detail(&e);
                            let diagnostic = provider_error_diagnostic(&e);
                            last_error_detail = Some(error_detail.clone());
                            last_diagnostic = Some(diagnostic.clone());
                            terminal_failure = Some(TerminalProviderFailure::new(
                                provider_name,
                                current_model,
                                self.route,
                                attempts_for_call,
                                diagnostic.clone(),
                            ));

                            push_failure(
                                &mut failures,
                                provider_name,
                                effective_model,
                                attempt + 1,
                                self.max_retries + 1,
                                failure_reason,
                                &error_detail,
                                Some(&diagnostic),
                            );

                            if rate_limited
                                && !non_retryable_rate_limit
                                && let Some(new_key) = self.rotate_key()
                            {
                                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_name, "error": error_detail})), &format!("Rate limited; key rotation selected key ending ...{} \
                                     but cannot apply (ModelProvider trait has no set_api_key). \
                                     Retrying with original key.", &new_key[new_key.len().saturating_sub(4)..]));
                            }

                            if non_retryable {
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_failure_attrs(
                                            provider_name,
                                            effective_model,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "Non-retryable error, moving on"
                                );
                                break;
                            }

                            if attempt < self.max_retries {
                                let wait = self.compute_backoff(backoff_ms, &e);
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        module_path!(),
                                        ::zeroclaw_log::Action::Note
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                                    .with_attrs(
                                        provider_retry_attrs(
                                            provider_name,
                                            effective_model,
                                            attempt + 1,
                                            wait,
                                            failure_reason,
                                            &error_detail,
                                            &diagnostic,
                                        )
                                    ),
                                    "ModelProvider call failed, retrying"
                                );
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                                backoff_ms = (backoff_ms.saturating_mul(2)).min(10_000);
                            }
                        }
                    }
                }

                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(provider_exhausted_attrs(
                            provider_name,
                            effective_model,
                            last_error_detail.as_deref(),
                            last_diagnostic.as_ref(),
                        )),
                    "Exhausted retries, trying next model_provider/model"
                );
            }

            if *current_model != model {
                ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"original_model": model, "fallback_model": *current_model})), "Model fallback exhausted all model_providers, trying next fallback model");
            }
        }

        terminal_failure.map_or_else(
            || anyhow::bail!("No model provider candidates were configured"),
            |failure| Err(failure.into()),
        )
    }

    fn supports_streaming(&self) -> bool {
        self.model_providers
            .iter()
            .any(|(_, p)| p.supports_streaming())
    }

    fn supports_streaming_tool_events(&self) -> bool {
        self.model_providers
            .iter()
            .any(|(_, p)| p.supports_streaming_tool_events())
    }

    fn stream_chat(
        &self,
        request: ChatRequest<'_>,
        model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> stream::BoxStream<'static, StreamResult<StreamEvent>> {
        let needs_tool_events = request.tools.is_some_and(|tools| !tools.is_empty());

        for (provider_name, model_provider) in &self.model_providers {
            if !model_provider.supports_streaming() || !options.enabled {
                continue;
            }

            if needs_tool_events && !model_provider.supports_streaming_tool_events() {
                continue;
            }

            let provider_clone = provider_name.clone();

            let current_model = self
                .model_chain(model)
                .first()
                .copied()
                .unwrap_or(model)
                .to_string();

            let req = ChatRequest {
                messages: request.messages,
                tools: request.tools,
                thinking: request.thinking,
            };
            let stream = ProviderDispatch::from_ref(&**model_provider).stream_chat(
                req,
                &current_model,
                temperature,
                options,
            );
            let (tx, rx) = tokio::sync::mpsc::channel::<StreamResult<StreamEvent>>(100);

            let handle = ::zeroclaw_spawn::spawn!(async move {
                let mut stream = stream;
                while let Some(event) = stream.next().await {
                    if let Err(ref e) = event {
                        ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_clone, "model": current_model, "e": e.to_string()})), "Streaming error: ");
                    }
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            });

            let guard = AbortOnDrop::new(handle.abort_handle());
            return stream::unfold((rx, guard), |(mut rx, guard)| async move {
                rx.recv().await.map(|event| (event, (rx, guard)))
            })
            .boxed();
        }

        let message = if needs_tool_events {
            "No model_provider supports streaming tool events".to_string()
        } else {
            "No model_provider supports streaming".to_string()
        };
        stream::once(async move { Err(super::traits::StreamError::ModelProvider(message)) }).boxed()
    }

    fn stream_chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> stream::BoxStream<'static, StreamResult<StreamChunk>> {
        // Try each model_provider/model combination for streaming
        // For streaming, we use the first model_provider that supports it and has streaming enabled
        for (provider_name, model_provider) in &self.model_providers {
            if !model_provider.supports_streaming() || !options.enabled {
                continue;
            }

            // Clone model_provider data for the stream
            let provider_clone = provider_name.clone();

            // Try the first model in the chain for streaming
            let current_model = match self.model_chain(model).first() {
                Some(m) => (*m).to_string(),
                None => model.to_string(),
            };

            // For streaming, we attempt once and propagate errors
            // The caller can retry the entire request if needed
            let stream = model_provider.stream_chat_with_system(
                system_prompt,
                message,
                &current_model,
                temperature,
                options,
            );

            // Use a channel to bridge the stream with logging
            let (tx, rx) = tokio::sync::mpsc::channel::<StreamResult<StreamChunk>>(100);

            let handle = ::zeroclaw_spawn::spawn!(async move {
                let mut stream = stream;
                while let Some(chunk) = stream.next().await {
                    if let Err(ref e) = chunk {
                        ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_clone, "model": current_model, "e": e.to_string()})), "Streaming error: ");
                    }
                    if tx.send(chunk).await.is_err() {
                        break; // Receiver dropped
                    }
                }
            });

            // Convert channel receiver to stream
            let guard = AbortOnDrop::new(handle.abort_handle());
            return stream::unfold((rx, guard), |(mut rx, guard)| async move {
                rx.recv().await.map(|chunk| (chunk, (rx, guard)))
            })
            .boxed();
        }

        // No streaming support available
        stream::once(async move {
            Err(super::traits::StreamError::ModelProvider(
                "No model_provider supports streaming".to_string(),
            ))
        })
        .boxed()
    }

    fn stream_chat_with_history(
        &self,
        messages: &[ChatMessage],
        model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> stream::BoxStream<'static, StreamResult<StreamChunk>> {
        // Try each model_provider/model combination for streaming with history.
        // Mirrors stream_chat_with_system but delegates to the underlying
        // model_provider's stream_chat_with_history, preserving the full conversation.
        for (provider_name, model_provider) in &self.model_providers {
            if !model_provider.supports_streaming() || !options.enabled {
                continue;
            }

            let provider_clone = provider_name.clone();

            let current_model = match self.model_chain(model).first() {
                Some(m) => (*m).to_string(),
                None => model.to_string(),
            };

            let stream = model_provider.stream_chat_with_history(
                messages,
                &current_model,
                temperature,
                options,
            );

            let (tx, rx) = tokio::sync::mpsc::channel::<StreamResult<StreamChunk>>(100);

            let handle = ::zeroclaw_spawn::spawn!(async move {
                let mut stream = stream;
                while let Some(chunk) = stream.next().await {
                    if let Err(ref e) = chunk {
                        ::zeroclaw_log::record!(WARN, ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note).with_outcome(::zeroclaw_log::EventOutcome::Unknown).with_attrs(::serde_json::json!({"model_provider": provider_clone, "model": current_model, "e": e.to_string()})), "Streaming error: ");
                    }
                    if tx.send(chunk).await.is_err() {
                        break; // Receiver dropped
                    }
                }
            });

            let guard = AbortOnDrop::new(handle.abort_handle());
            return stream::unfold((rx, guard), |(mut rx, guard)| async move {
                rx.recv().await.map(|chunk| (chunk, (rx, guard)))
            })
            .boxed();
        }

        // No streaming support available
        stream::once(async move {
            Err(super::traits::StreamError::ModelProvider(
                "No model_provider supports streaming".to_string(),
            ))
        })
        .boxed()
    }
}

impl ::zeroclaw_api::attribution::Attributable for ReliableModelProvider {
    fn role(&self) -> ::zeroclaw_api::attribution::Role {
        // Delegate to the primary (first) inner provider so the on-disk
        // model_provider_type reflects the concrete provider
        // (`anthropic`, `openai`, …) rather than the wrapper kind.
        // If the wrapper somehow held zero providers we fall back to
        // the parent `System` role — log emissions in that degenerate
        // state are not user-facing.
        match self.model_providers.first() {
            Some((_, p)) => ::zeroclaw_api::attribution::Attributable::role(&**p),
            None => ::zeroclaw_api::attribution::Role::System,
        }
    }

    fn alias(&self) -> &str {
        // Delegate to the primary inner provider for the same reason
        // as `role()`. Falls back to the wrapper's own configured alias
        // when no inner provider is registered.
        match self.model_providers.first() {
            Some((_, p)) => ::zeroclaw_api::attribution::Attributable::alias(&**p),
            None => &self.alias,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::sync::Arc;
    use zeroclaw_api::tool::ToolSpec;

    struct MockModelProvider {
        calls: Arc<AtomicUsize>,
        fail_until_attempt: usize,
        response: &'static str,
        error: &'static str,
    }

    #[async_trait]
    impl ModelProvider for MockModelProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= self.fail_until_attempt {
                anyhow::bail!(self.error);
            }
            Ok(self.response.to_string())
        }

        async fn chat_with_history(
            &self,
            _messages: &[ChatMessage],
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= self.fail_until_attempt {
                anyhow::bail!(self.error);
            }
            Ok(self.response.to_string())
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for MockModelProvider {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "MockModelProvider"
        }
    }

    /// Mock that records which model was used for each call.
    struct ModelAwareMock {
        calls: Arc<AtomicUsize>,
        models_seen: parking_lot::Mutex<Vec<String>>,
        fail_models: Vec<&'static str>,
        response: &'static str,
    }

    #[async_trait]
    impl ModelProvider for ModelAwareMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.models_seen.lock().push(model.to_string());
            if self.fail_models.contains(&model) {
                anyhow::bail!("500 model {} unavailable", model);
            }
            Ok(self.response.to_string())
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for ModelAwareMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "ModelAwareMock"
        }
    }

    // ── Existing tests (preserved) ──

    #[tokio::test]
    async fn succeeds_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 0,
                    response: "ok",
                    error: "boom",
                }),
            )],
            2,
            1,
        );

        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_then_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 1,
                    response: "recovered",
                    error: "temporary",
                }),
            )],
            2,
            1,
        );

        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "recovered");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn falls_back_after_retries_exhausted() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&primary_calls),
                        fail_until_attempt: usize::MAX,
                        response: "never",
                        error: "primary down",
                    }),
                ),
                (
                    "fallback".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&fallback_calls),
                        fail_until_attempt: 0,
                        response: "from fallback",
                        error: "fallback down",
                    }),
                ),
            ],
            1,
            1,
        );

        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "from fallback");
        assert_eq!(primary_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    /// Returns an empty completion (blank `chat_with_system` text, which the
    /// default `chat`/`chat_with_tools`/`chat_with_history` impls surface as a
    /// blank `ChatResponse`) for the first `empty_until_attempt` calls, then a
    /// non-empty response. Counts total calls so tests can assert re-rolls.
    struct EmptyThenTextMock {
        calls: Arc<AtomicUsize>,
        empty_until_attempt: usize,
        response: &'static str,
    }

    #[async_trait]
    impl ModelProvider for EmptyThenTextMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= self.empty_until_attempt {
                Ok(String::new())
            } else {
                Ok(self.response.to_string())
            }
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for EmptyThenTextMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "EmptyThenTextMock"
        }
    }

    #[tokio::test]
    async fn chat_retries_empty_completion_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: 1,
                    response: "recovered",
                }),
            )],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("recovered"));
        // One empty completion + one successful re-roll.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn chat_with_tools_retries_empty_completion_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: 1,
                    response: "recovered",
                }),
            )],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let result = model_provider
            .chat_with_tools(&messages, &[], "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("recovered"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn chat_with_history_retries_empty_string_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: 1,
                    response: "recovered",
                }),
            )],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let result = model_provider
            .chat_with_history(&messages, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "recovered");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn chat_with_system_retries_empty_string_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: 1,
                    response: "recovered",
                }),
            )],
            3,
            1,
        );

        // `simple_chat` routes through `ReliableModelProvider::chat_with_system`,
        // the path subagent delegation uses.
        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "recovered");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn chat_persistent_empty_returns_blank_without_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: usize::MAX, // always empty
                    response: "never",
                }),
            )],
            2,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        // Exhausting the empty re-rolls returns the last (blank) response rather
        // than erroring — strictly never worse than the pre-fix behavior.
        let result = model_provider
            .chat(request, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some(""));
        // Initial attempt + max_retries (2) re-rolls = 3 calls.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn chat_nonempty_response_is_not_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(EmptyThenTextMock {
                    calls: Arc::clone(&calls),
                    empty_until_attempt: 0, // never empty
                    response: "direct",
                }),
            )],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("direct"));
        // A non-empty response must not trigger any re-roll.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn returns_typed_terminal_error_when_all_providers_fail() {
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "p1".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail_until_attempt: usize::MAX,
                        response: "never",
                        error: "p1 error",
                    }),
                ),
                (
                    "p2".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail_until_attempt: usize::MAX,
                        response: "never",
                        error: "p2 error",
                    }),
                ),
            ],
            0,
            1,
        );

        let err = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .expect_err("all model_providers should fail");
        let terminal = terminal_provider_failure(&err).expect("typed terminal evidence");
        assert_eq!(terminal.actual_provider(), "p2");
        assert_eq!(terminal.actual_model(), "test");
        assert_eq!(terminal.attempts_for_call(), 2);
        assert_eq!(
            terminal.diagnostic().disposition(),
            ProviderErrorDisposition::Retryable
        );
        assert!(!err.to_string().contains("p2 error"));
    }

    struct TerminalFailureMock {
        calls: Arc<AtomicUsize>,
        error: &'static str,
    }

    impl TerminalFailureMock {
        fn fail<T>(&self) -> anyhow::Result<T> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!(self.error)
        }
    }

    #[async_trait]
    impl ModelProvider for TerminalFailureMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            self.fail()
        }

        async fn chat_with_history(
            &self,
            _messages: &[ChatMessage],
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            self.fail()
        }

        async fn chat_with_tools(
            &self,
            _messages: &[ChatMessage],
            _tools: &[serde_json::Value],
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            self.fail()
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            self.fail()
        }
    }

    impl ::zeroclaw_api::attribution::Attributable for TerminalFailureMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }

        fn alias(&self) -> &str {
            "TerminalFailureMock"
        }
    }

    async fn final_terminal_error(error: &'static str) -> anyhow::Error {
        let provider = ReliableModelProvider::new(
            "configured-alias",
            vec![(
                "custom".to_string(),
                Box::new(TerminalFailureMock {
                    calls: Arc::new(AtomicUsize::new(0)),
                    error,
                }),
            )],
            0,
            1,
        );

        provider
            .chat_with_system(None, "hello", "requested-model", None)
            .await
            .expect_err("provider should return a terminal failure")
    }

    #[tokio::test]
    async fn public_auth_classifier_recognizes_sanitized_terminal_failures() {
        for message in [
            "401 Unauthorized",
            "403 Forbidden",
            "OpenAI Codex OAuth token expired",
        ] {
            let error = final_terminal_error(message).await;
            let terminal = terminal_provider_failure(&error).expect("typed terminal failure");

            assert_eq!(terminal.diagnostic().kind(), "auth", "{message}");
            assert!(is_auth_error(&error), "{message}");
        }
    }

    #[tokio::test]
    async fn public_non_retryable_classifier_uses_terminal_disposition() {
        for message in [
            "404 model not found",
            "400 malformed provider request",
            r#"429 Too Many Requests: {"code":1311,"message":"package unavailable"}"#,
        ] {
            let error = final_terminal_error(message).await;
            let terminal = terminal_provider_failure(&error).expect("typed terminal failure");

            assert!(
                matches!(
                    terminal.diagnostic().disposition(),
                    ProviderErrorDisposition::NonRetryable
                        | ProviderErrorDisposition::RateLimitedNonRetryable
                ),
                "{message}"
            );
            assert!(is_non_retryable(&error), "{message}");
        }
    }

    #[tokio::test]
    async fn public_non_retryable_classifier_keeps_terminal_retryable_exceptions() {
        for message in [
            "429 Too Many Requests: retry later",
            "maximum context length exceeded",
        ] {
            let error = final_terminal_error(message).await;

            assert!(!is_non_retryable(&error), "{message}");
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum NonStreamingMethod {
        System,
        History,
        Tools,
        Chat,
    }

    #[tokio::test]
    async fn all_non_streaming_methods_return_the_same_typed_terminal_contract() {
        for method in [
            NonStreamingMethod::System,
            NonStreamingMethod::History,
            NonStreamingMethod::Tools,
            NonStreamingMethod::Chat,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let candidate = ProviderCandidateDescriptor::pinned(
                "openai",
                Some("private-backup"),
                "private-effective-model",
            );
            let model_provider = ReliableModelProvider::new_with_candidates(
                "requested-alias",
                vec![(
                    candidate.clone(),
                    Box::new(TerminalFailureMock {
                        calls: Arc::clone(&calls),
                        error: "503 provider body contains sk-secretvalue123 at \
                                https://user:password@provider.example/v1?token=secret",
                    }) as Box<dyn ModelProvider>,
                )],
                1,
                1,
            )
            .with_route(ProviderRoute::Vision);
            let messages = vec![ChatMessage::user("hello")];

            let err = match method {
                NonStreamingMethod::System => model_provider
                    .chat_with_system(None, "hello", "public-request-model", Some(0.0))
                    .await
                    .map(|_| ()),
                NonStreamingMethod::History => model_provider
                    .chat_with_history(&messages, "public-request-model", Some(0.0))
                    .await
                    .map(|_| ()),
                NonStreamingMethod::Tools => model_provider
                    .chat_with_tools(&messages, &[], "public-request-model", Some(0.0))
                    .await
                    .map(|_| ()),
                NonStreamingMethod::Chat => model_provider
                    .chat(
                        ChatRequest {
                            messages: &messages,
                            tools: None,
                            thinking: None,
                        },
                        "public-request-model",
                        Some(0.0),
                    )
                    .await
                    .map(|_| ()),
            }
            .expect_err("terminal provider failure expected");

            let wrapped = err.context("outer request context");
            let terminal = wrapped
                .downcast_ref::<TerminalProviderFailure>()
                .expect("anyhow downcast must find the typed source through context");
            assert!(std::ptr::eq(
                terminal,
                terminal_provider_failure(&wrapped).expect("central extractor")
            ));
            assert_eq!(terminal.actual_provider(), "private-backup");
            assert_eq!(terminal.provider_family(), "openai");
            assert_eq!(terminal.actual_model(), "private-effective-model");
            assert_eq!(terminal.route(), ProviderRoute::Vision);
            assert_eq!(terminal.attempts_for_call(), 2);
            assert_eq!(terminal.diagnostic().kind(), "provider_server");
            assert_eq!(terminal.diagnostic().status(), None);
            assert_eq!(
                terminal.diagnostic().disposition(),
                ProviderErrorDisposition::Retryable
            );
            assert_eq!(
                terminal.diagnostic().endpoint(),
                Some("https://provider.example/v1")
            );
            let safe = terminal.to_string();
            assert!(!safe.contains("provider body"), "{safe}");
            assert!(!safe.contains("sk-secretvalue123"), "{safe}");
            assert!(!safe.contains("password"), "{safe}");
            assert_eq!(calls.load(Ordering::SeqCst), 2, "{method:?}");
        }
    }

    #[tokio::test]
    async fn context_window_failure_is_typed_and_stops_after_first_real_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new_with_candidates(
            "primary",
            vec![
                (
                    ProviderCandidateDescriptor::requested("openai", Some("primary")),
                    Box::new(TerminalFailureMock {
                        calls: Arc::clone(&calls),
                        error: "400 maximum context length exceeded",
                    }) as Box<dyn ModelProvider>,
                ),
                (
                    ProviderCandidateDescriptor::requested("openai", Some("backup")),
                    Box::new(TerminalFailureMock {
                        calls: Arc::clone(&fallback_calls),
                        error: "fallback must not run",
                    }) as Box<dyn ModelProvider>,
                ),
            ],
            3,
            1,
        );
        let messages = vec![
            ChatMessage::system("system"),
            ChatMessage::user("old"),
            ChatMessage::assistant("reply"),
            ChatMessage::user("current"),
        ];

        let err = model_provider
            .chat_with_history(&messages, "requested", Some(0.0))
            .await
            .expect_err("context overflow must be delegated to the outer owner");
        let terminal = terminal_provider_failure(&err).expect("typed context evidence");
        assert_eq!(terminal.diagnostic().kind(), "context_window");
        assert_eq!(terminal.diagnostic().status(), None);
        assert_eq!(terminal.attempts_for_call(), 1);
        assert!(is_context_window_exceeded(&err));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn classifier_keeps_kind_status_and_disposition_separate() {
        let cases = [
            (
                "429 Too Many Requests: retry later",
                "rate_limited",
                None,
                ProviderErrorDisposition::RateLimited,
            ),
            (
                "429 Too Many Requests: insufficient quota",
                "rate_limited",
                None,
                ProviderErrorDisposition::RateLimitedNonRetryable,
            ),
            (
                "401 Unauthorized",
                "auth",
                None,
                ProviderErrorDisposition::NonRetryable,
            ),
            (
                "503 Service Unavailable",
                "provider_server",
                None,
                ProviderErrorDisposition::Retryable,
            ),
        ];

        for (message, kind, status, disposition) in cases {
            let diagnostic = provider_error_diagnostic(&anyhow::Error::msg(message));
            assert_eq!(diagnostic.kind(), kind, "{message}");
            assert_eq!(diagnostic.status(), status, "{message}");
            assert_eq!(diagnostic.disposition(), disposition, "{message}");
        }
    }

    #[test]
    fn legacy_retry_after_is_bounded_but_never_becomes_public_metadata() {
        let cases = [
            ("429 Retry-After: 2.0001", Some((3, 2_001))),
            ("429 Retry-After: 1e308", Some((86_400, 86_400_000))),
            ("429 Retry-After: NaN", None),
            ("429 Retry-After: inf", None),
            ("429 Retry-After: -1", None),
            ("429 Retry-After: nope", None),
        ];

        for (message, expected) in cases {
            let error = anyhow::Error::msg(message);
            let parsed = parse_legacy_retry_after(&error);
            assert_eq!(
                parsed.map(|value| (value.public_secs, value.millis)),
                expected,
                "{message}"
            );
            assert_eq!(provider_error_diagnostic(&error).retry_after_secs(), None);
        }
    }

    #[test]
    fn wrapped_typed_http_errors_keep_classification_and_retry_after_gating() {
        let cases = [
            (
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "retry later",
                "rate_limited",
                ProviderErrorDisposition::RateLimited,
                Some(12),
            ),
            (
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "insufficient quota",
                "rate_limited",
                ProviderErrorDisposition::RateLimitedNonRetryable,
                None,
            ),
            (
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                r#"{"code":1311,"message":"package unavailable"}"#,
                "rate_limited",
                ProviderErrorDisposition::RateLimitedNonRetryable,
                None,
            ),
            (
                reqwest::StatusCode::UNAUTHORIZED,
                "invalid api key",
                "auth",
                ProviderErrorDisposition::NonRetryable,
                None,
            ),
            (
                reqwest::StatusCode::FORBIDDEN,
                "access denied",
                "auth",
                ProviderErrorDisposition::NonRetryable,
                None,
            ),
            (
                reqwest::StatusCode::BAD_REQUEST,
                "maximum context length exceeded",
                "context_window",
                ProviderErrorDisposition::Retryable,
                None,
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "temporarily unavailable",
                "provider_server",
                ProviderErrorDisposition::Retryable,
                None,
            ),
        ];

        for (status, detail, kind, disposition, retry_after_secs) in cases {
            let error = anyhow::Error::new(crate::ProviderHttpError::new(
                "test",
                status,
                Some(12),
                detail.to_string(),
            ))
            .context("outer provider request context");
            let diagnostic = provider_error_diagnostic(&error);

            assert_eq!(diagnostic.kind(), kind, "{detail}");
            assert_eq!(diagnostic.status(), Some(status.as_u16()), "{detail}");
            assert_eq!(diagnostic.disposition(), disposition, "{detail}");
            assert_eq!(diagnostic.retry_after_secs(), retry_after_secs, "{detail}");
        }
    }

    #[tokio::test]
    async fn wrapped_api_error_keeps_bounded_retry_after_for_retryable_429() {
        let response = reqwest::Response::from(
            axum::http::Response::builder()
                .status(reqwest::StatusCode::TOO_MANY_REQUESTS)
                .header(reqwest::header::RETRY_AFTER, "999999")
                .body("retry later")
                .expect("test response"),
        );
        let error = crate::api_error("test", response)
            .await
            .context("outer provider request context");

        let diagnostic = provider_error_diagnostic(&error);

        assert_eq!(diagnostic.kind(), "rate_limited");
        assert_eq!(
            diagnostic.disposition(),
            ProviderErrorDisposition::RateLimited
        );
        assert_eq!(diagnostic.status(), Some(429));
        assert_eq!(diagnostic.retry_after_secs(), Some(86_400));
    }

    #[tokio::test]
    async fn wrapped_typed_context_window_aborts_retries_and_provider_fallback() {
        struct WrappedContextFailure {
            calls: Arc<AtomicUsize>,
        }

        impl ::zeroclaw_api::attribution::Attributable for WrappedContextFailure {
            fn role(&self) -> ::zeroclaw_api::attribution::Role {
                ::zeroclaw_api::attribution::Role::Provider(
                    ::zeroclaw_api::attribution::ProviderKind::Model(
                        ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                    ),
                )
            }

            fn alias(&self) -> &str {
                "WrappedContextFailure"
            }
        }

        #[async_trait]
        impl ModelProvider for WrappedContextFailure {
            async fn chat_with_system(
                &self,
                _system_prompt: Option<&str>,
                _message: &str,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::Error::new(crate::ProviderHttpError::new(
                    "test",
                    reqwest::StatusCode::BAD_REQUEST,
                    Some(12),
                    "maximum context length exceeded".to_string(),
                ))
                .context("outer provider request context"))
            }
        }

        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let provider = ReliableModelProvider::new(
            "configured-alias",
            vec![
                (
                    "primary".to_string(),
                    Box::new(WrappedContextFailure {
                        calls: Arc::clone(&primary_calls),
                    }),
                ),
                (
                    "fallback".to_string(),
                    Box::new(TerminalFailureMock {
                        calls: Arc::clone(&fallback_calls),
                        error: "fallback must not run",
                    }),
                ),
            ],
            3,
            1,
        );

        let error = provider
            .chat_with_system(None, "hello", "requested-model", None)
            .await
            .expect_err("context overflow belongs to the outer owner");
        let terminal = terminal_provider_failure(&error).expect("typed terminal failure");

        assert_eq!(terminal.diagnostic().kind(), "context_window");
        assert_eq!(terminal.diagnostic().retry_after_secs(), None);
        assert_eq!(terminal.attempts_for_call(), 1);
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn terminal_identity_uses_last_pinned_fallback_model_and_alias() {
        struct PinnedFailureMock {
            models: Arc<parking_lot::Mutex<Vec<String>>>,
        }

        #[async_trait]
        impl ModelProvider for PinnedFailureMock {
            async fn chat_with_system(
                &self,
                _system_prompt: Option<&str>,
                _message: &str,
                model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                self.models.lock().push(model.to_string());
                anyhow::bail!("503 unavailable")
            }
        }

        impl ::zeroclaw_api::attribution::Attributable for PinnedFailureMock {
            fn role(&self) -> ::zeroclaw_api::attribution::Role {
                ::zeroclaw_api::attribution::Role::Provider(
                    ::zeroclaw_api::attribution::ProviderKind::Model(
                        ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                    ),
                )
            }

            fn alias(&self) -> &str {
                "PinnedFailureMock"
            }
        }

        async fn fail_with(
            candidates: Vec<(ProviderCandidateDescriptor, Box<dyn ModelProvider>)>,
        ) -> TerminalProviderFailure {
            let provider =
                ReliableModelProvider::new_with_candidates("requested", candidates, 0, 1);
            let err = provider
                .chat_with_system(None, "hello", "public-model", None)
                .await
                .expect_err("all candidates fail");
            terminal_provider_failure(&err)
                .expect("typed terminal failure")
                .clone()
        }

        let invoked_models = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let make_failure = |descriptor: ProviderCandidateDescriptor| {
            let pinned = crate::model_pin::ModelPinnedProvider::new(
                descriptor.clone(),
                Box::new(PinnedFailureMock {
                    models: Arc::clone(&invoked_models),
                }),
            );
            (descriptor, Box::new(pinned) as Box<dyn ModelProvider>)
        };

        let fallback_model = fail_with(vec![
            make_failure(ProviderCandidateDescriptor::pinned(
                "openai",
                Some("primary"),
                "private-primary",
            )),
            make_failure(ProviderCandidateDescriptor::pinned(
                "openai",
                Some("primary"),
                "private-fallback-model",
            )),
        ])
        .await;
        assert_eq!(fallback_model.actual_provider(), "primary");
        assert_eq!(fallback_model.actual_model(), "private-fallback-model");
        assert_eq!(
            invoked_models.lock().as_slice(),
            ["private-primary", "private-fallback-model"]
        );

        invoked_models.lock().clear();

        let alias_fallback = fail_with(vec![
            make_failure(ProviderCandidateDescriptor::pinned(
                "openai",
                Some("primary"),
                "private-primary",
            )),
            make_failure(ProviderCandidateDescriptor::pinned(
                "openai",
                Some("backup"),
                "private-backup",
            )),
        ])
        .await;
        assert_eq!(alias_fallback.actual_provider(), "backup");
        assert_eq!(alias_fallback.provider_family(), "openai");
        assert_eq!(alias_fallback.actual_model(), "private-backup");
        assert_eq!(
            invoked_models.lock().as_slice(),
            ["private-primary", "private-backup"]
        );
    }

    #[tokio::test]
    async fn attempts_for_call_resets_for_each_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = ReliableModelProvider::new(
            "legacy",
            vec![(
                "openai".to_string(),
                Box::new(TerminalFailureMock {
                    calls: Arc::clone(&calls),
                    error: "503 unavailable",
                }) as Box<dyn ModelProvider>,
            )],
            1,
            1,
        );

        for _ in 0..2 {
            let err = provider
                .chat_with_system(None, "hello", "current-chain-model", None)
                .await
                .expect_err("call fails");
            let terminal = terminal_provider_failure(&err).expect("typed failure");
            assert_eq!(terminal.actual_provider(), "openai");
            assert_eq!(terminal.actual_model(), "current-chain-model");
            assert_eq!(terminal.attempts_for_call(), 2);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn non_retryable_detects_common_patterns() {
        assert!(is_non_retryable(&anyhow::Error::msg("400 Bad Request")));
        assert!(is_non_retryable(&anyhow::Error::msg("401 Unauthorized")));
        assert!(is_non_retryable(&anyhow::Error::msg("403 Forbidden")));
        assert!(is_non_retryable(&anyhow::Error::msg("404 Not Found")));
        assert!(is_non_retryable(&anyhow::Error::msg(
            "invalid api key provided"
        )));
        assert!(is_non_retryable(&anyhow::Error::msg(
            "authentication failed"
        )));
        assert!(is_non_retryable(&anyhow::Error::msg(
            "model glm-4.7 not found"
        )));
        assert!(is_non_retryable(&anyhow::Error::msg(
            "unsupported model: glm-4.7"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "429 Too Many Requests"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "408 Request Timeout"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "500 Internal Server Error"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg("502 Bad Gateway")));
        assert!(!is_non_retryable(&anyhow::Error::msg("timeout")));
        assert!(!is_non_retryable(&anyhow::Error::msg("connection reset")));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "model overloaded, try again later"
        )));
        // Context window errors are now recoverable (not non-retryable)
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "OpenAI Codex stream error: Your input exceeds the context window of this model."
        )));
    }

    #[test]
    fn auth_error_detects_common_patterns() {
        assert!(is_auth_error(&anyhow::Error::msg("401 Unauthorized")));
        assert!(is_auth_error(&anyhow::Error::msg("403 Forbidden")));
        assert!(is_auth_error(&anyhow::Error::msg("invalid api key")));
        assert!(is_auth_error(&anyhow::Error::msg("authentication failed")));
        assert!(is_auth_error(&anyhow::Error::msg("token expired")));
        assert!(!is_auth_error(&anyhow::Error::msg("400 Bad Request")));
        assert!(!is_auth_error(&anyhow::Error::msg("429 Too Many Requests")));
        assert!(!is_auth_error(&anyhow::Error::msg("timeout")));
        assert!(!is_auth_error(&anyhow::Error::msg("connection reset")));
    }

    #[test]
    fn provider_error_diagnostic_identifies_connect_timeout_endpoint() {
        let err = anyhow::Error::msg(
            "error sending request for url (https://api.deepseek.com/chat/completions): \
             client error (Connect): operation timed out",
        );

        let diagnostic = provider_error_diagnostic(&err);

        assert_eq!(diagnostic.kind, "connect_timeout");
        assert_eq!(diagnostic.phase, "tls_or_connect");
        assert_eq!(
            diagnostic.endpoint.as_deref(),
            Some("https://api.deepseek.com/chat/completions")
        );
        assert!(diagnostic.hint.contains("VPN"));
    }

    #[test]
    fn endpoint_from_error_text_strips_url_userinfo() {
        let endpoint = endpoint_from_error_text(
            "error sending request for url \
             (https://user:hunter2@inference.host/v1?token=hunter2#debug): timed out",
        );

        assert_eq!(endpoint.as_deref(), Some("https://inference.host/v1"));
    }

    #[test]
    fn sanitized_url_endpoint_scrubs_secret_like_path_segments() {
        let endpoint = sanitized_url_endpoint(
            reqwest::Url::parse(
                "https://user:hunter2@inference.host/v1/sk-secretvalue123/chat?token=hunter2#debug",
            )
            .expect("test URL parses"),
        );

        assert_eq!(endpoint, "https://inference.host/v1/[REDACTED]/chat");
        assert!(!endpoint.contains("secretvalue123"));
        assert!(!endpoint.contains("hunter2"));
    }

    #[test]
    fn endpoint_from_error_text_drops_unparseable_urls() {
        let endpoint = endpoint_from_error_text("error sending request to https://:not-a-url");

        assert_eq!(endpoint, None);
    }

    #[test]
    fn endpoint_from_error_text_preserves_ipv6_host_brackets() {
        let bare = endpoint_from_error_text("error sending request for url (http://[::1]): failed");
        let with_port = endpoint_from_error_text(
            "error sending request for url (http://[::1]:8080/v1): failed",
        );

        assert_eq!(bare.as_deref(), Some("http://[::1]/"));
        assert_eq!(with_port.as_deref(), Some("http://[::1]:8080/v1"));
    }

    #[test]
    fn provider_error_diagnostic_classifies_text_error_branches() {
        let cases = [
            (
                "input exceeds the context window of this model",
                "context_window",
                "request_validation",
                "larger-context model",
            ),
            (
                "401 Unauthorized: invalid api key",
                "auth",
                "http_response",
                "credentials",
            ),
            (
                "429 Too Many Requests",
                "rate_limited",
                "http_response",
                "quota",
            ),
            (
                "client error (Connect): operation timed out",
                "connect_timeout",
                "tls_or_connect",
                "VPN",
            ),
            (
                "request timed out while waiting for provider",
                "timeout",
                "request",
                "timed out",
            ),
            ("dns resolve failed for provider host", "dns", "dns", "DNS"),
            (
                "model gpt-missing does not exist",
                "model_not_found",
                "http_response",
                "model id",
            ),
            (
                "provider returned an opaque transport error",
                "provider_error",
                "unknown",
                "inspect provider error",
            ),
        ];

        for (message, expected_kind, expected_phase, expected_hint) in cases {
            let diagnostic = provider_error_diagnostic(&anyhow::Error::msg(message));

            assert_eq!(diagnostic.kind, expected_kind, "{message}");
            assert_eq!(diagnostic.phase, expected_phase, "{message}");
            assert!(diagnostic.hint.contains(expected_hint), "{message}");
        }
    }

    #[test]
    fn failure_summary_includes_provider_diagnostic_fields() {
        let diagnostic = ProviderErrorDiagnostic {
            kind: "connect_timeout",
            disposition: ProviderErrorDisposition::Retryable,
            phase: "tls_or_connect",
            hint: "check network, VPN, or firewall",
            endpoint: Some("https://api.deepseek.com/chat/completions".to_string()),
            status: None,
            retry_after_secs: None,
        };
        let mut failures = Vec::new();

        push_failure(
            &mut failures,
            "deepseek",
            "deepseek-reasoner",
            1,
            3,
            "retryable",
            "operation timed out",
            Some(&diagnostic),
        );

        let summary = failures.join("\n");
        assert!(summary.contains("kind=connect_timeout"));
        assert!(summary.contains("phase=tls_or_connect"));
        assert!(summary.contains("endpoint=https://api.deepseek.com/chat/completions"));
        assert!(summary.contains("hint=check network, VPN, or firewall"));
    }

    #[tokio::test]
    async fn context_window_error_aborts_retries_and_model_fallbacks() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut model_fallbacks = std::collections::HashMap::new();
        model_fallbacks.insert(
            "gpt-5.3-codex".to_string(),
            vec!["gpt-5.2-codex".to_string()],
        );

        let model_provider = ReliableModelProvider::new("test", vec![(
                "openai-codex".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: usize::MAX,
                    response: "never",
                    error: "OpenAI Codex stream error: Your input exceeds the context window of this model. Please adjust your input and try again.",
                }),
            )],
            4,
            1,
        )
        .with_model_fallbacks(model_fallbacks);

        let err = model_provider
            .simple_chat("hello", "gpt-5.3-codex", Some(0.0))
            .await
            .expect_err("context window overflow should fail fast");
        let terminal = terminal_provider_failure(&err).expect("typed context evidence");
        assert_eq!(terminal.diagnostic().kind(), "context_window");
        assert_eq!(terminal.attempts_for_call(), 1);
        // chat_with_system has no history to truncate, so it bails immediately
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn terminal_error_marks_non_retryable_model_mismatch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "custom".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: usize::MAX,
                    response: "never",
                    error: "unsupported model: glm-4.7",
                }),
            )],
            3,
            1,
        );

        let err = model_provider
            .simple_chat("hello", "glm-4.7", Some(0.0))
            .await
            .expect_err("model_provider should fail");
        let terminal = terminal_provider_failure(&err).expect("typed terminal evidence");
        assert_eq!(terminal.diagnostic().kind(), "model_not_found");
        assert_eq!(
            terminal.diagnostic().disposition(),
            ProviderErrorDisposition::NonRetryable
        );
        assert_eq!(terminal.attempts_for_call(), 1);
        assert!(!err.to_string().contains("unsupported model"));
        // Non-retryable errors should not consume retry budget.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn skips_retries_on_non_retryable_error() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&primary_calls),
                        fail_until_attempt: usize::MAX,
                        response: "never",
                        error: "401 Unauthorized",
                    }),
                ),
                (
                    "fallback".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&fallback_calls),
                        fail_until_attempt: 0,
                        response: "from fallback",
                        error: "fallback err",
                    }),
                ),
            ],
            3,
            1,
        );

        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "from fallback");
        // Primary should have been called only once (no retries)
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_with_history_retries_then_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 1,
                    response: "history ok",
                    error: "temporary",
                }),
            )],
            2,
            1,
        );

        let messages = vec![ChatMessage::system("system"), ChatMessage::user("hello")];
        let result = model_provider
            .chat_with_history(&messages, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "history ok");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn chat_with_history_falls_back() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&primary_calls),
                        fail_until_attempt: usize::MAX,
                        response: "never",
                        error: "primary down",
                    }),
                ),
                (
                    "fallback".into(),
                    Box::new(MockModelProvider {
                        calls: Arc::clone(&fallback_calls),
                        fail_until_attempt: 0,
                        response: "fallback ok",
                        error: "fallback err",
                    }),
                ),
            ],
            1,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let result = model_provider
            .chat_with_history(&messages, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "fallback ok");
        assert_eq!(primary_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    // ── New tests: model failover ──

    #[tokio::test]
    async fn model_failover_tries_fallback_model() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(ModelAwareMock {
            calls: Arc::clone(&calls),
            models_seen: parking_lot::Mutex::new(Vec::new()),
            fail_models: vec!["claude-opus"],
            response: "ok from sonnet",
        });

        let mut fallbacks = HashMap::new();
        fallbacks.insert("claude-opus".to_string(), vec!["claude-sonnet".to_string()]);

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "anthropic".into(),
                Box::new(mock.clone()) as Box<dyn ModelProvider>,
            )],
            0, // no retries — force immediate model failover
            1,
        )
        .with_model_fallbacks(fallbacks);

        let result = model_provider
            .simple_chat("hello", "claude-opus", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "ok from sonnet");

        let seen = mock.models_seen.lock();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], "claude-opus");
        assert_eq!(seen[1], "claude-sonnet");
    }

    #[tokio::test]
    async fn model_failover_all_models_fail() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(ModelAwareMock {
            calls: Arc::clone(&calls),
            models_seen: parking_lot::Mutex::new(Vec::new()),
            fail_models: vec!["model-a", "model-b", "model-c"],
            response: "never",
        });

        let mut fallbacks = HashMap::new();
        fallbacks.insert(
            "model-a".to_string(),
            vec!["model-b".to_string(), "model-c".to_string()],
        );

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "p1".into(),
                Box::new(mock.clone()) as Box<dyn ModelProvider>,
            )],
            0,
            1,
        )
        .with_model_fallbacks(fallbacks);

        let err = model_provider
            .simple_chat("hello", "model-a", Some(0.0))
            .await
            .expect_err("all models should fail");
        let terminal = terminal_provider_failure(&err).expect("typed terminal evidence");
        assert_eq!(terminal.actual_provider(), "p1");
        assert_eq!(terminal.actual_model(), "model-c");
        assert_eq!(terminal.attempts_for_call(), 3);

        let seen = mock.models_seen.lock();
        assert_eq!(seen.len(), 3);
    }

    #[tokio::test]
    async fn no_model_fallbacks_behaves_like_before() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 0,
                    response: "ok",
                    error: "boom",
                }),
            )],
            2,
            1,
        );
        // No model_fallbacks set — should work exactly as before
        let result = model_provider
            .simple_chat("hello", "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result, "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ── New tests: auth rotation ──

    #[tokio::test]
    async fn auth_rotation_cycles_keys() {
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "p".into(),
                Box::new(MockModelProvider {
                    calls: Arc::new(AtomicUsize::new(0)),
                    fail_until_attempt: 0,
                    response: "ok",
                    error: "",
                }),
            )],
            0,
            1,
        )
        .with_api_keys(vec!["key-a".into(), "key-b".into(), "key-c".into()]);

        // Rotate 5 times, verify round-robin
        let keys: Vec<&str> = (0..5)
            .map(|_| model_provider.rotate_key().unwrap())
            .collect();
        assert_eq!(keys, vec!["key-a", "key-b", "key-c", "key-a", "key-b"]);
    }

    #[tokio::test]
    async fn auth_rotation_returns_none_when_empty() {
        let model_provider = ReliableModelProvider::new("test", vec![], 0, 1);
        assert!(model_provider.rotate_key().is_none());
    }

    // ── New tests: Retry-After parsing ──

    #[test]
    fn parse_retry_after_integer() {
        let err = anyhow::Error::msg("429 Too Many Requests, Retry-After: 5");
        assert_eq!(parse_legacy_retry_after_ms(&err), Some(5000));
    }

    #[test]
    fn parse_retry_after_float() {
        let err = anyhow::Error::msg("Rate limited. retry_after: 2.5 seconds");
        assert_eq!(parse_legacy_retry_after_ms(&err), Some(2500));
    }

    #[test]
    fn parse_retry_after_missing() {
        let err = anyhow::Error::msg("500 Internal Server Error");
        assert_eq!(parse_legacy_retry_after_ms(&err), None);
    }

    #[test]
    fn rate_limited_detection() {
        assert!(is_rate_limited(&anyhow::Error::msg(
            "429 Too Many Requests"
        )));
        assert!(is_rate_limited(&anyhow::Error::msg(
            "HTTP 429 rate limit exceeded"
        )));
        assert!(!is_rate_limited(&anyhow::Error::msg("401 Unauthorized")));
        assert!(!is_rate_limited(&anyhow::Error::msg(
            "500 Internal Server Error"
        )));
    }

    #[test]
    fn non_retryable_rate_limit_detects_plan_restricted_model() {
        let err = anyhow::Error::msg(
            "API error (429 Too Many Requests): {\"code\":1311,\"message\":\"the current account plan does not include glm-5\"}",
        );
        assert!(
            is_non_retryable_rate_limit(&err),
            "plan-restricted 429 should skip retries"
        );
    }

    #[test]
    fn non_retryable_rate_limit_detects_insufficient_balance() {
        let err = anyhow::Error::msg(
            "API error (429 Too Many Requests): {\"code\":1113,\"message\":\"insufficient balance\"}",
        );
        assert!(
            is_non_retryable_rate_limit(&err),
            "insufficient-balance 429 should skip retries"
        );
    }

    #[test]
    fn non_retryable_rate_limit_does_not_flag_generic_429() {
        let err = anyhow::Error::msg("429 Too Many Requests: rate limit exceeded");
        assert!(
            !is_non_retryable_rate_limit(&err),
            "generic rate-limit 429 should remain retryable"
        );
    }

    #[test]
    fn compute_backoff_uses_retry_after() {
        let model_provider = ReliableModelProvider::new("test", vec![], 0, 500);
        let err = anyhow::Error::msg("429 Retry-After: 3");
        assert_eq!(model_provider.compute_backoff(500, &err), 3_000);
    }

    #[test]
    fn compute_backoff_caps_at_30s() {
        let model_provider = ReliableModelProvider::new("test", vec![], 0, 500);
        let err = anyhow::Error::msg("429 Retry-After: 120");
        assert_eq!(model_provider.compute_backoff(500, &err), 30_000);
    }

    #[test]
    fn compute_backoff_falls_back_to_base() {
        let model_provider = ReliableModelProvider::new("test", vec![], 0, 500);
        let err = anyhow::Error::msg("500 Server Error");
        assert_eq!(model_provider.compute_backoff(500, &err), 500);
    }

    // ── §2.1 API auth error (401/403) tests ──────────────────

    #[test]
    fn non_retryable_detects_401() {
        let err = anyhow::Error::msg("API error (401 Unauthorized): invalid api key");
        assert!(
            is_non_retryable(&err),
            "401 errors must be detected as non-retryable"
        );
    }

    #[test]
    fn non_retryable_detects_403() {
        let err = anyhow::Error::msg("API error (403 Forbidden): access denied");
        assert!(
            is_non_retryable(&err),
            "403 errors must be detected as non-retryable"
        );
    }

    #[test]
    fn non_retryable_detects_404() {
        let err = anyhow::Error::msg("API error (404 Not Found): model not found");
        assert!(
            is_non_retryable(&err),
            "404 errors must be detected as non-retryable"
        );
    }

    #[test]
    fn non_retryable_does_not_flag_429() {
        let err = anyhow::Error::msg("429 Too Many Requests");
        assert!(
            !is_non_retryable(&err),
            "429 must NOT be treated as non-retryable (it is retryable with backoff)"
        );
    }

    #[test]
    fn non_retryable_does_not_flag_408() {
        let err = anyhow::Error::msg("408 Request Timeout");
        assert!(
            !is_non_retryable(&err),
            "408 must NOT be treated as non-retryable (it is retryable)"
        );
    }

    #[test]
    fn non_retryable_does_not_flag_500() {
        let err = anyhow::Error::msg("500 Internal Server Error");
        assert!(
            !is_non_retryable(&err),
            "500 must NOT be treated as non-retryable (server errors are retryable)"
        );
    }

    #[test]
    fn non_retryable_does_not_flag_502() {
        let err = anyhow::Error::msg("502 Bad Gateway");
        assert!(
            !is_non_retryable(&err),
            "502 must NOT be treated as non-retryable"
        );
    }

    // ── §2.2 Rate limit Retry-After edge cases ───────────────

    #[test]
    fn parse_retry_after_zero() {
        let err = anyhow::Error::msg("429 Too Many Requests, Retry-After: 0");
        assert_eq!(
            parse_legacy_retry_after_ms(&err),
            Some(0),
            "Retry-After: 0 should parse as 0ms"
        );
    }

    #[test]
    fn parse_retry_after_with_underscore_separator() {
        let err = anyhow::Error::msg("rate limited, retry_after: 10");
        assert_eq!(
            parse_legacy_retry_after_ms(&err),
            Some(10_000),
            "retry_after with underscore must be parsed"
        );
    }

    #[test]
    fn parse_retry_after_space_separator() {
        let err = anyhow::Error::msg("Retry-After 7");
        assert_eq!(
            parse_legacy_retry_after_ms(&err),
            Some(7000),
            "Retry-After with space separator must be parsed"
        );
    }

    #[test]
    fn rate_limited_false_for_generic_error() {
        let err = anyhow::Error::msg("Connection refused");
        assert!(
            !is_rate_limited(&err),
            "generic errors must not be flagged as rate-limited"
        );
    }

    // ── §2.3 Malformed API response error classification ─────

    #[tokio::test]
    async fn non_retryable_skips_retries_for_401() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: usize::MAX,
                    response: "never",
                    error: "API error (401 Unauthorized): invalid key",
                }),
            )],
            5,
            1,
        );

        let result = model_provider.simple_chat("hello", "test", Some(0.0)).await;
        assert!(result.is_err(), "401 should fail without retries");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not retry on 401 — should be exactly 1 call"
        );
    }

    #[tokio::test]
    async fn non_retryable_rate_limit_skips_retries_for_plan_errors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(MockModelProvider {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: usize::MAX,
                    response: "never",
                    error: "API error (429 Too Many Requests): {\"code\":1311,\"message\":\"plan does not include glm-5\"}",
                }),
            )],
            5,
            1,
        );

        let result = model_provider.simple_chat("hello", "test", Some(0.0)).await;
        assert!(
            result.is_err(),
            "plan-restricted 429 should fail quickly without retrying"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not retry non-retryable 429 business errors"
        );
    }

    // Arc<ModelAwareMock> ModelProvider impl provided by blanket impl in zeroclaw-types.

    /// Mock model_provider that implements `chat()` with native tool support.
    struct NativeToolMock {
        calls: Arc<AtomicUsize>,
        fail_until_attempt: usize,
        response_text: &'static str,
        tool_calls: Vec<super::super::traits::ToolCall>,
        error: &'static str,
    }

    #[async_trait]
    impl ModelProvider for NativeToolMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(self.response_text.to_string())
        }

        fn supports_native_tools(&self) -> bool {
            true
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= self.fail_until_attempt {
                anyhow::bail!(self.error);
            }
            Ok(ChatResponse {
                text: Some(self.response_text.to_string()),
                tool_calls: self.tool_calls.clone(),
                usage: None,
                reasoning_content: None,
            })
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for NativeToolMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "NativeToolMock"
        }
    }

    #[tokio::test]
    async fn chat_delegates_to_inner_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let tool_call = super::super::traits::ToolCall {
            id: "call_1".to_string(),
            name: "shell".to_string(),
            arguments: r#"{"command":"date"}"#.to_string(),
            extra_content: None,
        };
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(NativeToolMock {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 0,
                    response_text: "ok",
                    tool_calls: vec![tool_call.clone()],
                    error: "boom",
                }) as Box<dyn ModelProvider>,
            )],
            2,
            1,
        );

        let messages = vec![ChatMessage::user("what time is it?")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "test-model", Some(0.0))
            .await
            .unwrap();

        assert_eq!(result.text.as_deref(), Some("ok"));
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].name, "shell");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chat_retries_and_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let tool_call = super::super::traits::ToolCall {
            id: "call_1".to_string(),
            name: "shell".to_string(),
            arguments: r#"{"command":"date"}"#.to_string(),
            extra_content: None,
        };
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(NativeToolMock {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 2,
                    response_text: "recovered",
                    tool_calls: vec![tool_call],
                    error: "temporary failure",
                }) as Box<dyn ModelProvider>,
            )],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("test")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "test-model", Some(0.0))
            .await
            .unwrap();

        assert_eq!(result.text.as_deref(), Some("recovered"));
        assert!(
            calls.load(Ordering::SeqCst) > 1,
            "should have retried at least once"
        );
    }

    #[tokio::test]
    async fn chat_preserves_native_tools_support() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(NativeToolMock {
                    calls: Arc::clone(&calls),
                    fail_until_attempt: 0,
                    response_text: "ok",
                    tool_calls: vec![],
                    error: "boom",
                }) as Box<dyn ModelProvider>,
            )],
            2,
            1,
        );

        assert!(
            model_provider.supports_native_tools(),
            "ReliableModelProvider must propagate supports_native_tools from inner model_provider"
        );
    }

    // ── Gap 2-4: Parity tests for chat() ────────────────────────

    /// `chat()` returns the same typed terminal evidence as the string methods.
    #[tokio::test]
    async fn chat_returns_typed_terminal_error_when_all_providers_fail() {
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "p1".into(),
                    Box::new(NativeToolMock {
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail_until_attempt: usize::MAX,
                        response_text: "never",
                        tool_calls: vec![],
                        error: "p1 chat error",
                    }) as Box<dyn ModelProvider>,
                ),
                (
                    "p2".into(),
                    Box::new(NativeToolMock {
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail_until_attempt: usize::MAX,
                        response_text: "never",
                        tool_calls: vec![],
                        error: "p2 chat error",
                    }) as Box<dyn ModelProvider>,
                ),
            ],
            0,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let err = model_provider
            .chat(request, "test", Some(0.0))
            .await
            .expect_err("all model_providers should fail");
        let terminal = terminal_provider_failure(&err).expect("typed terminal evidence");
        assert_eq!(terminal.actual_provider(), "p2");
        assert_eq!(terminal.actual_model(), "test");
        assert_eq!(terminal.attempts_for_call(), 2);
        assert_eq!(
            terminal.diagnostic().disposition(),
            ProviderErrorDisposition::Retryable
        );
        assert!(!err.to_string().contains("p2 chat error"));
    }

    /// Mock that records model names and can fail specific models,
    /// implementing `chat()` for native tool calling parity tests.
    struct NativeModelAwareMock {
        calls: Arc<AtomicUsize>,
        models_seen: parking_lot::Mutex<Vec<String>>,
        fail_models: Vec<&'static str>,
        response_text: &'static str,
    }

    #[async_trait]
    impl ModelProvider for NativeModelAwareMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(self.response_text.to_string())
        }

        fn supports_native_tools(&self) -> bool {
            true
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.models_seen.lock().push(model.to_string());
            if self.fail_models.contains(&model) {
                anyhow::bail!("500 model {} unavailable", model);
            }
            Ok(ChatResponse {
                text: Some(self.response_text.to_string()),
                tool_calls: vec![],
                usage: None,
                reasoning_content: None,
            })
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for NativeModelAwareMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "NativeModelAwareMock"
        }
    }

    // Arc<NativeModelAwareMock> ModelProvider impl provided by blanket impl in zeroclaw-types.

    /// Gap 3: `chat()` tries fallback models on failure,
    /// matching behavior of `model_failover_tries_fallback_model`.
    #[tokio::test]
    async fn chat_tries_model_failover_on_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(NativeModelAwareMock {
            calls: Arc::clone(&calls),
            models_seen: parking_lot::Mutex::new(Vec::new()),
            fail_models: vec!["claude-opus"],
            response_text: "ok from sonnet",
        });

        let mut fallbacks = HashMap::new();
        fallbacks.insert("claude-opus".to_string(), vec!["claude-sonnet".to_string()]);

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "anthropic".into(),
                Box::new(mock.clone()) as Box<dyn ModelProvider>,
            )],
            0, // no retries — force immediate model failover
            1,
        )
        .with_model_fallbacks(fallbacks);

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "claude-opus", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("ok from sonnet"));

        let seen = mock.models_seen.lock();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], "claude-opus");
        assert_eq!(seen[1], "claude-sonnet");
    }

    /// Gap 4: `chat()` skips retries on non-retryable errors (401, 403, etc.),
    /// matching behavior of `skips_retries_on_non_retryable_error`.
    #[tokio::test]
    async fn chat_skips_non_retryable_errors() {
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(NativeToolMock {
                        calls: Arc::clone(&primary_calls),
                        fail_until_attempt: usize::MAX,
                        response_text: "never",
                        tool_calls: vec![],
                        error: "401 Unauthorized",
                    }) as Box<dyn ModelProvider>,
                ),
                (
                    "fallback".into(),
                    Box::new(NativeToolMock {
                        calls: Arc::clone(&fallback_calls),
                        fail_until_attempt: 0,
                        response_text: "from fallback",
                        tool_calls: vec![],
                        error: "fallback err",
                    }) as Box<dyn ModelProvider>,
                ),
            ],
            3,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let request = ChatRequest {
            messages: &messages,
            tools: None,
            thinking: None,
        };
        let result = model_provider
            .chat(request, "test", Some(0.0))
            .await
            .unwrap();
        assert_eq!(result.text.as_deref(), Some("from fallback"));
        // Primary should have been called only once (no retries)
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    // ── Context window truncation tests ─────────────────────────

    #[test]
    fn context_window_error_is_not_non_retryable() {
        // Context window errors should be recoverable via truncation
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "exceeds the context window"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "maximum context length exceeded"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "too many tokens in the request"
        )));
        assert!(!is_non_retryable(&anyhow::Error::msg(
            "token limit exceeded"
        )));
    }

    #[test]
    fn is_context_window_exceeded_detects_llamacpp() {
        assert!(is_context_window_exceeded(&anyhow::Error::msg(
            "request (8968 tokens) exceeds the available context size (8448 tokens), try increasing it"
        )));
    }

    // ── Tool schema error detection tests ───────────────────────────────

    #[test]
    fn tool_schema_error_detects_groq_validation_failure() {
        let msg = r#"Groq API error (400 Bad Request): {"error":{"message":"tool call validation failed: attempted to call tool 'memory_recall' which was not in request"}}"#;
        let err = anyhow::Error::msg(msg.to_string());
        assert!(is_tool_schema_error(&err));
    }

    #[test]
    fn tool_schema_error_detects_not_in_request() {
        let err = anyhow::Error::msg("tool 'search' was not in request");
        assert!(is_tool_schema_error(&err));
    }

    #[test]
    fn tool_schema_error_detects_not_found_in_tool_list() {
        let err = anyhow::Error::msg("function 'foo' not found in tool list");
        assert!(is_tool_schema_error(&err));
    }

    #[test]
    fn tool_schema_error_detects_invalid_tool_call() {
        let err = anyhow::Error::msg("invalid_tool_call: no matching function");
        assert!(is_tool_schema_error(&err));
    }

    #[test]
    fn tool_schema_error_ignores_unrelated_errors() {
        let err = anyhow::Error::msg("invalid api key");
        assert!(!is_tool_schema_error(&err));

        let err = anyhow::Error::msg("model not found");
        assert!(!is_tool_schema_error(&err));
    }

    #[test]
    fn non_retryable_returns_false_for_tool_schema_400() {
        // A 400 error with tool schema validation text should NOT be non-retryable.
        let msg = "400 Bad Request: tool call validation failed: attempted to call tool 'x' which was not in request";
        let err = anyhow::Error::msg(msg.to_string());
        assert!(!is_non_retryable(&err));
    }

    #[test]
    fn non_retryable_returns_true_for_other_400_errors() {
        // A regular 400 error (e.g. invalid API key) should still be non-retryable.
        let err = anyhow::Error::msg("400 Bad Request: invalid api key provided");
        assert!(is_non_retryable(&err));
    }

    struct StreamingToolEventMock {
        stream_calls: Arc<AtomicUsize>,
        supports_tool_events: bool,
    }

    impl StreamingToolEventMock {
        fn new(supports_tool_events: bool) -> Self {
            Self {
                stream_calls: Arc::new(AtomicUsize::new(0)),
                supports_tool_events,
            }
        }
    }

    #[async_trait]
    impl ModelProvider for StreamingToolEventMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok("ok".to_string())
        }

        fn supports_streaming(&self) -> bool {
            true
        }

        fn supports_streaming_tool_events(&self) -> bool {
            self.supports_tool_events
        }

        fn stream_chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
            _options: StreamOptions,
        ) -> stream::BoxStream<'static, StreamResult<StreamEvent>> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            stream::iter(vec![
                Ok(StreamEvent::ToolCall(super::super::traits::ToolCall {
                    id: "call_1".to_string(),
                    name: "shell".to_string(),
                    arguments: r#"{"command":"date"}"#.to_string(),
                    extra_content: None,
                })),
                Ok(StreamEvent::Final),
            ])
            .boxed()
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for StreamingToolEventMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "StreamingToolEventMock"
        }
    }

    // Arc<StreamingToolEventMock> ModelProvider impl provided by blanket impl in zeroclaw-types.

    #[tokio::test]
    async fn stream_chat_prefers_provider_with_tool_event_support() {
        let primary = Arc::new(StreamingToolEventMock::new(false));
        let fallback = Arc::new(StreamingToolEventMock::new(true));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(Arc::clone(&primary)) as Box<dyn ModelProvider>,
                ),
                (
                    "fallback".into(),
                    Box::new(Arc::clone(&fallback)) as Box<dyn ModelProvider>,
                ),
            ],
            0,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let tools = vec![ToolSpec {
            name: "shell".to_string(),
            description: "run shell".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                }
            }),
        }];
        let mut stream = model_provider.stream_chat(
            ChatRequest {
                messages: &messages,
                tools: Some(&tools),
                thinking: None,
            },
            "model",
            Some(0.0),
            StreamOptions::new(true),
        );

        let first = stream.next().await.unwrap().unwrap();
        let second = stream.next().await.unwrap().unwrap();
        assert!(stream.next().await.is_none());

        match first {
            StreamEvent::ToolCall(call) => assert_eq!(call.name, "shell"),
            other => panic!("expected tool-call event, got {other:?}"),
        }
        assert!(matches!(second, StreamEvent::Final));
        assert_eq!(primary.stream_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fallback.stream_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stream_chat_errors_when_no_provider_supports_tool_events() {
        let primary = Arc::new(StreamingToolEventMock::new(false));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(Arc::clone(&primary)) as Box<dyn ModelProvider>,
            )],
            0,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let tools = vec![ToolSpec {
            name: "shell".to_string(),
            description: "run shell".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        }];
        let mut stream = model_provider.stream_chat(
            ChatRequest {
                messages: &messages,
                tools: Some(&tools),
                thinking: None,
            },
            "model",
            Some(0.0),
            StreamOptions::new(true),
        );

        let first = stream.next().await.unwrap();
        let err = first.expect_err("stream should fail without tool-event support");
        assert!(
            err.to_string()
                .contains("No model_provider supports streaming tool events"),
            "unexpected stream error: {err}"
        );
        assert!(stream.next().await.is_none());
        assert_eq!(primary.stream_calls.load(Ordering::SeqCst), 0);
    }

    // ── stream_chat_with_history failover tests ──────────────────────

    /// Mock model_provider that supports streaming via stream_chat_with_history.
    struct StreamingHistoryMock {
        stream_calls: Arc<AtomicUsize>,
        supports: bool,
    }

    #[async_trait]
    impl ModelProvider for StreamingHistoryMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok("ok".to_string())
        }

        fn supports_streaming(&self) -> bool {
            self.supports
        }

        fn stream_chat_with_history(
            &self,
            messages: &[ChatMessage],
            _model: &str,
            _temperature: Option<f64>,
            _options: StreamOptions,
        ) -> stream::BoxStream<'static, StreamResult<StreamChunk>> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            // Echo the number of messages as the delta to verify history was passed through
            let msg_count = messages.len().to_string();
            stream::iter(vec![
                Ok(StreamChunk::delta(msg_count)),
                Ok(StreamChunk::final_chunk()),
            ])
            .boxed()
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for StreamingHistoryMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "StreamingHistoryMock"
        }
    }

    #[tokio::test]
    async fn stream_chat_with_history_delegates_to_streaming_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "primary".into(),
                Box::new(StreamingHistoryMock {
                    stream_calls: Arc::clone(&calls),
                    supports: true,
                }) as Box<dyn ModelProvider>,
            )],
            0,
            1,
        );

        let messages = vec![
            ChatMessage::system("system"),
            ChatMessage::user("msg1"),
            ChatMessage::assistant("resp1"),
            ChatMessage::user("msg2"),
        ];
        let mut stream = model_provider.stream_chat_with_history(
            &messages,
            "model",
            Some(0.0),
            StreamOptions::new(true),
        );

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(
            first.delta, "4",
            "should pass all 4 messages to model_provider"
        );
        let second = stream.next().await.unwrap().unwrap();
        assert!(second.is_final);
        assert!(stream.next().await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stream_chat_with_history_skips_non_streaming_providers() {
        let non_streaming_calls = Arc::new(AtomicUsize::new(0));
        let streaming_calls = Arc::new(AtomicUsize::new(0));

        let model_provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "non-streaming".into(),
                    Box::new(StreamingHistoryMock {
                        stream_calls: Arc::clone(&non_streaming_calls),
                        supports: false,
                    }) as Box<dyn ModelProvider>,
                ),
                (
                    "streaming".into(),
                    Box::new(StreamingHistoryMock {
                        stream_calls: Arc::clone(&streaming_calls),
                        supports: true,
                    }) as Box<dyn ModelProvider>,
                ),
            ],
            0,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let mut stream = model_provider.stream_chat_with_history(
            &messages,
            "model",
            Some(0.0),
            StreamOptions::new(true),
        );

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.delta, "1");
        assert_eq!(
            non_streaming_calls.load(Ordering::SeqCst),
            0,
            "non-streaming model_provider should be skipped"
        );
        assert_eq!(
            streaming_calls.load(Ordering::SeqCst),
            1,
            "streaming model_provider should be used"
        );
    }

    #[tokio::test]
    async fn stream_chat_with_history_errors_when_no_provider_supports_streaming() {
        let model_provider = ReliableModelProvider::new(
            "test",
            vec![(
                "non-streaming".into(),
                Box::new(StreamingHistoryMock {
                    stream_calls: Arc::new(AtomicUsize::new(0)),
                    supports: false,
                }) as Box<dyn ModelProvider>,
            )],
            0,
            1,
        );

        let messages = vec![ChatMessage::user("hello")];
        let mut stream = model_provider.stream_chat_with_history(
            &messages,
            "model",
            Some(0.0),
            StreamOptions::new(true),
        );

        let first = stream.next().await.unwrap();
        let err = first.expect_err("should fail when no model_provider supports streaming");
        assert!(
            err.to_string()
                .contains("No model_provider supports streaming"),
            "unexpected error: {err}"
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn fallback_records_provider_fallback_info() {
        scope_provider_fallback(async {
            let model_provider = ReliableModelProvider::new(
                "test",
                vec![
                    (
                        "broken".into(),
                        Box::new(MockModelProvider {
                            calls: Arc::new(AtomicUsize::new(0)),
                            fail_until_attempt: 99, // always fail
                            response: "unused",
                            error: "401 Unauthorized",
                        }),
                    ),
                    (
                        "working".into(),
                        Box::new(MockModelProvider {
                            calls: Arc::new(AtomicUsize::new(0)),
                            fail_until_attempt: 0,
                            response: "hello from working",
                            error: "unused",
                        }),
                    ),
                ],
                2,
                1,
            );

            let resp = model_provider
                .simple_chat("hi", "test-model", Some(0.0))
                .await
                .unwrap();
            assert_eq!(resp, "hello from working");

            let fb = take_last_provider_fallback();
            assert!(fb.is_some(), "fallback info should be recorded");
            let fb = fb.unwrap();
            assert_eq!(fb.requested_provider, "broken");
            assert_eq!(fb.actual_provider, "working");
            assert_eq!(fb.actual_model, "test-model");

            // Second take should be None.
            assert!(take_last_provider_fallback().is_none());
        })
        .await;
    }

    // Regression for #6589: ReliableModelProvider::supports_vision() must reflect the
    // primary (first) provider, not .any() across the fallback chain. This mirrors
    // supports_native_tools() which already uses .first().
    #[test]
    fn supports_vision_reflects_first_provider_not_any_fallback() {
        struct VisionMock(bool);

        #[async_trait]
        impl ModelProvider for VisionMock {
            async fn chat_with_system(
                &self,
                _system_prompt: Option<&str>,
                _message: &str,
                _model: &str,
                _temperature: Option<f64>,
            ) -> anyhow::Result<String> {
                Ok(String::new())
            }

            fn supports_vision(&self) -> bool {
                self.0
            }
        }
        impl ::zeroclaw_api::attribution::Attributable for VisionMock {
            fn role(&self) -> ::zeroclaw_api::attribution::Role {
                ::zeroclaw_api::attribution::Role::Provider(
                    ::zeroclaw_api::attribution::ProviderKind::Model(
                        ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                    ),
                )
            }
            fn alias(&self) -> &str {
                "VisionMock"
            }
        }

        let provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(VisionMock(false)) as Box<dyn ModelProvider>,
                ),
                (
                    "fallback".into(),
                    Box::new(VisionMock(true)) as Box<dyn ModelProvider>,
                ),
            ],
            0,
            0,
        );

        assert!(
            !provider.supports_vision(),
            "ReliableModelProvider with non-vision primary must report supports_vision()=false even when a fallback supports vision"
        );

        let provider = ReliableModelProvider::new(
            "test",
            vec![
                (
                    "primary".into(),
                    Box::new(VisionMock(true)) as Box<dyn ModelProvider>,
                ),
                (
                    "fallback".into(),
                    Box::new(VisionMock(false)) as Box<dyn ModelProvider>,
                ),
            ],
            0,
            0,
        );

        assert!(provider.supports_vision());
    }

    #[tokio::test]
    async fn reliable_wrapper_exposes_inner_provider_attribution() {
        use crate::ProviderDispatch;
        use std::sync::Arc;
        use zeroclaw_api::attribution::Attributable;

        let inner_mock = MockModelProvider {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_until_attempt: 0,
            response: "ok",
            error: "",
        };
        let inner_role = inner_mock.role();
        let inner_alias = inner_mock.alias().to_string();

        let reliable = ReliableModelProvider::new(
            "wrapped-alias",
            vec![("primary".into(), Box::new(inner_mock))],
            0,
            0,
        );
        // The wrapper must report the inner provider's role/alias,
        // not its own.
        assert_eq!(reliable.role(), inner_role, "wrapper must delegate role()",);
        assert_eq!(
            reliable.alias(),
            inner_alias,
            "wrapper must delegate alias()",
        );

        // End-to-end through ProviderDispatch: the captured event
        // must report the inner provider's `model_provider_type`,
        // never `reliable`.
        let _writer_guard = zeroclaw_log::__private_test_writer_lock();
        let _hook_guard = zeroclaw_log::__private_test_hook_lock();
        zeroclaw_log::try_install_capture_subscriber();
        let mut rx = zeroclaw_log::subscribe_or_install();
        while rx.try_recv().is_ok() {}

        let reliable: Arc<dyn ModelProvider> = Arc::new(reliable);
        let dispatch = ProviderDispatch::new(reliable);
        let req = ChatRequest {
            messages: &[],
            tools: None,
            thinking: None,
        };
        let _ = dispatch.chat(req, "m", None).await;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut found_type: Option<String> = None;
        while found_type.is_none() && std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let step = remaining.min(std::time::Duration::from_millis(50));
            match tokio::time::timeout(step, rx.recv()).await {
                Ok(Ok(value)) => {
                    if let Some(zc) = value.get("zeroclaw")
                        && let Some(t) = zc.get("model_provider_type").and_then(|v| v.as_str())
                    {
                        found_type = Some(t.to_string());
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                Err(_elapsed) => {}
            }
        }
        assert_ne!(
            found_type.as_deref(),
            Some("reliable"),
            "ReliableModelProvider must not surface as model_provider_type=reliable",
        );
        zeroclaw_log::clear_broadcast_hook();
    }
}
