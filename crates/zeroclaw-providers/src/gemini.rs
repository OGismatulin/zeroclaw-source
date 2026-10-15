//! Google Gemini model_provider with support for:
//! - Direct API key (`GEMINI_API_KEY` env var or config)
//! - Gemini CLI OAuth tokens (reuse existing ~/.gemini/ authentication)
//! - ZeroClaw auth-profiles OAuth tokens

use crate::auth::AuthService;
use crate::opencode_session::RouterProfile;
use crate::traits::{
    ChatMessage, ChatRequest as ProviderChatRequest, ChatResponse as ProviderChatResponse,
    ModelProvider, TokenUsage, ToolCall, ToolsPayload,
};
use async_trait::async_trait;
use base64::Engine;
use directories::UserDirs;
use reqwest::{Client, header::HeaderValue};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use zeroclaw_api::schema::{CleaningStrategy, SchemaCleanCache};
use zeroclaw_api::tool::ToolSpec;

const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 8192;
const SYNTHETIC_CALL_ID_PREFIX: &str = "gemini-call-";
const GOOGLE_API_KEY_HEADER: &str = "x-goog-api-key";

/// Gemini model_provider supporting multiple authentication methods.
pub struct GeminiModelProvider {
    /// `[providers.models.gemini.<alias>]` config-key alias.
    alias: String,
    auth: Option<GeminiAuth>,
    oauth_project: Arc<tokio::sync::Mutex<Option<String>>>,
    oauth_project_seed: Option<String>,
    oauth_cred_paths: Vec<PathBuf>,
    oauth_index: Arc<tokio::sync::Mutex<usize>>,
    /// AuthService for managed profiles (auth-profiles.json).
    auth_service: Option<AuthService>,
    /// Override profile name for managed auth.
    auth_profile_override: Option<String>,
    /// Per-alias OAuth app credentials carried at construction time so
    /// runtime token refreshes via `AuthService::get_valid_gemini_access_token`
    /// can mint new access tokens without dipping back into Config. Set
    /// from `GeminiModelProviderConfig.oauth_client_id` / `oauth_client_secret`.
    oauth_client_id: Option<String>,
    oauth_client_secret: Option<String>,
    base_url: Option<String>,
    router_profile: Option<RouterProfile>,
    timeout_secs: u64,
    max_output_tokens: u32,
    native_tools: bool,
    schema_cache: SchemaCleanCache,
}

/// Mutable OAuth token state — supports runtime refresh for long-lived processes.
struct OAuthTokenState {
    access_token: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    /// Expiry as unix millis. `None` means unknown (treat as potentially expired).
    expiry_millis: Option<i64>,
}

/// Resolved credential — the variant determines both the HTTP auth method
/// and the diagnostic label returned by `auth_source()`.
enum GeminiAuth {
    /// Explicit API key from config: sent as `x-goog-api-key`.
    ExplicitKey(String),
    /// OAuth access token from Gemini CLI: sent as `Authorization: Bearer`.
    /// Wrapped in a Mutex to allow runtime token refresh.
    OAuthToken(Arc<tokio::sync::Mutex<OAuthTokenState>>),
    /// OAuth token managed by AuthService (auth-profiles.json).
    /// Token refresh is handled by AuthService, not here.
    ManagedOAuth,
}

impl GeminiAuth {
    /// Whether this credential is an OAuth token (CLI or managed).
    fn is_oauth(&self) -> bool {
        matches!(self, GeminiAuth::OAuthToken(_) | GeminiAuth::ManagedOAuth)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// API REQUEST/RESPONSE TYPES
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
struct GenerateContentRequest {
    contents: Vec<Content>,
    #[serde(rename = "systemInstruction", skip_serializing_if = "Option::is_none")]
    system_instruction: Option<Content>,
    #[serde(rename = "generationConfig")]
    generation_config: GenerationConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
struct InternalGenerateContentEnvelope {
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_prompt_id: Option<String>,
    request: InternalGenerateContentRequest,
}

/// Nested request payload for cloudcode-pa's code assist APIs.
#[derive(Debug, Serialize)]
struct InternalGenerateContentRequest {
    contents: Vec<Content>,
    #[serde(rename = "systemInstruction", skip_serializing_if = "Option::is_none")]
    system_instruction: Option<Content>,
    #[serde(rename = "generationConfig", skip_serializing_if = "Option::is_none")]
    generation_config: Option<GenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize, Clone)]
struct Content {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    parts: Vec<Part>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
enum Part {
    Text {
        text: String,
    },
    Inline {
        inline_data: InlineData,
    },
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: FunctionCallPart,
        #[serde(rename = "thoughtSignature", skip_serializing_if = "Option::is_none")]
        thought_signature: Option<String>,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: FunctionResponsePart,
    },
}

#[derive(Debug, Serialize, Clone)]
struct FunctionCallPart {
    name: String,
    args: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct FunctionResponsePart {
    name: String,
    response: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl Part {
    fn text(s: impl Into<String>) -> Self {
        Part::Text { text: s.into() }
    }
}

#[derive(Debug, Serialize, Clone)]
struct InlineData {
    mime_type: String,
    data: String,
}

/// Build Gemini Parts from a message content string.
/// If the content contains [IMAGE:data:...] markers (already normalized by the
/// multimodal pipeline), they are extracted as inline_data parts. The remaining
/// text becomes a text part. Falls back to a single text part if no markers.
fn build_parts(content: &str) -> Vec<Part> {
    let (text, image_refs) = crate::multimodal::parse_image_markers(content);
    let mut parts = Vec::new();
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        parts.push(Part::text(trimmed));
    }
    for uri in &image_refs {
        if let Some(rest) = uri.strip_prefix("data:")
            && let Some(semi_pos) = rest.find(';')
        {
            let mime = &rest[..semi_pos];
            if let Some(b64) = rest[semi_pos + 1..].strip_prefix("base64,") {
                parts.push(Part::Inline {
                    inline_data: InlineData {
                        mime_type: mime.to_string(),
                        data: b64.to_string(),
                    },
                });
            }
        }
    }
    if parts.is_empty() {
        parts.push(Part::text(content));
    }
    parts
}

#[derive(Debug, Serialize, Clone)]
struct GenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct GenerateContentResponse {
    candidates: Option<Vec<Candidate>>,
    error: Option<ApiError>,
    #[serde(default)]
    response: Option<Box<GenerateContentResponse>>,
    #[serde(default, rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Debug, Deserialize)]
struct GeminiUsageMetadata {
    #[serde(default, rename = "promptTokenCount")]
    prompt_token_count: Option<u64>,
    #[serde(default, rename = "candidatesTokenCount")]
    candidates_token_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    #[serde(default)]
    content: Option<CandidateContent>,
}

#[derive(Debug, Deserialize)]
struct CandidateContent {
    parts: Vec<ResponsePart>,
}

#[derive(Debug, Deserialize)]
struct ResponsePart {
    #[serde(default)]
    text: Option<String>,
    /// Thinking models (e.g. gemini-3-pro-preview) mark reasoning parts with `thought: true`.
    #[serde(default)]
    thought: bool,
    #[serde(default, rename = "functionCall")]
    function_call: Option<ResponseFunctionCall>,
    #[serde(default, rename = "thoughtSignature")]
    thought_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponseFunctionCall {
    name: String,
    #[serde(default)]
    args: Option<serde_json::Value>,
    #[serde(default)]
    id: Option<String>,
}

impl CandidateContent {
    fn effective_text(self) -> Option<String> {
        let mut answer_parts: Vec<String> = Vec::new();
        let mut first_thinking: Option<String> = None;

        for part in self.parts {
            if let Some(text) = part.text {
                if text.is_empty() {
                    continue;
                }
                if !part.thought {
                    answer_parts.push(text);
                } else if first_thinking.is_none() {
                    first_thinking = Some(text);
                }
            }
        }

        if answer_parts.is_empty() {
            first_thinking
        } else {
            Some(answer_parts.join(""))
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

impl GenerateContentResponse {
    /// cloudcode-pa wraps the actual response under `response`.
    fn into_effective_response(self) -> Self {
        match self {
            Self {
                response: Some(mut inner),
                usage_metadata,
                ..
            } => {
                if inner.usage_metadata.is_none() {
                    inner.usage_metadata = usage_metadata;
                }
                *inner
            }
            other => other,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// GEMINI CLI TOKEN STRUCTURES
// ══════════════════════════════════════════════════════════════════════════════

/// OAuth token stored by Gemini CLI in `~/.gemini/oauth_creds.json`
#[derive(Debug, Deserialize)]
struct GeminiCliOAuthCreds {
    access_token: Option<String>,
    #[serde(alias = "idToken")]
    id_token: Option<String>,
    refresh_token: Option<String>,
    #[serde(alias = "clientId")]
    client_id: Option<String>,
    #[serde(alias = "clientSecret")]
    client_secret: Option<String>,
    /// Unix milliseconds expiry (used by newer Gemini CLI versions).
    #[serde(alias = "expiryDate")]
    expiry_date: Option<i64>,
    /// RFC 3339 expiry string (used by older Gemini CLI versions).
    expiry: Option<String>,
}

// ══════════════════════════════════════════════════════════════════════════════
// GEMINI CLI OAUTH CONSTANTS
// ══════════════════════════════════════════════════════════════════════════════

/// Google OAuth token endpoint.
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Internal API endpoint used by Gemini CLI for OAuth users.
/// See: <https://github.com/google-gemini/gemini-cli/issues/19200>
const CLOUDCODE_PA_ENDPOINT: &str = "https://cloudcode-pa.googleapis.com/v1internal";

/// loadCodeAssist endpoint for resolving the project ID.
const LOAD_CODE_ASSIST_ENDPOINT: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";

/// A `loadCodeAssist` project reference: a bare id string, or an object
/// carrying `id` / `projectId`. Google returns either shape depending on
/// whether the account already has an onboarded project.
#[derive(Deserialize)]
#[serde(untagged)]
enum ProjectRef {
    Id(String),
    Object {
        #[serde(alias = "projectId")]
        id: Option<String>,
    },
}

impl ProjectRef {
    fn into_id(self) -> Option<String> {
        match self {
            Self::Id(id) => Some(id),
            Self::Object { id } => id,
        }
        .filter(|p| !p.trim().is_empty())
    }
}

#[derive(Deserialize)]
struct LoadCodeAssistResponse {
    #[serde(rename = "cloudaicompanionProject")]
    cloudaicompanion_project: Option<ProjectRef>,
    #[serde(rename = "currentCloudaicompanionProject")]
    current_cloudaicompanion_project: Option<ProjectRef>,
}

impl LoadCodeAssistResponse {
    fn resolve_project_id(self) -> Option<String> {
        self.cloudaicompanion_project
            .and_then(ProjectRef::into_id)
            .or_else(|| {
                self.current_cloudaicompanion_project
                    .and_then(ProjectRef::into_id)
            })
    }
}

/// Google AI Studio's Gemini endpoint.
pub(crate) const BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

// ══════════════════════════════════════════════════════════════════════════════
// TOKEN REFRESH
// ══════════════════════════════════════════════════════════════════════════════

/// Result of a successful token refresh.
struct RefreshedToken {
    access_token: String,
    /// Expiry as unix millis (computed from `expires_in` seconds in the response).
    expiry_millis: Option<i64>,
}

fn refresh_gemini_cli_token(
    refresh_token: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> anyhow::Result<RefreshedToken> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());

    let form = build_oauth_refresh_form(refresh_token, client_id, client_secret);

    let response = client
        .post(GOOGLE_TOKEN_ENDPOINT)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .map_err(|error| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "oauth_provider": "gemini_cli",
                        "phase": "refresh_request",
                        "error": format!("{}", error),
                    })),
                "gemini: CLI OAuth refresh request failed"
            );
            anyhow::Error::msg(format!("Gemini CLI OAuth refresh request failed: {error}"))
        })?;

    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| "<failed to read response body>".to_string());

    if !status.is_success() {
        anyhow::bail!("Gemini CLI OAuth refresh failed (HTTP {status}): {body}");
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        expires_in: Option<i64>,
    }

    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|_| {
        ::zeroclaw_log::record!(
            ERROR,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(::serde_json::json!({"oauth_provider": "gemini_cli"})),
            "gemini: CLI OAuth refresh response is not valid JSON"
        );
        anyhow::Error::msg("Gemini CLI OAuth refresh response is not valid JSON")
    })?;

    let access_token = parsed
        .access_token
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({
                        "oauth_provider": "gemini_cli",
                        "missing": "access_token",
                    })),
                "gemini: CLI OAuth refresh missing access_token"
            );
            anyhow::Error::msg("Gemini CLI OAuth refresh response missing access_token")
        })?;

    let expiry_millis = parsed.expires_in.and_then(|secs| {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())?;
        now_millis.checked_add(secs.checked_mul(1000)?)
    });

    Ok(RefreshedToken {
        access_token,
        expiry_millis,
    })
}

fn build_oauth_refresh_form(
    refresh_token: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
    ];
    if let Some(id) = client_id.and_then(GeminiModelProvider::normalize_non_empty) {
        form.push(("client_id", id));
    }
    if let Some(secret) = client_secret.and_then(GeminiModelProvider::normalize_non_empty) {
        form.push(("client_secret", secret));
    }
    form
}

fn extract_client_id_from_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;

    #[derive(Deserialize)]
    struct IdTokenClaims {
        aud: Option<String>,
        azp: Option<String>,
    }

    let claims: IdTokenClaims = serde_json::from_slice(&decoded).ok()?;
    claims
        .aud
        .as_deref()
        .and_then(GeminiModelProvider::normalize_non_empty)
        .or_else(|| {
            claims
                .azp
                .as_deref()
                .and_then(GeminiModelProvider::normalize_non_empty)
        })
}

/// Async version of token refresh for use during runtime (inside tokio context).
async fn refresh_gemini_cli_token_async(
    refresh_token: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> anyhow::Result<RefreshedToken> {
    let refresh_token = refresh_token.to_string();
    let client_id = client_id.map(str::to_string);
    let client_secret = client_secret.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        refresh_gemini_cli_token(
            &refresh_token,
            client_id.as_deref(),
            client_secret.as_deref(),
        )
    })
    .await
    .map_err(|e| {
        ::zeroclaw_log::record!(
            ERROR,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                .with_attrs(::serde_json::json!({
                    "oauth_provider": "gemini_cli",
                    "phase": "task_join",
                    "error": format!("{}", e),
                })),
            "gemini: token refresh task panicked"
        );
        anyhow::Error::msg(format!("Token refresh task panicked: {e}"))
    })?
}

/// Typed builder for [`GeminiModelProvider`].
///
/// Only `alias` is required; every credential input is optional and layered
/// at [`Self::build`] time in this order:
///   1. Explicit API key from [`Self::api_key`]
///   2. Managed OAuth via [`Self::managed_auth`] (when wired and the
///      profile exists)
///   3. CLI OAuth tokens from `~/.gemini/oauth_creds.json`
#[must_use]
pub struct GeminiBuilder {
    alias: String,
    api_key: Option<String>,
    auth_service: Option<AuthService>,
    profile_override: Option<String>,
    oauth_project_seed: Option<String>,
    oauth_client_id: Option<String>,
    oauth_client_secret: Option<String>,
    base_url: Option<String>,
    router_profile: Option<RouterProfile>,
    timeout_secs: Option<u64>,
    max_output_tokens: Option<u32>,
    native_tools: bool,
}

impl GeminiBuilder {
    pub fn base_url(mut self, base_url: &str) -> Self {
        self.base_url = Some(base_url.trim_end_matches('/').to_string());
        self
    }

    pub fn router_profile(mut self, profile: RouterProfile) -> Self {
        self.router_profile = Some(profile);
        self
    }

    pub fn timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }

    pub fn max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    pub fn native_tools(mut self, native_tools: bool) -> Self {
        self.native_tools = native_tools;
        self
    }

    pub fn try_build(self) -> anyhow::Result<GeminiModelProvider> {
        if self.router_profile.is_some()
            && self
                .api_key
                .as_deref()
                .and_then(GeminiModelProvider::normalize_non_empty)
                .is_none()
        {
            anyhow::bail!("gemini router mode requires an explicit API key");
        }
        Ok(self.build())
    }

    /// Explicit API key (from `[providers.models.gemini.<alias>] api_key`).
    /// When set (and non-empty after trimming), takes precedence over every
    /// OAuth path.
    pub fn api_key(mut self, key: Option<&str>) -> Self {
        self.api_key = key.map(str::to_string);
        self
    }

    /// Wire up managed OAuth via the shared [`AuthService`], with an
    /// optional profile override. When set and no explicit API key is
    /// provided, the builder probes the service at build time; if a
    /// managed profile exists, the resulting provider uses managed OAuth
    /// instead of falling through to the CLI creds.
    pub fn managed_auth(
        mut self,
        auth_service: AuthService,
        profile_override: Option<String>,
    ) -> Self {
        self.auth_service = Some(auth_service);
        self.profile_override = profile_override;
        self
    }

    /// Seed value for the OAuth project resolution cache.
    pub fn oauth_project_seed(mut self, seed: Option<String>) -> Self {
        self.oauth_project_seed = seed;
        self
    }

    /// Override the OAuth client credentials (defaults to the Gemini CLI
    /// public client when unset).
    pub fn oauth_client(
        mut self,
        client_id: Option<String>,
        client_secret: Option<String>,
    ) -> Self {
        self.oauth_client_id = client_id;
        self.oauth_client_secret = client_secret;
        self
    }

    /// Resolve the credential layers and finalize the provider.
    pub fn build(self) -> GeminiModelProvider {
        let oauth_cred_paths = GeminiModelProvider::discover_oauth_cred_paths();

        // Layer 1 — explicit API key.
        let explicit_key = self
            .api_key
            .as_deref()
            .and_then(GeminiModelProvider::normalize_non_empty)
            .map(GeminiAuth::ExplicitKey);

        // Layer 3 — CLI OAuth fallback. Used both when no managed service is
        // wired at all, and when a managed service was wired but no profile
        // was found on disk.
        let load_cli_oauth = || {
            GeminiModelProvider::try_load_gemini_cli_token(oauth_cred_paths.first())
                .map(|state| GeminiAuth::OAuthToken(Arc::new(tokio::sync::Mutex::new(state))))
        };

        // Layer 2 — managed OAuth (only probed when an AuthService is wired
        // and no explicit key beat it).
        let (auth, use_managed) = match (explicit_key, self.auth_service.as_ref()) {
            (Some(a), _) => (Some(a), false),
            (None, _) if self.router_profile.is_some() => (None, false),
            (None, Some(service)) => {
                let profile = self.profile_override.clone();
                let has_managed = std::thread::scope(|s| {
                    let service = service.clone();
                    s.spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .ok()?;
                        rt.block_on(async {
                            service
                                .get_gemini_profile(profile.as_deref())
                                .await
                                .ok()
                                .flatten()
                        })
                    })
                    .join()
                    .ok()
                    .flatten()
                    .is_some()
                });
                if has_managed {
                    (Some(GeminiAuth::ManagedOAuth), true)
                } else {
                    (load_cli_oauth(), false)
                }
            }
            (None, None) => (load_cli_oauth(), false),
        };

        GeminiModelProvider {
            alias: self.alias,
            auth,
            oauth_project: Arc::new(tokio::sync::Mutex::new(None)),
            oauth_project_seed: self.oauth_project_seed,
            oauth_cred_paths,
            oauth_index: Arc::new(tokio::sync::Mutex::new(0)),
            auth_service: if use_managed { self.auth_service } else { None },
            auth_profile_override: self.profile_override,
            oauth_client_id: self.oauth_client_id,
            oauth_client_secret: self.oauth_client_secret,
            base_url: self.base_url,
            router_profile: self.router_profile,
            timeout_secs: self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
            max_output_tokens: self.max_output_tokens.unwrap_or(DEFAULT_MAX_OUTPUT_TOKENS),
            native_tools: self.native_tools,
            schema_cache: SchemaCleanCache::new(),
        }
    }
}

impl GeminiModelProvider {
    /// Entry point for constructing a Gemini provider. Only `alias` is
    /// required; layer optional credential inputs onto the returned
    /// [`GeminiBuilder`].
    ///
    /// Authentication priority (evaluated at build time):
    /// 1. Explicit API key ([`GeminiBuilder::api_key`], from
    ///    `[providers.models.gemini.<alias>] api_key`)
    /// 2. Managed OAuth via [`GeminiBuilder::managed_auth`], when wired
    ///    and a profile exists
    /// 3. Gemini CLI OAuth tokens (`~/.gemini/oauth_creds.json`)
    pub fn builder(alias: &str) -> GeminiBuilder {
        GeminiBuilder {
            alias: alias.to_string(),
            api_key: None,
            auth_service: None,
            profile_override: None,
            oauth_project_seed: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            base_url: None,
            router_profile: None,
            timeout_secs: None,
            max_output_tokens: None,
            native_tools: false,
        }
    }

    fn normalize_non_empty(value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn load_gemini_cli_creds(creds_path: &PathBuf) -> Option<GeminiCliOAuthCreds> {
        if !creds_path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(creds_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn discover_oauth_cred_paths() -> Vec<PathBuf> {
        let home = match UserDirs::new() {
            Some(u) => u.home_dir().to_path_buf(),
            None => return Vec::new(),
        };

        let mut paths = Vec::new();

        let primary = home.join(".gemini").join("oauth_creds.json");
        if primary.exists() {
            paths.push(primary);
        }

        if let Ok(entries) = std::fs::read_dir(&home) {
            let mut extras: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with(".gemini-") && name.ends_with("-home") {
                        let path = e.path().join(".gemini").join("oauth_creds.json");
                        if path.exists() {
                            return Some(path);
                        }
                    }
                    None
                })
                .collect();
            extras.sort();
            paths.extend(extras);
        }

        paths
    }

    /// Try to load OAuth credentials from Gemini CLI's cached credentials.
    /// Location: `~/.gemini/oauth_creds.json`
    /// Returns the full `OAuthTokenState` so the model_provider can refresh at runtime.
    fn try_load_gemini_cli_token(path: Option<&PathBuf>) -> Option<OAuthTokenState> {
        let creds = Self::load_gemini_cli_creds(path?)?;

        // Determine expiry in millis: prefer expiry_date over expiry (RFC 3339)
        let expiry_millis = creds.expiry_date.or_else(|| {
            creds.expiry.as_deref().and_then(|expiry| {
                chrono::DateTime::parse_from_rfc3339(expiry)
                    .ok()
                    .map(|dt| dt.timestamp_millis())
            })
        });

        let access_token = creds
            .access_token
            .and_then(|token| Self::normalize_non_empty(&token))?;

        let id_token_client_id = creds
            .id_token
            .as_deref()
            .and_then(extract_client_id_from_id_token);

        let client_id = creds
            .client_id
            .as_deref()
            .and_then(Self::normalize_non_empty)
            .or(id_token_client_id);
        let client_secret = creds
            .client_secret
            .as_deref()
            .and_then(Self::normalize_non_empty);

        Some(OAuthTokenState {
            access_token,
            refresh_token: creds.refresh_token,
            client_id,
            client_secret,
            expiry_millis,
        })
    }

    /// Check if Gemini CLI is configured and has valid credentials
    pub fn has_cli_credentials() -> bool {
        Self::discover_oauth_cred_paths().iter().any(|path| {
            Self::load_gemini_cli_creds(path)
                .and_then(|creds| {
                    creds
                        .access_token
                        .as_deref()
                        .and_then(Self::normalize_non_empty)
                })
                .is_some()
        })
    }

    /// Check if any Gemini authentication is available via the Gemini CLI
    /// OAuth credential cache. Per-alias config-supplied keys are tracked
    /// separately on the constructed provider, so this helper no longer
    /// reads process env.
    pub fn has_any_auth() -> bool {
        Self::has_cli_credentials()
    }

    /// Get authentication source description for diagnostics.
    /// Uses the stored enum variant — no env var re-reading at call time.
    pub fn auth_source(&self) -> &'static str {
        match self.auth.as_ref() {
            Some(GeminiAuth::ExplicitKey(_)) => "config",
            Some(GeminiAuth::OAuthToken(_)) => "Gemini CLI OAuth",
            Some(GeminiAuth::ManagedOAuth) => "auth-profiles",
            None => "none",
        }
    }

    /// Get a valid OAuth access token, refreshing if expired.
    /// Adds a 60-second buffer before actual expiry to avoid edge-case failures.
    async fn get_valid_oauth_token(
        state: &Arc<tokio::sync::Mutex<OAuthTokenState>>,
    ) -> anyhow::Result<String> {
        let mut guard = state.lock().await;

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(i64::MAX);

        // Refresh if expiry is unknown, already expired, or within 60s of expiry.
        let needs_refresh = guard
            .expiry_millis
            .is_none_or(|exp| exp <= now_millis.saturating_add(60_000));

        if needs_refresh {
            if let Some(ref refresh_token) = guard.refresh_token {
                let refreshed = refresh_gemini_cli_token_async(
                    refresh_token,
                    guard.client_id.as_deref(),
                    guard.client_secret.as_deref(),
                )
                .await?;
                ::zeroclaw_log::record!(
                    INFO,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note),
                    "Gemini CLI OAuth token refreshed successfully (runtime)"
                );
                guard.access_token = refreshed.access_token;
                guard.expiry_millis = refreshed.expiry_millis;
            } else {
                anyhow::bail!(
                    "Gemini CLI OAuth token expired and no refresh_token available — re-run `gemini` to authenticate"
                );
            }
        }

        Ok(guard.access_token.clone())
    }

    /// Rotate to the next available OAuth credentials file and swap state.
    /// Returns `true` when rotation succeeded.
    async fn rotate_oauth_credential(
        &self,
        state: &Arc<tokio::sync::Mutex<OAuthTokenState>>,
    ) -> bool {
        if self.oauth_cred_paths.len() <= 1 {
            return false;
        }

        let mut idx = self.oauth_index.lock().await;
        let start = *idx;

        loop {
            let next = (*idx + 1) % self.oauth_cred_paths.len();
            *idx = next;

            if next == start {
                return false;
            }

            if let Some(next_state) =
                Self::try_load_gemini_cli_token(self.oauth_cred_paths.get(next))
            {
                {
                    let mut guard = state.lock().await;
                    *guard = next_state;
                }
                {
                    let mut cached_project = self.oauth_project.lock().await;
                    *cached_project = None;
                }
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                    &format!(
                        "Gemini OAuth: rotated credential to {}",
                        self.oauth_cred_paths[next].display().to_string()
                    )
                );
                return true;
            }
        }
    }

    fn format_model_name(model: &str) -> String {
        if model.starts_with("models/") {
            model.to_string()
        } else {
            format!("models/{model}")
        }
    }

    fn format_internal_model_name(model: &str) -> String {
        model.strip_prefix("models/").unwrap_or(model).to_string()
    }

    fn build_generate_content_url(model: &str, auth: &GeminiAuth) -> String {
        match auth {
            GeminiAuth::OAuthToken(_) | GeminiAuth::ManagedOAuth => {
                // OAuth tokens are scoped for the internal Code Assist API.
                // The model is passed in the request body, not the URL path.
                format!("{CLOUDCODE_PA_ENDPOINT}:generateContent")
            }
            _ => {
                let model_name = Self::format_model_name(model);
                format!("{BASE_URL}/{model_name}:generateContent")
            }
        }
    }

    fn generate_content_url(&self, model: &str, auth: &GeminiAuth) -> String {
        match (auth, self.base_url.as_deref()) {
            (GeminiAuth::ExplicitKey(_), Some(base)) => {
                format!("{base}/{}:generateContent", Self::format_model_name(model))
            }
            _ => Self::build_generate_content_url(model, auth),
        }
    }

    fn http_client(&self) -> Client {
        zeroclaw_config::schema::build_runtime_proxy_client_with_timeouts(
            "model_provider.gemini",
            self.timeout_secs,
            10,
        )
    }

    fn with_router_headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let Some(profile) = self.router_profile else {
            return request;
        };
        profile
            .headers(self.base_url.as_deref().unwrap_or(BASE_URL))
            .into_iter()
            .fold(request, |request, (name, value)| {
                request.header(name, value)
            })
    }

    /// Resolve the GCP project ID for OAuth by calling the loadCodeAssist endpoint.
    /// Caches the result for subsequent calls.
    async fn resolve_oauth_project(&self, token: &str) -> anyhow::Result<String> {
        let project_seed = self.oauth_project_seed.clone();
        let project_seed_for_request = project_seed.clone();
        let duet_project_for_request = project_seed.clone();

        // Check cache first
        {
            let cached = self.oauth_project.lock().await;
            if let Some(ref project) = *cached {
                return Ok(project.clone());
            }
        }

        // Call loadCodeAssist
        let client = self.http_client();
        let response = client
            .post(LOAD_CODE_ASSIST_ENDPOINT)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "cloudaicompanionProject": project_seed_for_request,
                "metadata": {
                    "ideType": "GEMINI_CLI",
                    "platform": "PLATFORM_UNSPECIFIED",
                    "pluginType": "GEMINI",
                    "duetProject": duet_project_for_request,
                }
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if let Some(seed) = project_seed {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown)
                        .with_attrs(::serde_json::json!({"status": status.to_string()})),
                    "loadCodeAssist failed (HTTP ); using oauth_project seed fallback"
                );
                return Ok(seed);
            }
            anyhow::bail!("loadCodeAssist failed (HTTP {status}): {body}");
        }

        let result: LoadCodeAssistResponse = response.json().await?;
        let project = result
            .resolve_project_id()
            .or(project_seed)
            .ok_or_else(|| {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "missing": "cloudaicompanionProject",
                        })),
                    "gemini: loadCodeAssist missing project context"
                );
                anyhow::Error::msg("loadCodeAssist response missing project context")
            })?;

        // Cache for future calls
        {
            let mut cached = self.oauth_project.lock().await;
            *cached = Some(project.clone());
        }

        Ok(project)
    }

    /// Build the HTTP request for generateContent.
    /// For OAuth, pass the resolved `oauth_token` and `project`.
    /// For API key, both are `None`.
    fn build_generate_content_request(
        &self,
        auth: &GeminiAuth,
        url: &str,
        request: &GenerateContentRequest,
        model: &str,
        include_generation_config: bool,
        project: Option<&str>,
        oauth_token: Option<&str>,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        let req = self.http_client().post(url).json(request);
        Ok(self.with_router_headers(match auth {
            GeminiAuth::ExplicitKey(key) => {
                req.header(GOOGLE_API_KEY_HEADER, Self::sensitive_api_key_header(key)?)
            }
            GeminiAuth::OAuthToken(_) | GeminiAuth::ManagedOAuth => {
                let token = oauth_token.unwrap_or_default();
                // Internal Code Assist API uses a wrapped payload shape:
                // { model, project?, user_prompt_id?, request: { contents, systemInstruction?, generationConfig } }
                let internal_request = InternalGenerateContentEnvelope {
                    model: Self::format_internal_model_name(model),
                    project: project.map(|value| value.to_string()),
                    user_prompt_id: Some(uuid::Uuid::new_v4().to_string()),
                    request: InternalGenerateContentRequest {
                        contents: request.contents.clone(),
                        system_instruction: request.system_instruction.clone(),
                        generation_config: if include_generation_config {
                            Some(request.generation_config.clone())
                        } else {
                            None
                        },
                        tools: request.tools.clone(),
                    },
                };
                self.http_client()
                    .post(url)
                    .json(&internal_request)
                    .bearer_auth(token)
            }
        }))
    }

    fn sensitive_api_key_header(key: &str) -> anyhow::Result<HeaderValue> {
        let mut value = HeaderValue::from_str(key)
            .map_err(|_| anyhow::Error::msg("Gemini API key contains invalid header characters"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn build_api_key_probe_request(&self, key: &str) -> anyhow::Result<reqwest::RequestBuilder> {
        Ok(self
            .http_client()
            .get(format!("{BASE_URL}/models"))
            .header(GOOGLE_API_KEY_HEADER, Self::sensitive_api_key_header(key)?))
    }

    fn should_retry_oauth_without_generation_config(
        status: reqwest::StatusCode,
        error_text: &str,
    ) -> bool {
        if status != reqwest::StatusCode::BAD_REQUEST {
            return false;
        }

        error_text.contains("Unknown name \"generationConfig\"")
            || error_text.contains("Unknown name 'generationConfig'")
            || error_text.contains(r#"Unknown name \"generationConfig\""#)
    }

    fn should_rotate_oauth_on_error(status: reqwest::StatusCode, error_text: &str) -> bool {
        status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            || status.is_server_error()
            || error_text.contains("RESOURCE_EXHAUSTED")
    }
}

impl GeminiModelProvider {
    fn anchor_on_user_turn(contents: &mut Vec<Content>) -> anyhow::Result<()> {
        // Gemini rejects a request whose last turn is a model turn. History
        // trims, session restores, and steering continuations can all leave
        // the history ending on the model's own output. Those model turns are
        // the context a continuation must see, so they are kept and a final
        // user continuation turn is appended; a request with no turns at all
        // falls back to a lone user placeholder, and model-only history has
        // nothing to anchor a request on and fails explicitly instead of
        // being silently replaced with a context-free one.
        match contents.last().map(|c| c.role.as_deref()) {
            Some(Some("user")) => {}
            Some(Some("model")) => {
                if contents.iter().any(|c| c.role.as_deref() == Some("user")) {
                    contents.push(Content {
                        role: Some("user".to_string()),
                        parts: vec![Part::text("[continue]")],
                    });
                } else {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({ "turns": contents.len() })),
                        "gemini: model-only history cannot anchor a generateContent request"
                    );
                    return Err(anyhow::Error::msg(
                        "gemini: history ends on model turns but contains no user turn; \
                         refusing to drop the model context or fabricate a context-free request",
                    ));
                }
            }
            // no turns at all (empty or system-only): a request still needs
            // one user turn to anchor on
            _ => {
                contents.push(Content {
                    role: Some("user".to_string()),
                    parts: vec![Part::text("[continue]")],
                });
            }
        }
        Ok(())
    }

    fn build_chat_contents(
        messages: &[ChatMessage],
        tool_instructions: Option<&str>,
    ) -> anyhow::Result<(Vec<Content>, Option<Content>)> {
        let mut system_parts: Vec<&str> = Vec::new();
        let mut contents: Vec<Content> = Vec::new();
        for msg in messages {
            match msg.role.as_str() {
                "system" => system_parts.push(&msg.content),
                "user" => contents.push(Content {
                    role: Some("user".to_string()),
                    parts: build_parts(&msg.content),
                }),
                "assistant" => contents.push(Content {
                    role: Some("model".to_string()),
                    parts: vec![Part::text(&msg.content)],
                }),
                _ => {}
            }
        }
        if let Some(instructions) = tool_instructions {
            system_parts.push(instructions);
        }
        Self::anchor_on_user_turn(&mut contents)?;
        let system_instruction = if system_parts.is_empty() {
            None
        } else {
            Some(Content {
                role: None,
                parts: vec![Part::text(system_parts.join("\n\n"))],
            })
        };
        Ok((contents, system_instruction))
    }

    async fn chat_with_history_full(
        &self,
        messages: &[ChatMessage],
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<(String, Option<TokenUsage>)> {
        let (contents, system_instruction) = Self::build_chat_contents(messages, None)?;
        self.send_generate_content(contents, system_instruction, model, temperature)
            .await
    }

    fn token_usage_from_metadata(usage: GeminiUsageMetadata) -> Option<TokenUsage> {
        if usage.prompt_token_count.is_none() && usage.candidates_token_count.is_none() {
            return None;
        }
        Some(TokenUsage {
            input_tokens: usage.prompt_token_count,
            output_tokens: usage.candidates_token_count,
            cached_input_tokens: None,
        })
    }

    async fn send_generate_content(
        &self,
        contents: Vec<Content>,
        system_instruction: Option<Content>,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<(String, Option<TokenUsage>)> {
        let auth = self.auth.as_ref().ok_or_else(|| {
            ::zeroclaw_log::record!(
                ERROR,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"missing": "auth"})),
                "gemini: no auth configured"
            );
            anyhow::Error::msg(
                "Gemini API key not found. Options:\n\
                 1. Set GEMINI_API_KEY env var\n\
                 2. Run `gemini` CLI to authenticate (tokens will be reused)\n\
                 3. Run `zeroclaw auth login --model-provider gemini`\n\
                 4. Get an API key from https://aistudio.google.com/app/apikey\n\
                 5. Run `zeroclaw quickstart --model-provider gemini --api-key <key>` to configure",
            )
        })?;

        let oauth_state = match auth {
            GeminiAuth::OAuthToken(state) => Some(state.clone()),
            _ => None,
        };

        // For OAuth: get a valid (potentially refreshed) token and resolve project
        let (mut oauth_token, mut project) = match auth {
            GeminiAuth::OAuthToken(state) => {
                let token = Self::get_valid_oauth_token(state).await?;
                let proj = self.resolve_oauth_project(&token).await?;
                (Some(token), Some(proj))
            }
            GeminiAuth::ManagedOAuth => {
                let auth_service = self.auth_service.as_ref().ok_or_else(|| {
                    ::zeroclaw_log::record!(
                        ERROR,
                        ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({"missing": "auth_service"})),
                        "gemini: ManagedOAuth requires auth_service"
                    );
                    anyhow::Error::msg("ManagedOAuth requires auth_service")
                })?;
                let token = auth_service
                    .get_valid_gemini_access_token(
                        self.auth_profile_override.as_deref(),
                        self.oauth_client_id.as_deref().unwrap_or(""),
                        self.oauth_client_secret.as_deref().unwrap_or(""),
                    )
                    .await?
                    .ok_or_else(|| {
                        ::zeroclaw_log::record!(
                            ERROR,
                            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({"oauth_provider": "gemini"})),
                            "gemini: auth profile not found"
                        );
                        anyhow::Error::msg(
                            "Gemini auth profile not found. Run `zeroclaw auth login --model-provider gemini`.",
                        )
                    })?;
                let proj = self.resolve_oauth_project(&token).await?;
                (Some(token), Some(proj))
            }
            _ => (None, None),
        };

        let request = GenerateContentRequest {
            contents,
            system_instruction,
            generation_config: GenerationConfig {
                temperature,
                max_output_tokens: self.max_output_tokens,
            },
            tools: None,
        };

        if self.router_profile.is_some() {
            let result = self.post_explicit_key_request(&request, model).await?;
            return Self::text_from_response(result);
        }

        let url = Self::build_generate_content_url(model, auth);

        let mut response = self
            .build_generate_content_request(
                auth,
                &url,
                &request,
                model,
                true,
                project.as_deref(),
                oauth_token.as_deref(),
            )?
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();

            if auth.is_oauth() && Self::should_rotate_oauth_on_error(status, &error_text) {
                // For CLI OAuth: rotate credentials
                // For ManagedOAuth: AuthService handles refresh, just retry
                let can_retry = match auth {
                    GeminiAuth::OAuthToken(_) => {
                        if let Some(state) = oauth_state.as_ref() {
                            self.rotate_oauth_credential(state).await
                        } else {
                            false
                        }
                    }
                    GeminiAuth::ManagedOAuth => true, // AuthService refreshes automatically
                    _ => false,
                };

                if can_retry {
                    // Re-fetch token (may be refreshed)
                    let (new_token, new_project) = match auth {
                        GeminiAuth::OAuthToken(state) => {
                            let token = Self::get_valid_oauth_token(state).await?;
                            let proj = self.resolve_oauth_project(&token).await?;
                            (token, proj)
                        }
                        GeminiAuth::ManagedOAuth => {
                            let Some(auth_service) = self.auth_service.as_ref() else {
                                return Err(anyhow::Error::msg(
                                    "Gemini managed OAuth requires an auth service",
                                ));
                            };
                            let token = auth_service
                                .get_valid_gemini_access_token(
                                    self.auth_profile_override.as_deref(),
                                    self.oauth_client_id.as_deref().unwrap_or(""),
                                    self.oauth_client_secret.as_deref().unwrap_or(""),
                                )
                                .await?
                                .ok_or_else(|| {
                                    ::zeroclaw_log::record!(
                                        ERROR,
                                        ::zeroclaw_log::Event::new(
                                            module_path!(),
                                            ::zeroclaw_log::Action::Reject
                                        )
                                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                        .with_attrs(
                                            ::serde_json::json!({"oauth_provider": "gemini"})
                                        ),
                                        "gemini: auth profile not found"
                                    );
                                    anyhow::Error::msg("Gemini auth profile not found")
                                })?;
                            let proj = self.resolve_oauth_project(&token).await?;
                            (token, proj)
                        }
                        _ => {
                            return Err(anyhow::Error::msg(
                                "Gemini retry reached a non-refreshable authentication mode",
                            ));
                        }
                    };
                    oauth_token = Some(new_token);
                    project = Some(new_project);
                    response = self
                        .build_generate_content_request(
                            auth,
                            &url,
                            &request,
                            model,
                            true,
                            project.as_deref(),
                            oauth_token.as_deref(),
                        )?
                        .send()
                        .await?;
                } else {
                    anyhow::bail!("Gemini API error ({status}): {error_text}");
                }
            } else if auth.is_oauth()
                && Self::should_retry_oauth_without_generation_config(status, &error_text)
            {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                    "Gemini OAuth internal endpoint rejected generationConfig; retrying without generationConfig"
                );
                response = self
                    .build_generate_content_request(
                        auth,
                        &url,
                        &request,
                        model,
                        false,
                        project.as_deref(),
                        oauth_token.as_deref(),
                    )?
                    .send()
                    .await?;
            } else {
                anyhow::bail!("Gemini API error ({status}): {error_text}");
            }
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            if auth.is_oauth()
                && Self::should_retry_oauth_without_generation_config(status, &error_text)
            {
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Unknown),
                    "Gemini OAuth internal endpoint rejected generationConfig; retrying without generationConfig"
                );
                response = self
                    .build_generate_content_request(
                        auth,
                        &url,
                        &request,
                        model,
                        false,
                        project.as_deref(),
                        oauth_token.as_deref(),
                    )?
                    .send()
                    .await?;
            } else {
                anyhow::bail!("Gemini API error ({status}): {error_text}");
            }
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gemini API error ({status}): {error_text}");
        }

        let result: GenerateContentResponse = response.json().await?;
        if let Some(err) = &result.error {
            anyhow::bail!("Gemini API error: {}", err.message);
        }
        let result = result.into_effective_response();
        if let Some(err) = result.error {
            anyhow::bail!("Gemini API error: {}", err.message);
        }

        Self::text_from_response(result)
    }

    fn text_from_response(
        result: GenerateContentResponse,
    ) -> anyhow::Result<(String, Option<TokenUsage>)> {
        let usage = result
            .usage_metadata
            .and_then(Self::token_usage_from_metadata);

        let text = result
            .candidates
            .and_then(|c| c.into_iter().next())
            .and_then(|c| c.content)
            .and_then(|c| c.effective_text())
            .ok_or_else(|| {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                    "gemini: empty response text"
                );
                anyhow::Error::msg("No response from Gemini")
            })?;

        Ok((text, usage))
    }
}

impl GeminiModelProvider {
    async fn post_explicit_key_request(
        &self,
        request: &GenerateContentRequest,
        model: &str,
    ) -> anyhow::Result<GenerateContentResponse> {
        let auth = self
            .auth
            .as_ref()
            .filter(|auth| matches!(auth, GeminiAuth::ExplicitKey(_)))
            .ok_or_else(|| {
                anyhow::Error::msg("gemini router requests require an explicit API key")
            })?;
        let url = self.generate_content_url(model, auth);
        let response = self
            .build_generate_content_request(auth, &url, request, model, true, None, None)?
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(crate::api_error("gemini", response).await);
        }
        let result: GenerateContentResponse = response.json().await?;
        if let Some(err) = &result.error {
            anyhow::bail!("Gemini API error: {}", err.message);
        }
        let result = result.into_effective_response();
        if let Some(err) = &result.error {
            anyhow::bail!("Gemini API error: {}", err.message);
        }
        Ok(result)
    }

    async fn chat_native(
        &self,
        request: ProviderChatRequest<'_>,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ProviderChatResponse> {
        let (contents, system_instruction) = Self::build_native_contents(request.messages)?;
        let tools = match request.tools.filter(|tools| !tools.is_empty()) {
            Some(tools) => match self.convert_tools(tools) {
                ToolsPayload::Gemini {
                    function_declarations,
                } => Some(vec![serde_json::json!({
                    "functionDeclarations": function_declarations
                })]),
                payload => {
                    anyhow::bail!(
                        "gemini native mode produced a non-Gemini tools payload ({payload:?})"
                    )
                }
            },
            None => None,
        };
        let body = GenerateContentRequest {
            contents,
            system_instruction,
            generation_config: GenerationConfig {
                temperature,
                max_output_tokens: self.max_output_tokens,
            },
            tools,
        };
        let result = self.post_explicit_key_request(&body, model).await?;
        Self::chat_response_from_native(result)
    }

    fn chat_response_from_native(
        result: GenerateContentResponse,
    ) -> anyhow::Result<ProviderChatResponse> {
        let usage = result
            .usage_metadata
            .and_then(Self::token_usage_from_metadata);
        let parts = result
            .candidates
            .and_then(|candidates| candidates.into_iter().next())
            .and_then(|candidate| candidate.content)
            .map(|content| content.parts)
            .unwrap_or_default();

        let mut text = String::new();
        let mut tool_calls: Vec<ToolCall> = Vec::new();
        let mut used_ids = std::collections::HashSet::new();
        for part in parts {
            if let Some(call) = part.function_call {
                let id = call
                    .id
                    .filter(|id| !id.is_empty() && used_ids.insert(id.clone()))
                    .unwrap_or_else(|| {
                        format!("{SYNTHETIC_CALL_ID_PREFIX}{}", uuid::Uuid::new_v4())
                    });
                tool_calls.push(ToolCall {
                    id,
                    name: call.name,
                    arguments: call
                        .args
                        .unwrap_or_else(|| serde_json::json!({}))
                        .to_string(),
                    extra_content: part
                        .thought_signature
                        .filter(|signature| !signature.is_empty())
                        .map(|signature| {
                            serde_json::json!({"google": {"thought_signature": signature}})
                        }),
                });
            } else if !part.thought
                && let Some(chunk) = part.text
            {
                text.push_str(&chunk);
            }
        }

        if text.is_empty() && tool_calls.is_empty() {
            return Err(anyhow::Error::new(
                zeroclaw_api::model_provider::SemanticEmptyTerminalCompletion,
            ));
        }
        Ok(ProviderChatResponse {
            text: (!text.is_empty()).then_some(text),
            tool_calls,
            usage,
            reasoning_content: None,
        })
    }

    fn parse_assistant_tool_calls(content: &str) -> Option<(Option<String>, Vec<ToolCall>)> {
        let value = serde_json::from_str::<serde_json::Value>(content).ok()?;
        let calls =
            serde_json::from_value::<Vec<ToolCall>>(value.get("tool_calls")?.clone()).ok()?;
        let text = value
            .get("content")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string);
        Some((text, calls))
    }

    fn wire_call_id(id: &str) -> Option<String> {
        (!id.starts_with(SYNTHETIC_CALL_ID_PREFIX)).then(|| id.to_string())
    }

    fn model_parts_for_calls(text: Option<String>, calls: &[ToolCall]) -> Vec<Part> {
        let mut parts: Vec<Part> = text.into_iter().map(Part::text).collect();
        for call in calls {
            parts.push(Part::FunctionCall {
                function_call: FunctionCallPart {
                    name: call.name.clone(),
                    args: serde_json::from_str(&call.arguments)
                        .unwrap_or_else(|_| serde_json::json!({})),
                    id: Self::wire_call_id(&call.id),
                },
                thought_signature: call
                    .extra_content
                    .as_ref()
                    .and_then(|extra| extra.pointer("/google/thought_signature"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            });
        }
        parts
    }

    fn parse_tool_result(content: &str) -> Option<(String, String)> {
        let value = serde_json::from_str::<serde_json::Value>(content).ok()?;
        let object = value.as_object()?;
        let id = object.get("tool_call_id")?.as_str()?.to_string();
        let result = match object.get("content") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
        };
        Some((id, result))
    }

    fn flush_tool_results(
        contents: &mut Vec<Content>,
        pending: &mut Vec<(String, Part)>,
        call_order: &[String],
    ) {
        if pending.is_empty() {
            return;
        }
        pending.sort_by_key(|(id, _)| {
            call_order
                .iter()
                .position(|candidate| candidate == id)
                .unwrap_or(usize::MAX)
        });
        contents.push(Content {
            role: Some("user".to_string()),
            parts: pending.drain(..).map(|(_, part)| part).collect(),
        });
    }

    fn build_native_contents(
        messages: &[ChatMessage],
    ) -> anyhow::Result<(Vec<Content>, Option<Content>)> {
        let mut system_parts: Vec<&str> = Vec::new();
        let mut contents: Vec<Content> = Vec::new();
        let mut call_names: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut call_order: Vec<String> = Vec::new();
        let mut pending: Vec<(String, Part)> = Vec::new();

        for (index, msg) in messages.iter().enumerate() {
            if ChatMessage::should_skip_internal_pruning_marker(messages, index) {
                continue;
            }
            if !matches!(msg.role.as_str(), "tool" | "system") {
                Self::flush_tool_results(&mut contents, &mut pending, &call_order);
            }
            match msg.role.as_str() {
                "system" => system_parts.push(&msg.content),
                "user" => contents.push(Content {
                    role: Some("user".to_string()),
                    parts: build_parts(&msg.content),
                }),
                "assistant" => {
                    let parts = match Self::parse_assistant_tool_calls(&msg.content) {
                        Some((text, calls)) => {
                            call_order = calls.iter().map(|call| call.id.clone()).collect();
                            for call in &calls {
                                call_names.insert(call.id.clone(), call.name.clone());
                            }
                            Self::model_parts_for_calls(text, &calls)
                        }
                        None => {
                            call_order.clear();
                            if msg.content.trim().is_empty() {
                                Vec::new()
                            } else {
                                vec![Part::text(&msg.content)]
                            }
                        }
                    };
                    if !parts.is_empty() {
                        contents.push(Content {
                            role: Some("model".to_string()),
                            parts,
                        });
                    }
                }
                "tool" => match Self::parse_tool_result(&msg.content) {
                    Some((id, result)) if call_names.contains_key(&id) => {
                        let name = call_names[&id].clone();
                        pending.push((
                            id.clone(),
                            Part::FunctionResponse {
                                function_response: FunctionResponsePart {
                                    name,
                                    response: serde_json::json!({ "result": result }),
                                    id: Self::wire_call_id(&id),
                                },
                            },
                        ));
                    }
                    _ => {
                        ::zeroclaw_log::record!(
                            WARN,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Reject
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                            "gemini: tool result without a matching function call dropped"
                        );
                    }
                },
                _ => {}
            }
        }
        Self::flush_tool_results(&mut contents, &mut pending, &call_order);
        Self::anchor_on_user_turn(&mut contents)?;
        let system_instruction = if system_parts.is_empty() {
            None
        } else {
            Some(Content {
                role: None,
                parts: vec![Part::text(system_parts.join("\n\n"))],
            })
        };
        Ok((contents, system_instruction))
    }
}

#[async_trait]
impl ModelProvider for GeminiModelProvider {
    // ── ModelProvider-family defaults ──
    fn default_base_url(&self) -> Option<&str> {
        Some(self.base_url.as_deref().unwrap_or(BASE_URL))
    }

    fn convert_tools(&self, tools: &[ToolSpec]) -> ToolsPayload {
        if !self.native_tools {
            return ToolsPayload::PromptGuided {
                instructions: zeroclaw_api::model_provider::build_tool_instructions_text(tools),
            };
        }
        ToolsPayload::Gemini {
            function_declarations: tools
                .iter()
                .map(|tool| {
                    let parameters = self
                        .schema_cache
                        .clean_shared(&tool.parameters, CleaningStrategy::Gemini);
                    serde_json::json!({
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": (*parameters).clone(),
                    })
                })
                .collect(),
        }
    }

    fn capabilities(&self) -> zeroclaw_api::model_provider::ProviderCapabilities {
        zeroclaw_api::model_provider::ProviderCapabilities {
            vision: true,
            native_tool_calling: self.native_tools,
            prompt_caching: false,
            extended_thinking: false,
        }
    }

    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        let system_instruction = system_prompt.map(|sys| Content {
            role: None,
            parts: vec![Part::text(sys)],
        });

        let contents = vec![Content {
            role: Some("user".to_string()),
            parts: build_parts(message),
        }];

        let (text, _usage) = self
            .send_generate_content(contents, system_instruction, model, temperature)
            .await?;
        Ok(text)
    }

    async fn chat_with_history(
        &self,
        messages: &[ChatMessage],
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        let (text, _usage) = self
            .chat_with_history_full(messages, model, temperature)
            .await?;
        Ok(text)
    }

    async fn chat(
        &self,
        request: ProviderChatRequest<'_>,
        model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ProviderChatResponse> {
        if self.native_tools {
            return self.chat_native(request, model, temperature).await;
        }
        let tool_instructions = if let Some(tools) = request.tools
            && !tools.is_empty()
            && !self.supports_native_tools()
        {
            Some(match self.convert_tools(tools) {
                ToolsPayload::PromptGuided { instructions } => instructions,
                payload => {
                    anyhow::bail!(
                        "Provider returned non-prompt-guided tools payload ({payload:?}) while supports_native_tools() is false"
                    )
                }
            })
        } else {
            None
        };
        let (contents, system_instruction) =
            Self::build_chat_contents(request.messages, tool_instructions.as_deref())?;
        let (text, usage) = self
            .send_generate_content(contents, system_instruction, model, temperature)
            .await?;
        Ok(ProviderChatResponse {
            text: Some(text),
            tool_calls: Vec::new(),
            usage,
            reasoning_content: None,
        })
    }

    async fn warmup(&self) -> anyhow::Result<()> {
        if self.router_profile.is_some() {
            return Ok(());
        }
        if let Some(auth) = self.auth.as_ref() {
            match auth {
                GeminiAuth::ManagedOAuth => {
                    // For ManagedOAuth, verify and refresh the token if needed.
                    // This ensures fallback works even if tokens expired during daemon uptime.
                    let auth_service = self.auth_service.as_ref().ok_or_else(|| {
                        ::zeroclaw_log::record!(
                            ERROR,
                            ::zeroclaw_log::Event::new(
                                module_path!(),
                                ::zeroclaw_log::Action::Reject
                            )
                            .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                            .with_attrs(::serde_json::json!({"missing": "auth_service"})),
                            "gemini: ManagedOAuth requires auth_service"
                        );
                        anyhow::Error::msg("ManagedOAuth requires auth_service")
                    })?;

                    let _token = auth_service
                        .get_valid_gemini_access_token(
                            self.auth_profile_override.as_deref(),
                            self.oauth_client_id.as_deref().unwrap_or(""),
                            self.oauth_client_secret.as_deref().unwrap_or(""),
                        )
                        .await?
                        .ok_or_else(|| {
                            ::zeroclaw_log::record!(
                                ERROR,
                                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                    .with_attrs(::serde_json::json!({"oauth_provider": "gemini"})),
                                "gemini: auth profile not found or expired"
                            );
                            anyhow::Error::msg(
                                "Gemini auth profile not found or expired. Run: zeroclaw auth login --model-provider gemini",
                            )
                        })?;

                    // Token refresh happens in get_valid_gemini_access_token().
                    // We don't call resolve_oauth_project() here to keep warmup fast.
                    // OAuth project will be resolved lazily on first real request.
                }
                GeminiAuth::OAuthToken(_) => {
                    // CLI OAuth — cloudcode-pa does not expose a lightweight model-list probe.
                    // Token will be validated on first real request.
                }
                GeminiAuth::ExplicitKey(key) => {
                    // API key path — verify with public API models endpoint.
                    self.build_api_key_probe_request(key)?
                        .send()
                        .await?
                        .error_for_status()?;
                }
            }
        }
        Ok(())
    }

    async fn list_models(&self) -> anyhow::Result<Vec<String>> {
        // Gemini's /v1beta/models requires authentication. Onboard pulls the
        // catalog from models.dev before the user has entered a key.
        crate::models_dev::list_models_for("google").await
    }
}

impl ::zeroclaw_api::attribution::Attributable for GeminiModelProvider {
    fn role(&self) -> ::zeroclaw_api::attribution::Role {
        ::zeroclaw_api::attribution::Role::Provider(
            ::zeroclaw_api::attribution::ProviderKind::Model(
                ::zeroclaw_api::attribution::ModelProviderKind::Gemini,
            ),
        )
    }
    fn alias(&self) -> &str {
        &self.alias
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{StatusCode, header::AUTHORIZATION};

    fn test_oauth_auth(token: &str) -> GeminiAuth {
        GeminiAuth::OAuthToken(Arc::new(tokio::sync::Mutex::new(OAuthTokenState {
            access_token: token.to_string(),
            refresh_token: None,
            client_id: None,
            client_secret: None,
            expiry_millis: None,
        })))
    }

    fn test_model_provider(auth: Option<GeminiAuth>) -> GeminiModelProvider {
        GeminiModelProvider {
            alias: "test".to_string(),
            auth,
            oauth_project: Arc::new(tokio::sync::Mutex::new(None)),
            oauth_project_seed: None,
            oauth_cred_paths: Vec::new(),
            oauth_index: Arc::new(tokio::sync::Mutex::new(0)),
            auth_service: None,
            auth_profile_override: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            base_url: None,
            router_profile: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            native_tools: false,
            schema_cache: SchemaCleanCache::new(),
        }
    }

    #[test]
    fn normalize_non_empty_trims_and_filters() {
        assert_eq!(
            GeminiModelProvider::normalize_non_empty(" value "),
            Some("value".into())
        );
        assert_eq!(GeminiModelProvider::normalize_non_empty(""), None);
        assert_eq!(GeminiModelProvider::normalize_non_empty(" \t\n"), None);
    }

    fn resolve(body: &str) -> Option<String> {
        serde_json::from_str::<LoadCodeAssistResponse>(body)
            .unwrap()
            .resolve_project_id()
    }

    #[test]
    fn load_code_assist_reads_bare_string_project() {
        assert_eq!(
            resolve(r#"{"cloudaicompanionProject":"my-proj"}"#),
            Some("my-proj".into())
        );
    }

    #[test]
    fn load_code_assist_reads_object_id_and_project_id() {
        assert_eq!(
            resolve(r#"{"cloudaicompanionProject":{"id":"obj-proj"}}"#),
            Some("obj-proj".into())
        );
        assert_eq!(
            resolve(r#"{"cloudaicompanionProject":{"projectId":"alias-proj"}}"#),
            Some("alias-proj".into())
        );
    }

    #[test]
    fn load_code_assist_falls_back_to_current_project() {
        assert_eq!(
            resolve(r#"{"currentCloudaicompanionProject":"current-proj"}"#),
            Some("current-proj".into())
        );
        assert_eq!(
            resolve(r#"{"currentCloudaicompanionProject":{"id":"current-obj"}}"#),
            Some("current-obj".into())
        );
        assert_eq!(
            resolve(r#"{"currentCloudaicompanionProject":{"projectId":"current-alias"}}"#),
            Some("current-alias".into())
        );
    }

    #[test]
    fn load_code_assist_prefers_primary_over_current() {
        assert_eq!(
            resolve(
                r#"{"cloudaicompanionProject":"primary","currentCloudaicompanionProject":"current"}"#
            ),
            Some("primary".into())
        );
    }

    #[test]
    fn load_code_assist_skips_blank_primary_for_current() {
        assert_eq!(
            resolve(
                r#"{"cloudaicompanionProject":"  ","currentCloudaicompanionProject":"current"}"#
            ),
            Some("current".into())
        );
    }

    #[test]
    fn load_code_assist_none_when_no_project_context() {
        assert_eq!(resolve(r#"{}"#), None);
        assert_eq!(resolve(r#"{"cloudaicompanionProject":{"id":null}}"#), None);
        assert_eq!(resolve(r#"{"cloudaicompanionProject":""}"#), None);
    }

    #[test]
    fn oauth_refresh_form_uses_provided_client_credentials() {
        let form = build_oauth_refresh_form("refresh-token", Some("client-id"), Some("secret"));
        let map: std::collections::HashMap<_, _> = form.into_iter().collect();
        assert_eq!(map.get("grant_type"), Some(&"refresh_token".to_string()));
        assert_eq!(map.get("refresh_token"), Some(&"refresh-token".to_string()));
        assert_eq!(map.get("client_id"), Some(&"client-id".to_string()));
        assert_eq!(map.get("client_secret"), Some(&"secret".to_string()));
    }

    #[test]
    fn oauth_refresh_form_omits_client_credentials_when_missing() {
        let form = build_oauth_refresh_form("refresh-token", None, None);
        let map: std::collections::HashMap<_, _> = form.into_iter().collect();
        assert!(!map.contains_key("client_id"));
        assert!(!map.contains_key("client_secret"));
    }

    #[test]
    fn extract_client_id_from_id_token_prefers_aud_claim() {
        let payload = serde_json::json!({
            "aud": "aud-client-id",
            "azp": "azp-client-id"
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{payload_b64}.sig");

        assert_eq!(
            extract_client_id_from_id_token(&token),
            Some("aud-client-id".to_string())
        );
    }

    #[test]
    fn extract_client_id_from_id_token_uses_azp_when_aud_missing() {
        let payload = serde_json::json!({
            "azp": "azp-client-id"
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{payload_b64}.sig");

        assert_eq!(
            extract_client_id_from_id_token(&token),
            Some("azp-client-id".to_string())
        );
    }

    #[test]
    fn extract_client_id_from_id_token_returns_none_for_invalid_tokens() {
        assert_eq!(extract_client_id_from_id_token("invalid"), None);
        assert_eq!(extract_client_id_from_id_token("a.b.c"), None);
    }

    #[test]
    fn try_load_cli_token_derives_client_id_from_id_token_when_missing() {
        let payload = serde_json::json!({ "aud": "derived-client-id" });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let id_token = format!("header.{payload_b64}.sig");

        let file = tempfile::NamedTempFile::new().unwrap();
        let json = format!(
            r#"{{
                "access_token": "ya29.test-access",
                "refresh_token": "1//test-refresh",
                "id_token": "{id_token}"
            }}"#
        );
        std::fs::write(file.path(), json).unwrap();

        let path = file.path().to_path_buf();
        let state = GeminiModelProvider::try_load_gemini_cli_token(Some(&path)).unwrap();
        assert_eq!(state.client_id.as_deref(), Some("derived-client-id"));
        assert_eq!(state.client_secret, None);
    }

    #[test]
    fn provider_creates_without_key() {
        let model_provider = GeminiModelProvider::builder("test").build();
        // May pick up env vars; just verify it doesn't panic
        let _ = model_provider.auth_source();
    }

    #[test]
    fn provider_creates_with_key() {
        let model_provider = GeminiModelProvider::builder("test")
            .api_key(Some("test-api-key"))
            .build();
        assert!(matches!(
            model_provider.auth,
            Some(GeminiAuth::ExplicitKey(ref key)) if key == "test-api-key"
        ));
    }

    #[test]
    fn provider_rejects_empty_key() {
        let model_provider = GeminiModelProvider::builder("test")
            .api_key(Some(""))
            .build();
        assert!(!matches!(
            model_provider.auth,
            Some(GeminiAuth::ExplicitKey(_))
        ));
    }

    #[test]
    fn auth_source_explicit_key() {
        let model_provider = test_model_provider(Some(GeminiAuth::ExplicitKey("key".into())));
        assert_eq!(model_provider.auth_source(), "config");
    }

    #[test]
    fn auth_source_none_without_credentials() {
        let model_provider = test_model_provider(None);
        assert_eq!(model_provider.auth_source(), "none");
    }

    #[test]
    fn auth_source_oauth() {
        let model_provider = test_model_provider(Some(test_oauth_auth("ya29.mock")));
        assert_eq!(model_provider.auth_source(), "Gemini CLI OAuth");
    }

    #[test]
    fn model_name_formatting() {
        assert_eq!(
            GeminiModelProvider::format_model_name("gemini-2.0-flash"),
            "models/gemini-2.0-flash"
        );
        assert_eq!(
            GeminiModelProvider::format_model_name("models/gemini-1.5-pro"),
            "models/gemini-1.5-pro"
        );
        assert_eq!(
            GeminiModelProvider::format_internal_model_name("models/gemini-2.5-flash"),
            "gemini-2.5-flash"
        );
        assert_eq!(
            GeminiModelProvider::format_internal_model_name("gemini-2.5-flash"),
            "gemini-2.5-flash"
        );
    }

    #[test]
    fn api_key_url_excludes_credential() {
        let auth = GeminiAuth::ExplicitKey("api-key-123".into());
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        assert!(url.ends_with(":generateContent"));
        assert!(!url.contains("api-key-123"));
        assert!(!url.contains("?key="));
    }

    #[test]
    fn oauth_url_uses_internal_endpoint() {
        let auth = test_oauth_auth("ya29.test-token");
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        assert!(url.starts_with("https://cloudcode-pa.googleapis.com/v1internal"));
        assert!(url.ends_with(":generateContent"));
        assert!(!url.contains("generativelanguage.googleapis.com"));
        assert!(!url.contains("?key="));
    }

    #[test]
    fn api_key_url_uses_public_endpoint() {
        let auth = GeminiAuth::ExplicitKey("api-key-123".into());
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        assert!(url.contains("generativelanguage.googleapis.com/v1beta"));
        assert!(url.contains("models/gemini-2.0-flash"));
    }

    #[test]
    fn oauth_request_uses_bearer_auth_header() {
        let model_provider = test_model_provider(Some(test_oauth_auth("ya29.mock-token")));
        let auth = test_oauth_auth("ya29.mock-token");
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        let body = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part::text("hello")],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: Some(0.7),
                max_output_tokens: 8192,
            },
            tools: None,
        };

        let request = model_provider
            .build_generate_content_request(
                &auth,
                &url,
                &body,
                "gemini-2.0-flash",
                true,
                Some("test-project"),
                Some("ya29.mock-token"),
            )
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok()),
            Some("Bearer ya29.mock-token")
        );
    }

    #[test]
    fn oauth_request_wraps_payload_in_request_envelope() {
        let model_provider = test_model_provider(Some(test_oauth_auth("ya29.mock-token")));
        let auth = test_oauth_auth("ya29.mock-token");
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        let body = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part::text("hello")],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: Some(0.7),
                max_output_tokens: 8192,
            },
            tools: None,
        };

        let request = model_provider
            .build_generate_content_request(
                &auth,
                &url,
                &body,
                "models/gemini-2.0-flash",
                true,
                Some("test-project"),
                Some("ya29.mock-token"),
            )
            .unwrap()
            .build()
            .unwrap();

        let payload = request
            .body()
            .and_then(|b| b.as_bytes())
            .expect("json request body should be bytes");
        let json: serde_json::Value = serde_json::from_slice(payload).unwrap();

        assert_eq!(json["model"], "gemini-2.0-flash");
        assert!(json.get("generationConfig").is_none());
        assert!(json.get("request").is_some());
        assert!(json["request"].get("generationConfig").is_some());
    }

    #[test]
    fn api_key_request_uses_header_without_url_credential() {
        let model_provider =
            test_model_provider(Some(GeminiAuth::ExplicitKey("api-key-123".into())));
        let auth = GeminiAuth::ExplicitKey("api-key-123".into());
        let url = GeminiModelProvider::build_generate_content_url("gemini-2.0-flash", &auth);
        let body = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part::text("hello")],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: Some(0.7),
                max_output_tokens: 8192,
            },
            tools: None,
        };

        let request = model_provider
            .build_generate_content_request(
                &auth,
                &url,
                &body,
                "gemini-2.0-flash",
                true,
                None,
                None,
            )
            .unwrap()
            .build()
            .unwrap();

        assert!(request.headers().get(AUTHORIZATION).is_none());
        assert_eq!(
            request
                .headers()
                .get(GOOGLE_API_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("api-key-123")
        );
        assert!(
            request
                .headers()
                .get(GOOGLE_API_KEY_HEADER)
                .expect("API key header")
                .is_sensitive()
        );
        assert!(!request.url().as_str().contains("api-key-123"));
        assert!(!request.url().query_pairs().any(|(name, _)| name == "key"));
    }

    #[test]
    fn api_key_probe_uses_header_without_url_credential() {
        let model_provider = test_model_provider(None);
        let request = model_provider
            .build_api_key_probe_request("api-key-123")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get(GOOGLE_API_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("api-key-123")
        );
        assert!(
            request
                .headers()
                .get(GOOGLE_API_KEY_HEADER)
                .expect("API key header")
                .is_sensitive()
        );
        assert_eq!(
            request.url().as_str(),
            "https://generativelanguage.googleapis.com/v1beta/models"
        );
    }

    #[test]
    fn api_key_header_rejects_control_characters_without_echoing_credential() {
        let credential = "api-key-123\r\ninjected: value";
        let error = GeminiModelProvider::sensitive_api_key_header(credential)
            .expect_err("control characters must be rejected");

        assert_eq!(
            error.to_string(),
            "Gemini API key contains invalid header characters"
        );
        assert!(!error.to_string().contains(credential));
    }

    #[test]
    fn request_serialization() {
        let request = GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".to_string()),
                parts: vec![Part::text("Hello")],
            }],
            system_instruction: Some(Content {
                role: None,
                parts: vec![Part::text("You are helpful")],
            }),
            generation_config: GenerationConfig {
                temperature: Some(0.7),
                max_output_tokens: 8192,
            },
            tools: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"text\":\"Hello\""));
        assert!(json.contains("\"systemInstruction\""));
        assert!(!json.contains("\"system_instruction\""));
        assert!(json.contains("\"temperature\":0.7"));
        assert!(json.contains("\"maxOutputTokens\":8192"));
    }

    #[test]
    fn internal_request_includes_model() {
        let request = InternalGenerateContentEnvelope {
            model: "gemini-3-pro-preview".to_string(),
            project: Some("test-project".to_string()),
            user_prompt_id: Some("prompt-123".to_string()),
            request: InternalGenerateContentRequest {
                contents: vec![Content {
                    role: Some("user".to_string()),
                    parts: vec![Part::text("Hello")],
                }],
                system_instruction: None,
                generation_config: Some(GenerationConfig {
                    temperature: Some(0.7),
                    max_output_tokens: 8192,
                }),
                tools: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"model\":\"gemini-3-pro-preview\""));
        assert!(json.contains("\"request\""));
        assert!(json.contains("\"generationConfig\""));
        assert!(json.contains("\"maxOutputTokens\":8192"));
        assert!(json.contains("\"user_prompt_id\":\"prompt-123\""));
        assert!(json.contains("\"project\":\"test-project\""));
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"temperature\":0.7"));
    }

    #[test]
    fn internal_request_omits_generation_config_when_none() {
        let request = InternalGenerateContentEnvelope {
            model: "gemini-3-pro-preview".to_string(),
            project: Some("test-project".to_string()),
            user_prompt_id: None,
            request: InternalGenerateContentRequest {
                contents: vec![Content {
                    role: Some("user".to_string()),
                    parts: vec![Part::text("Hello")],
                }],
                system_instruction: None,
                generation_config: None,
                tools: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("generationConfig"));
        assert!(json.contains("\"model\":\"gemini-3-pro-preview\""));
    }

    #[test]
    fn internal_request_includes_project() {
        let request = InternalGenerateContentEnvelope {
            model: "gemini-2.5-flash".to_string(),
            project: Some("my-gcp-project-id".to_string()),
            user_prompt_id: None,
            request: InternalGenerateContentRequest {
                contents: vec![Content {
                    role: Some("user".to_string()),
                    parts: vec![Part::text("Hello")],
                }],
                system_instruction: None,
                generation_config: None,
                tools: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"project\":\"my-gcp-project-id\""));
    }

    #[test]
    fn creds_deserialize_with_expiry_date() {
        let json = r#"{
            "access_token": "ya29.test-token",
            "refresh_token": "1//test-refresh",
            "expiry_date": 4102444800000
        }"#;

        let creds: GeminiCliOAuthCreds = serde_json::from_str(json).unwrap();
        assert_eq!(creds.access_token.as_deref(), Some("ya29.test-token"));
        assert_eq!(creds.refresh_token.as_deref(), Some("1//test-refresh"));
        assert_eq!(creds.expiry_date, Some(4_102_444_800_000));
        assert!(creds.expiry.is_none());
    }

    #[test]
    fn creds_deserialize_accepts_camel_case_fields() {
        let json = r#"{
            "access_token": "ya29.test-token",
            "idToken": "header.payload.sig",
            "refresh_token": "1//test-refresh",
            "clientId": "test-client-id",
            "clientSecret": "test-client-secret",
            "expiryDate": 4102444800000
        }"#;

        let creds: GeminiCliOAuthCreds = serde_json::from_str(json).unwrap();
        assert_eq!(creds.id_token.as_deref(), Some("header.payload.sig"));
        assert_eq!(creds.client_id.as_deref(), Some("test-client-id"));
        assert_eq!(creds.client_secret.as_deref(), Some("test-client-secret"));
        assert_eq!(creds.expiry_date, Some(4_102_444_800_000));
    }

    #[test]
    fn oauth_retry_detection_for_generation_config_rejection() {
        // Bare quotes (e.g. pre-parsed error string)
        let err =
            "Invalid JSON payload received. Unknown name \"generationConfig\": Cannot find field.";
        assert!(
            GeminiModelProvider::should_retry_oauth_without_generation_config(
                StatusCode::BAD_REQUEST,
                err
            )
        );
        // JSON-escaped quotes (raw response body from Google API)
        let err_json = r#"Invalid JSON payload received. Unknown name \"generationConfig\": Cannot find field."#;
        assert!(
            GeminiModelProvider::should_retry_oauth_without_generation_config(
                StatusCode::BAD_REQUEST,
                err_json
            )
        );
        assert!(
            !GeminiModelProvider::should_retry_oauth_without_generation_config(
                StatusCode::UNAUTHORIZED,
                err
            )
        );
        assert!(
            !GeminiModelProvider::should_retry_oauth_without_generation_config(
                StatusCode::BAD_REQUEST,
                "something else"
            )
        );
    }

    #[test]
    fn response_deserialization() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello there!"}]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        assert!(response.candidates.is_some());
        let text = response
            .candidates
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .content
            .unwrap()
            .parts
            .into_iter()
            .next()
            .unwrap()
            .text;
        assert_eq!(text, Some("Hello there!".to_string()));
    }

    #[test]
    fn error_response_deserialization() {
        let json = r#"{
            "error": {
                "message": "Invalid API key"
            }
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().message, "Invalid API key");
    }

    #[test]
    fn internal_response_deserialization() {
        let json = r#"{
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [{"text": "Hello from internal"}]
                    }
                }]
            }
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let text = response
            .into_effective_response()
            .candidates
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .content
            .unwrap()
            .parts
            .into_iter()
            .next()
            .unwrap()
            .text;
        assert_eq!(text, Some("Hello from internal".to_string()));
    }

    // ── Thinking model response tests ──────────────────────────────────────

    #[test]
    fn thinking_response_extracts_non_thinking_text() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [
                        {"thought": true, "text": "Let me think about this..."},
                        {"text": "The answer is 42."},
                        {"thoughtSignature": "c2lnbmF0dXJl"}
                    ]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, Some("The answer is 42.".to_string()));
    }

    #[test]
    fn non_thinking_response_unaffected() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello there!"}]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, Some("Hello there!".to_string()));
    }

    #[test]
    fn thinking_only_response_falls_back_to_thinking_text() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [
                        {"thought": true, "text": "I need more context..."},
                        {"thoughtSignature": "c2lnbmF0dXJl"}
                    ]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, Some("I need more context...".to_string()));
    }

    #[test]
    fn empty_parts_returns_none() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": []
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, None);
    }

    #[test]
    fn multiple_text_parts_concatenated() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Part one. "},
                        {"text": "Part two."}
                    ]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, Some("Part one. Part two.".to_string()));
    }

    #[test]
    fn thought_signature_only_parts_skipped() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "parts": [
                        {"thoughtSignature": "c2lnbmF0dXJl"}
                    ]
                }
            }]
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let candidate = response.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, None);
    }

    #[test]
    fn internal_response_thinking_model() {
        let json = r#"{
            "response": {
                "candidates": [{
                    "content": {
                        "parts": [
                            {"thought": true, "text": "reasoning..."},
                            {"text": "final answer"}
                        ]
                    }
                }]
            }
        }"#;

        let response: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let effective = response.into_effective_response();
        let candidate = effective.candidates.unwrap().into_iter().next().unwrap();
        let text = candidate.content.unwrap().effective_text();
        assert_eq!(text, Some("final answer".to_string()));
    }

    #[tokio::test]
    async fn warmup_without_key_is_noop() {
        let model_provider = test_model_provider(None);
        let result = model_provider.warmup().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn warmup_oauth_is_noop() {
        let model_provider = test_model_provider(Some(test_oauth_auth("ya29.mock-token")));
        let result = model_provider.warmup().await;
        assert!(result.is_ok());
    }

    #[test]
    fn discover_oauth_cred_paths_does_not_panic() {
        let _paths = GeminiModelProvider::discover_oauth_cred_paths();
    }

    #[tokio::test]
    async fn rotate_oauth_without_alternatives_returns_false() {
        let state = Arc::new(tokio::sync::Mutex::new(OAuthTokenState {
            access_token: "ya29.mock".to_string(),
            refresh_token: None,
            client_id: None,
            client_secret: None,
            expiry_millis: None,
        }));
        let model_provider = test_model_provider(Some(GeminiAuth::OAuthToken(state.clone())));
        assert!(!model_provider.rotate_oauth_credential(&state).await);
    }

    #[test]
    fn response_parses_usage_metadata() {
        let json = r#"{
            "candidates": [{"content": {"parts": [{"text": "Hello"}]}}],
            "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 40}
        }"#;
        let resp: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let usage = resp.usage_metadata.unwrap();
        assert_eq!(usage.prompt_token_count, Some(120));
        assert_eq!(usage.candidates_token_count, Some(40));
    }

    #[test]
    fn response_usage_metadata_maps_to_token_usage() {
        let usage = GeminiUsageMetadata {
            prompt_token_count: Some(120),
            candidates_token_count: Some(40),
        };

        let token_usage =
            GeminiModelProvider::token_usage_from_metadata(usage).expect("usage counts should map");

        assert_eq!(token_usage.input_tokens, Some(120));
        assert_eq!(token_usage.output_tokens, Some(40));
        assert_eq!(token_usage.cached_input_tokens, None);
    }

    #[test]
    fn empty_usage_metadata_maps_to_none() {
        let usage = GeminiUsageMetadata {
            prompt_token_count: None,
            candidates_token_count: None,
        };

        assert!(GeminiModelProvider::token_usage_from_metadata(usage).is_none());
    }

    #[test]
    fn wrapped_response_preserves_outer_usage_metadata() {
        let json = r#"{
            "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 40},
            "response": {
                "candidates": [{"content": {"parts": [{"text": "Hello"}]}}]
            }
        }"#;

        let resp: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let effective = resp.into_effective_response();
        let usage = effective.usage_metadata.unwrap();

        assert_eq!(usage.prompt_token_count, Some(120));
        assert_eq!(usage.candidates_token_count, Some(40));
    }

    #[test]
    fn wrapped_response_prefers_inner_usage_metadata() {
        let json = r#"{
            "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 40},
            "response": {
                "candidates": [{"content": {"parts": [{"text": "Hello"}]}}],
                "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2}
            }
        }"#;

        let resp: GenerateContentResponse = serde_json::from_str(json).unwrap();
        let effective = resp.into_effective_response();
        let usage = effective.usage_metadata.unwrap();

        assert_eq!(usage.prompt_token_count, Some(5));
        assert_eq!(usage.candidates_token_count, Some(2));
    }

    #[test]
    fn response_parses_without_usage_metadata() {
        let json = r#"{"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}"#;
        let resp: GenerateContentResponse = serde_json::from_str(json).unwrap();
        assert!(resp.usage_metadata.is_none());
    }

    #[tokio::test]
    async fn warmup_managed_oauth_requires_auth_service() {
        let model_provider = GeminiModelProvider {
            alias: "test".to_string(),
            auth: Some(GeminiAuth::ManagedOAuth),
            oauth_project: Arc::new(tokio::sync::Mutex::new(None)),
            oauth_project_seed: None,
            oauth_cred_paths: Vec::new(),
            oauth_index: Arc::new(tokio::sync::Mutex::new(0)),
            auth_service: None, // Missing auth_service
            auth_profile_override: None,
            oauth_client_id: None,
            oauth_client_secret: None,
            base_url: None,
            router_profile: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            native_tools: false,
            schema_cache: SchemaCleanCache::new(),
        };

        let result = model_provider.warmup().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("ManagedOAuth requires auth_service")
        );
    }

    #[tokio::test]
    async fn warmup_cli_oauth_skips_validation() {
        let model_provider = test_model_provider(Some(test_oauth_auth("fake_token")));
        let result = model_provider.warmup().await;
        // Should succeed without making HTTP requests
        assert!(result.is_ok());
    }

    // ── Part enum serialization tests ────────────────────────────────────

    #[test]
    fn part_text_serializes_as_text_object() {
        let part = Part::text("hello");
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json, serde_json::json!({"text": "hello"}));
    }

    #[test]
    fn part_inline_serializes_as_inline_data_object() {
        let part = Part::Inline {
            inline_data: InlineData {
                mime_type: "image/png".to_string(),
                data: "iVBOR...".to_string(),
            },
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"inline_data": {"mime_type": "image/png", "data": "iVBOR..."}})
        );
    }

    #[test]
    fn part_text_constructor_accepts_string_and_str() {
        let from_str = Part::text("hello");
        let from_string = Part::text(String::from("hello"));
        // Both should serialize identically
        assert_eq!(
            serde_json::to_value(&from_str).unwrap(),
            serde_json::to_value(&from_string).unwrap(),
        );
    }

    #[test]
    fn content_with_mixed_parts_serializes_correctly() {
        let content = Content {
            role: Some("user".to_string()),
            parts: vec![
                Part::text("Describe this image:"),
                Part::Inline {
                    inline_data: InlineData {
                        mime_type: "image/jpeg".to_string(),
                        data: "/9j/4AAQ...".to_string(),
                    },
                },
            ],
        };
        let json = serde_json::to_value(&content).unwrap();
        let parts = json["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].get("text").is_some());
        assert!(parts[1].get("inline_data").is_some());
    }

    // ── build_parts tests ────────────────────────────────────────────────

    #[test]
    fn build_parts_plain_text_returns_single_text_part() {
        let parts = build_parts("Hello, world!");
        assert_eq!(parts.len(), 1);
        assert_eq!(
            serde_json::to_value(&parts[0]).unwrap(),
            serde_json::json!({"text": "Hello, world!"})
        );
    }

    #[test]
    fn build_parts_empty_string_returns_single_text_part() {
        let parts = build_parts("");
        assert_eq!(parts.len(), 1);
        // Falls back to original content when no markers and trimmed is empty
        assert_eq!(
            serde_json::to_value(&parts[0]).unwrap(),
            serde_json::json!({"text": ""})
        );
    }

    #[test]
    fn build_parts_extracts_data_uri_as_inline_part() {
        let content = "Check this [IMAGE:data:image/png;base64,iVBORw0KGgo=]";
        let parts = build_parts(content);
        assert_eq!(parts.len(), 2);
        // First part is text
        assert_eq!(
            serde_json::to_value(&parts[0]).unwrap(),
            serde_json::json!({"text": "Check this"})
        );
        // Second part is inline image
        assert_eq!(
            serde_json::to_value(&parts[1]).unwrap(),
            serde_json::json!({"inline_data": {"mime_type": "image/png", "data": "iVBORw0KGgo="}})
        );
    }

    #[test]
    fn build_parts_multiple_images() {
        let content = "Image A: [IMAGE:data:image/png;base64,AAAA] Image B: [IMAGE:data:image/jpeg;base64,BBBB]";
        let parts = build_parts(content);
        assert_eq!(parts.len(), 3); // text + 2 images
        // Verify both inline parts
        let inline_parts: Vec<_> = parts
            .iter()
            .filter(|p| matches!(p, Part::Inline { .. }))
            .collect();
        assert_eq!(inline_parts.len(), 2);
    }

    #[test]
    fn build_parts_ignores_non_data_uri_markers() {
        // File paths and URLs are not data URIs — build_parts should only
        // extract data: URIs, leaving non-data markers as stripped text.
        let content = "Look [IMAGE:/tmp/photo.png]";
        let parts = build_parts(content);
        // parse_image_markers extracts the marker, but build_parts only
        // converts data: URIs to inline parts. The text remains.
        for part in &parts {
            assert!(matches!(part, Part::Text { .. }));
        }
    }

    #[test]
    fn build_parts_image_only_still_produces_inline_part() {
        let content = "[IMAGE:data:image/gif;base64,R0lGODlh]";
        let parts = build_parts(content);
        // Should have just the inline part (text is empty after marker removal)
        assert_eq!(parts.len(), 1);
        assert!(matches!(&parts[0], Part::Inline { .. }));
    }

    // ── chat_with_history uses build_parts for user messages ─────────────

    #[test]
    fn chat_with_history_maps_roles_correctly() {
        let messages = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello [IMAGE:data:image/png;base64,AA==]"),
        ];

        let (contents, system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, None)
                .expect("user-anchored history must build");

        let system_instruction = system_instruction.expect("system prompt should be separated");
        assert_eq!(system_instruction.role, None);
        assert!(
            matches!(&system_instruction.parts[0], Part::Text { text } if text == "You are helpful")
        );

        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].role.as_deref(), Some("user"));
        assert!(
            contents[0]
                .parts
                .iter()
                .any(|p| matches!(p, Part::Inline { .. }))
        );
    }

    #[test]
    fn chat_contents_preserves_trailing_model_turn_and_appends_user_continuation() {
        let messages = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello"),
            ChatMessage::assistant("I see the image"),
        ];

        let (contents, _system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, None)
                .expect("history with a prior user turn must build");

        // the model turn is the context a continuation needs, so it is kept
        // and the request is anchored with a final user continuation turn
        assert_eq!(contents.len(), 3, "model turn must be preserved");
        assert_eq!(contents[0].role.as_deref(), Some("user"));
        assert_eq!(contents[1].role.as_deref(), Some("model"));
        assert!(
            matches!(&contents[1].parts[0], Part::Text { text } if text == "I see the image"),
            "the assistant context must survive the request build"
        );
        assert_eq!(contents[2].role.as_deref(), Some("user"));
        assert!(matches!(&contents[2].parts[0], Part::Text { text } if text == "[continue]"));
    }

    #[test]
    fn chat_contents_model_only_history_fails_explicitly() {
        let messages = vec![ChatMessage::assistant("I see the image")];

        let result = GeminiModelProvider::build_chat_contents(&messages, None);

        let err = result.expect_err("model-only history must fail instead of losing context");
        assert!(
            err.to_string()
                .contains("history ends on model turns but contains no user turn"),
            "error should name the anchoring problem, got: {err}"
        );
    }

    #[test]
    fn chat_contents_empty_history_falls_back_to_bare_continue() {
        let messages = vec![ChatMessage::system("You are helpful")];

        let (contents, _system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, None)
                .expect("system-only history must build with a bare anchor turn");

        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].role.as_deref(), Some("user"));
        assert!(matches!(&contents[0].parts[0], Part::Text { text } if text == "[continue]"));
    }

    #[test]
    fn chat_contents_ending_on_user_turn_is_untouched() {
        let messages = vec![
            ChatMessage::user("Hello"),
            ChatMessage::assistant("Hi"),
            ChatMessage::user("Now continue"),
        ];

        let (contents, _system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, None)
                .expect("history already ending on a user turn must build");

        assert_eq!(contents.len(), 3, "no synthetic turn may be appended");
        assert!(
            !contents.iter().any(|c| {
                c.parts
                    .iter()
                    .any(|p| matches!(p, Part::Text { text } if text == "[continue]"))
            }),
            "no [continue] placeholder may appear"
        );
    }

    #[test]
    fn chat_contents_append_tool_instructions_to_system_prompt() {
        let messages = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello"),
        ];

        let (_contents, system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, Some("Use tools carefully"))
                .expect("user-anchored history must build");

        let system_instruction = system_instruction.expect("system prompt should include tools");
        assert!(
            matches!(&system_instruction.parts[0], Part::Text { text } if text == "You are helpful\n\nUse tools carefully")
        );
    }

    #[test]
    fn chat_contents_create_system_prompt_from_tool_instructions() {
        let messages = vec![ChatMessage::user("Hello")];

        let (_contents, system_instruction) =
            GeminiModelProvider::build_chat_contents(&messages, Some("Use tools carefully"))
                .expect("user-anchored history must build");

        let system_instruction =
            system_instruction.expect("tool instructions should be system prompt");
        assert!(
            matches!(&system_instruction.parts[0], Part::Text { text } if text == "Use tools carefully")
        );
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use crate::opencode_session::{OPENCODE_SESSION_HEADER, RouterProfile};
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use zeroclaw_api::tool::ToolSpec;

    const ARGON_BASE: &str = "https://opencode.ai/inference/go/v1";
    const ARGON_MODEL: &str = "gemini-4-argon-contributor";

    type Captured = Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>>;

    async fn serve(
        status: u16,
        body: Value,
        extra_headers: Vec<(&'static str, &'static str)>,
    ) -> (String, Captured, tokio::task::JoinHandle<()>) {
        let captured: Captured = Arc::new(Mutex::new(Vec::new()));
        let seen = captured.clone();
        let app = axum::Router::new().fallback(
            move |headers: axum::http::HeaderMap, axum::Json(request): axum::Json<Value>| {
                let seen = seen.clone();
                let body = body.to_string();
                let extra_headers = extra_headers.clone();
                async move {
                    seen.lock().unwrap().push((headers, request));
                    let mut response = axum::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json");
                    for (name, value) in extra_headers {
                        response = response.header(name, value);
                    }
                    response.body(axum::body::Body::from(body)).unwrap()
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = ::zeroclaw_spawn::spawn!(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/inference/go/v1"), captured, server)
    }

    fn router_builder(base: &str) -> GeminiBuilder {
        GeminiModelProvider::builder("argon")
            .api_key(Some("router-key"))
            .base_url(base)
            .router_profile(RouterProfile::opencode())
    }

    fn router_provider(base: &str) -> GeminiModelProvider {
        router_builder(base).native_tools(true).try_build().unwrap()
    }

    fn sample_request() -> GenerateContentRequest {
        GenerateContentRequest {
            contents: vec![Content {
                role: Some("user".into()),
                parts: vec![Part::text("hello")],
            }],
            system_instruction: None,
            generation_config: GenerationConfig {
                temperature: None,
                max_output_tokens: 8192,
            },
            tools: None,
        }
    }

    fn built_request(provider: &GeminiModelProvider) -> reqwest::Request {
        let auth = provider.auth.as_ref().unwrap();
        let url = provider.generate_content_url(ARGON_MODEL, auth);
        provider
            .build_generate_content_request(
                auth,
                &url,
                &sample_request(),
                ARGON_MODEL,
                true,
                None,
                None,
            )
            .unwrap()
            .build()
            .unwrap()
    }

    fn weather_tool() -> ToolSpec {
        ToolSpec::new(
            "get_weather",
            "Weather by city",
            json!({
                "type": "object",
                "properties": {"city": {"type": "string", "minLength": 1}},
                "required": ["city"],
                "additionalProperties": false,
                "$schema": "http://json-schema.org/draft-07/schema#"
            }),
        )
    }

    fn function_call_response() -> Value {
        json!({
            "candidates": [{"content": {"role": "model", "parts": [{
                "functionCall": {"name": "get_weather", "args": {"city": "Paris"}, "id": "call-1"},
                "thoughtSignature": "SIG-ONE"
            }]}}],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3}
        })
    }

    fn text_response(text: &str) -> Value {
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}]})
    }

    async fn native_chat(
        provider: &GeminiModelProvider,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> anyhow::Result<ProviderChatResponse> {
        provider
            .chat(
                ProviderChatRequest {
                    messages,
                    tools: Some(tools),
                    thinking: None,
                },
                ARGON_MODEL,
                None,
            )
            .await
    }

    fn assistant_history(response: &ProviderChatResponse) -> ChatMessage {
        ChatMessage::assistant(
            json!({"content": response.text, "tool_calls": response.tool_calls}).to_string(),
        )
    }

    fn tool_result(id: &str, content: &str) -> ChatMessage {
        ChatMessage::tool(json!({"tool_call_id": id, "content": content}).to_string())
    }

    #[test]
    fn generate_content_url_uses_the_builder_base_url() {
        let provider = router_builder(ARGON_BASE).try_build().unwrap();
        let url = provider.generate_content_url(ARGON_MODEL, provider.auth.as_ref().unwrap());
        assert_eq!(
            url,
            "https://opencode.ai/inference/go/v1/models/gemini-4-argon-contributor:generateContent"
        );
        assert_eq!(provider.default_base_url(), Some(ARGON_BASE));
    }

    #[test]
    fn generate_content_url_defaults_to_ai_studio() {
        let provider = GeminiModelProvider::builder("plain")
            .api_key(Some("k"))
            .build();
        let url =
            provider.generate_content_url("gemini-2.0-flash", provider.auth.as_ref().unwrap());
        assert_eq!(
            url,
            format!("{BASE_URL}/models/gemini-2.0-flash:generateContent")
        );
        assert_eq!(provider.default_base_url(), Some(BASE_URL));
    }

    #[test]
    fn request_carries_session_and_user_agent_with_a_profile() {
        let request = built_request(&router_builder(ARGON_BASE).try_build().unwrap());
        let session = request.headers().get(OPENCODE_SESSION_HEADER).unwrap();
        assert!(!session.to_str().unwrap().is_empty());
        assert_eq!(
            request.headers().get(reqwest::header::USER_AGENT).unwrap(),
            crate::opencode_session::OPENCODE_USER_AGENT
        );
    }

    #[test]
    fn request_has_no_router_headers_without_a_profile() {
        let provider = GeminiModelProvider::builder("plain")
            .api_key(Some("k"))
            .build();
        let request = built_request(&provider);
        assert!(request.headers().get(OPENCODE_SESSION_HEADER).is_none());
        assert!(request.headers().get(reqwest::header::USER_AGENT).is_none());
    }

    #[test]
    fn request_sends_the_api_key_in_the_goog_header() {
        let request = built_request(&router_builder(ARGON_BASE).try_build().unwrap());
        let key = request.headers().get(GOOGLE_API_KEY_HEADER).unwrap();
        assert_eq!(key, "router-key");
        assert!(key.is_sensitive());
        assert!(request.headers().get(AUTHORIZATION_HEADER).is_none());
    }

    const AUTHORIZATION_HEADER: &str = "authorization";

    #[tokio::test]
    async fn warmup_sends_nothing_in_router_mode() {
        let (base, captured, server) = serve(200, text_response("x"), vec![]).await;
        let provider = router_provider(&base);
        provider.warmup().await.expect("router warmup is a no-op");
        server.abort();
        assert!(captured.lock().unwrap().is_empty());
    }

    #[test]
    fn router_mode_without_a_key_fails_instead_of_google_oauth() {
        for key in [None, Some(""), Some("  ")] {
            let result = GeminiModelProvider::builder("argon")
                .api_key(key)
                .base_url(ARGON_BASE)
                .router_profile(RouterProfile::opencode())
                .try_build();
            let Err(error) = result else {
                panic!("no key in router mode must fail");
            };
            assert!(!error.to_string().contains("oauth_creds"));
        }
        let built = GeminiModelProvider::builder("argon")
            .router_profile(RouterProfile::opencode())
            .build();
        assert!(built.auth.is_none());
    }

    #[tokio::test]
    async fn client_timeout_comes_from_the_builder() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = ::zeroclaw_spawn::spawn!(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    held.push(socket);
                }
            }
        });
        let provider = router_builder(&format!("http://{addr}/v1"))
            .timeout_secs(1)
            .try_build()
            .unwrap();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            provider.chat_with_system(None, "hi", ARGON_MODEL, None),
        )
        .await;
        server.abort();
        assert!(outcome.expect("client timeout must fire first").is_err());
    }

    #[tokio::test]
    async fn generation_config_uses_the_builder_output_limit() {
        let (base, captured, server) = serve(200, text_response("ok"), vec![]).await;
        let limited = router_builder(&base)
            .max_output_tokens(4096)
            .try_build()
            .unwrap();
        limited
            .chat_with_system(None, "hi", ARGON_MODEL, None)
            .await
            .unwrap();
        let default = router_builder(&base).try_build().unwrap();
        default
            .chat_with_system(None, "hi", ARGON_MODEL, None)
            .await
            .unwrap();
        server.abort();
        let seen = captured.lock().unwrap();
        assert_eq!(seen[0].1["generationConfig"]["maxOutputTokens"], 4096);
        assert_eq!(seen[1].1["generationConfig"]["maxOutputTokens"], 8192);
    }

    #[tokio::test]
    async fn chat_with_system_still_returns_text_in_router_mode() {
        let (base, captured, server) = serve(200, text_response("plain answer"), vec![]).await;
        let provider = router_provider(&base);
        let text = provider
            .chat_with_system(Some("sys"), "hi", ARGON_MODEL, None)
            .await
            .unwrap();
        let history = provider
            .chat_with_history(&[ChatMessage::user("hi")], ARGON_MODEL, None)
            .await
            .unwrap();
        server.abort();
        assert_eq!(text, "plain answer");
        assert_eq!(history, "plain answer");
        let seen = captured.lock().unwrap();
        assert!(seen[0].0.get(OPENCODE_SESSION_HEADER).is_some());
        assert!(seen[0].1.get("tools").is_none());
    }

    #[test]
    fn native_tools_flag_switches_capabilities() {
        let on = router_builder(ARGON_BASE)
            .native_tools(true)
            .try_build()
            .unwrap();
        assert!(on.capabilities().native_tool_calling);
        assert!(on.supports_native_tools());
        let off = router_builder(ARGON_BASE).try_build().unwrap();
        assert!(!off.capabilities().native_tool_calling);
        assert!(!off.supports_native_tools());
        assert!(matches!(
            off.convert_tools(&[weather_tool()]),
            ToolsPayload::PromptGuided { .. }
        ));
    }

    #[test]
    fn tools_serialize_as_function_declarations() {
        let provider = router_provider(ARGON_BASE);
        let ToolsPayload::Gemini {
            function_declarations,
        } = provider.convert_tools(&[weather_tool()])
        else {
            panic!("native mode must produce the Gemini payload");
        };
        assert_eq!(function_declarations.len(), 1);
        let declaration = &function_declarations[0];
        assert_eq!(declaration["name"], "get_weather");
        assert_eq!(declaration["description"], "Weather by city");
        assert_eq!(declaration["parameters"]["required"], json!(["city"]));
        let text = declaration["parameters"].to_string();
        assert!(!text.contains("additionalProperties"));
        assert!(!text.contains("$schema"));
        assert!(!text.contains("minLength"));
    }

    #[test]
    fn part_variants_serialize_to_the_router_json() {
        let call = serde_json::to_value(Part::FunctionCall {
            function_call: FunctionCallPart {
                name: "get_weather".into(),
                args: json!({"city": "Paris"}),
                id: Some("call-1".into()),
            },
            thought_signature: Some("SIG-ONE".into()),
        })
        .unwrap();
        assert_eq!(
            call,
            json!({
                "functionCall": {"name": "get_weather", "args": {"city": "Paris"}, "id": "call-1"},
                "thoughtSignature": "SIG-ONE"
            })
        );
        let bare = serde_json::to_value(Part::FunctionCall {
            function_call: FunctionCallPart {
                name: "f".into(),
                args: json!({}),
                id: None,
            },
            thought_signature: None,
        })
        .unwrap();
        assert_eq!(bare, json!({"functionCall": {"name": "f", "args": {}}}));
        let response = serde_json::to_value(Part::FunctionResponse {
            function_response: FunctionResponsePart {
                name: "get_weather".into(),
                response: json!({"result": "sunny"}),
                id: None,
            },
        })
        .unwrap();
        assert_eq!(
            response,
            json!({"functionResponse": {"name": "get_weather", "response": {"result": "sunny"}}})
        );
    }

    #[test]
    fn response_function_call_becomes_tool_call_with_signature() {
        let result: GenerateContentResponse =
            serde_json::from_value(function_call_response()).unwrap();
        let response = GeminiModelProvider::chat_response_from_native(result).unwrap();
        assert_eq!(response.text, None);
        assert_eq!(response.tool_calls.len(), 1);
        let call = &response.tool_calls[0];
        assert_eq!(call.id, "call-1");
        assert_eq!(call.name, "get_weather");
        assert_eq!(call.arguments, r#"{"city":"Paris"}"#);
        assert_eq!(
            call.extra_content,
            Some(json!({"google": {"thought_signature": "SIG-ONE"}}))
        );
        assert_eq!(response.usage.unwrap().input_tokens, Some(11));
    }

    #[test]
    fn response_function_call_without_id_gets_a_unique_synthetic_id() {
        let result: GenerateContentResponse = serde_json::from_value(json!({
            "candidates": [{"content": {"parts": [
                {"functionCall": {"name": "f", "args": {"a": 1}}},
                {"functionCall": {"name": "f", "args": {"a": 2}}}
            ]}}]
        }))
        .unwrap();
        let response = GeminiModelProvider::chat_response_from_native(result).unwrap();
        assert_eq!(response.tool_calls.len(), 2);
        assert_ne!(response.tool_calls[0].id, response.tool_calls[1].id);
        assert!(
            response
                .tool_calls
                .iter()
                .all(|c| c.extra_content.is_none())
        );
    }

    #[test]
    fn parallel_function_calls_keep_every_signature_found() {
        let result: GenerateContentResponse = serde_json::from_value(json!({
            "candidates": [{"content": {"parts": [
                {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}, "id": "a"},
                 "thoughtSignature": "SIG-FIRST"},
                {"functionCall": {"name": "get_weather", "args": {"city": "Rome"}, "id": "b"}}
            ]}}]
        }))
        .unwrap();
        let response = GeminiModelProvider::chat_response_from_native(result).unwrap();
        assert_eq!(response.tool_calls.len(), 2);
        assert_eq!(response.tool_calls[0].id, "a");
        assert_eq!(response.tool_calls[1].id, "b");
        assert_eq!(
            response.tool_calls[0].extra_content,
            Some(json!({"google": {"thought_signature": "SIG-FIRST"}}))
        );
        assert_eq!(response.tool_calls[1].extra_content, None);
        assert_eq!(response.tool_calls[1].arguments, r#"{"city":"Rome"}"#);
    }

    #[tokio::test]
    async fn chat_sends_tools_and_returns_a_function_call_only_response() {
        let (base, captured, server) = serve(200, function_call_response(), vec![]).await;
        let provider = router_provider(&base);
        let response = native_chat(
            &provider,
            &[ChatMessage::user("weather?")],
            &[weather_tool()],
        )
        .await
        .expect("a function call without text is a normal response");
        server.abort();
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "get_weather");
        let seen = captured.lock().unwrap();
        let declarations = &seen[0].1["tools"][0]["functionDeclarations"];
        assert_eq!(declarations[0]["name"], "get_weather");
        assert!(
            !declarations[0]["parameters"]
                .to_string()
                .contains("additionalProperties")
        );
        assert!(seen[0].0.get(GOOGLE_API_KEY_HEADER).is_some());
    }

    #[tokio::test]
    async fn history_round_trip_returns_the_signature() {
        let (base, captured, server) = serve(200, function_call_response(), vec![]).await;
        let provider = router_provider(&base);
        let first = native_chat(
            &provider,
            &[ChatMessage::user("weather?")],
            &[weather_tool()],
        )
        .await
        .unwrap();
        server.abort();
        let (base, captured_two, server) = serve(200, text_response("sunny"), vec![]).await;
        let provider = router_provider(&base);
        let history = vec![
            ChatMessage::user("weather?"),
            assistant_history(&first),
            tool_result("call-1", "sunny, 21C"),
        ];
        let second = native_chat(&provider, &history, &[weather_tool()])
            .await
            .unwrap();
        server.abort();
        assert_eq!(second.text.as_deref(), Some("sunny"));
        drop(captured);
        let seen = captured_two.lock().unwrap();
        let contents = &seen[0].1["contents"];
        assert_eq!(contents[1]["role"], "model");
        assert_eq!(
            contents[1]["parts"][0],
            json!({
                "functionCall": {"name": "get_weather", "args": {"city": "Paris"}, "id": "call-1"},
                "thoughtSignature": "SIG-ONE"
            })
        );
        assert_eq!(contents[2]["role"], "user");
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["name"],
            "get_weather"
        );
        assert_eq!(
            contents[2]["parts"][0]["functionResponse"]["response"],
            json!({"result": "sunny, 21C"})
        );
    }

    #[test]
    fn history_without_a_signature_sends_no_signature() {
        let call = ToolCall {
            id: "b".into(),
            name: "get_weather".into(),
            arguments: r#"{"city":"Rome"}"#.into(),
            extra_content: None,
        };
        let messages = vec![
            ChatMessage::user("go"),
            ChatMessage::assistant(json!({"content": null, "tool_calls": [call]}).to_string()),
            tool_result("b", "rainy"),
        ];
        let (contents, _) = GeminiModelProvider::build_native_contents(&messages).unwrap();
        let part = serde_json::to_value(&contents[1].parts[0]).unwrap();
        assert!(part.get("thoughtSignature").is_none());
        assert!(part.get("functionCall").is_some());
    }

    #[test]
    fn tool_result_message_maps_to_function_response() {
        let calls: Vec<ToolCall> = ["a", "b"]
            .iter()
            .map(|id| ToolCall {
                id: (*id).into(),
                name: format!("tool_{id}"),
                arguments: "{}".into(),
                extra_content: None,
            })
            .collect();
        let messages = vec![
            ChatMessage::user("go"),
            ChatMessage::assistant(json!({"content": "working", "tool_calls": calls}).to_string()),
            tool_result("b", "result-b"),
            tool_result("a", "result-a"),
        ];
        let (contents, _) = GeminiModelProvider::build_native_contents(&messages).unwrap();
        assert_eq!(contents.len(), 3);
        let model = serde_json::to_value(&contents[1]).unwrap();
        assert_eq!(model["parts"][0], json!({"text": "working"}));
        assert_eq!(model["parts"][1]["functionCall"]["name"], "tool_a");
        let user = serde_json::to_value(&contents[2]).unwrap();
        assert_eq!(user["role"], "user");
        assert_eq!(user["parts"][0]["functionResponse"]["name"], "tool_a");
        assert_eq!(
            user["parts"][0]["functionResponse"]["response"],
            json!({"result": "result-a"})
        );
        assert_eq!(user["parts"][1]["functionResponse"]["name"], "tool_b");
        assert_eq!(
            user["parts"][1]["functionResponse"]["response"],
            json!({"result": "result-b"})
        );
    }

    #[test]
    fn native_history_still_ends_on_a_user_turn() {
        let call = ToolCall {
            id: "a".into(),
            name: "f".into(),
            arguments: "{}".into(),
            extra_content: None,
        };
        let messages = vec![
            ChatMessage::user("go"),
            ChatMessage::assistant(json!({"content": null, "tool_calls": [call]}).to_string()),
        ];
        let (contents, _) = GeminiModelProvider::build_native_contents(&messages).unwrap();
        assert_eq!(contents.last().unwrap().role.as_deref(), Some("user"));
    }

    #[tokio::test]
    async fn text_only_response_still_returns_text() {
        let (base, _captured, server) = serve(200, text_response("just text"), vec![]).await;
        let provider = router_provider(&base);
        let response = native_chat(&provider, &[ChatMessage::user("hi")], &[weather_tool()])
            .await
            .unwrap();
        server.abort();
        assert_eq!(response.text.as_deref(), Some("just text"));
        assert!(response.tool_calls.is_empty());
    }

    #[tokio::test]
    async fn thought_only_response_is_not_shown_in_native_mode() {
        let body = json!({"candidates": [{"content": {"parts": [
            {"text": "private reasoning", "thought": true}
        ]}}]});
        let (base, _captured, server) = serve(200, body.clone(), vec![]).await;
        let native = router_provider(&base);
        let error = native_chat(&native, &[ChatMessage::user("hi")], &[weather_tool()])
            .await
            .expect_err("thought-only must not become visible text");
        assert!(
            error
                .downcast_ref::<zeroclaw_api::model_provider::SemanticEmptyTerminalCompletion>()
                .is_some()
        );
        let prompt_guided = router_builder(&base).try_build().unwrap();
        let text = prompt_guided
            .chat_with_system(None, "hi", ARGON_MODEL, None)
            .await
            .unwrap();
        server.abort();
        assert_eq!(text, "private reasoning");
    }

    #[test]
    fn mixed_thought_and_answer_parts_keep_only_the_answer() {
        let result: GenerateContentResponse = serde_json::from_value(json!({
            "candidates": [{"content": {"parts": [
                {"text": "hidden", "thought": true},
                {"text": "shown"}
            ]}}]
        }))
        .unwrap();
        let response = GeminiModelProvider::chat_response_from_native(result).unwrap();
        assert_eq!(response.text.as_deref(), Some("shown"));
    }

    #[tokio::test]
    async fn router_http_error_keeps_status_and_retry_after() {
        let (base, _captured, server) = serve(
            429,
            json!({"error": {"message": "slow down for user-secret-detail"}}),
            vec![("retry-after", "17")],
        )
        .await;
        let provider = router_provider(&base);
        let error = native_chat(&provider, &[ChatMessage::user("hi")], &[weather_tool()])
            .await
            .expect_err("429 must fail");
        let plain = provider
            .chat_with_system(None, "hi", ARGON_MODEL, None)
            .await
            .expect_err("429 must fail on the text path too");
        server.abort();
        for error in [error, plain] {
            let typed = error
                .downcast_ref::<crate::ProviderHttpError>()
                .expect("router errors keep the typed HTTP boundary");
            assert_eq!(typed.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(typed.retry_after_secs(), Some(17));
        }
    }
}
