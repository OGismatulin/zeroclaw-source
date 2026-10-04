use crate::helpers::{domain_guard, response_body};
use anyhow::Context;
use async_trait::async_trait;
use reqwest::header::LOCATION;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult, with_ephemeral_workspace_warning};
use zeroclaw_config::policy::SecurityPolicy;
use zeroclaw_config::policy::ToolOperation;

const FAL_RESPONSE_LIMIT_BYTES: usize = 1024 * 1024;
const FAL_ERROR_LIMIT_BYTES: usize = 16 * 1024;
const GENERATED_IMAGE_LIMIT_BYTES: usize = 20 * 1024 * 1024;
const MAX_IMAGE_REDIRECTS: usize = 10;

struct ValidatedImageTarget {
    url: reqwest::Url,
    host: String,
    resolved_addrs: Vec<SocketAddr>,
}

fn parse_public_https_url(raw_url: &str) -> anyhow::Result<(reqwest::Url, String, u16)> {
    let raw_url = raw_url.trim();
    if raw_url.is_empty() || raw_url.chars().any(char::is_whitespace) {
        anyhow::bail!("Generated image URL must be a non-empty URL without whitespace");
    }

    let mut url = reqwest::Url::parse(raw_url).context("Invalid generated image URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("Generated image URL must use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("Generated image URL userinfo is not allowed");
    }

    let request_host = url
        .host_str()
        .ok_or_else(|| anyhow::Error::msg("Generated image URL must include a host"))?;
    if request_host.ends_with('.') {
        anyhow::bail!("Generated image URL host must not end with a dot");
    }
    let host = domain_guard::normalize_domain(request_host)
        .ok_or_else(|| anyhow::Error::msg("Generated image URL host is invalid"))?;
    let ip_literal = host.parse::<IpAddr>().ok();
    if domain_guard::is_private_or_local_host(&host) {
        anyhow::bail!("Generated image URL targets a local or non-global host");
    }
    if ip_literal.is_some_and(domain_guard::is_cloud_metadata_ip) {
        anyhow::bail!("Generated image URL targets a cloud metadata host");
    }

    // Request the host that was validated, not the raw spelling. Normalization
    // can change the host (a leading dot is stripped), and the DNS pin applied
    // by `generated_image_client_with_builder` is keyed on the normalized host.
    // Without this, `resolve_to_addrs` never matches the request host and
    // reqwest silently falls back to its own unvalidated lookup. IP-literal
    // hosts are left alone: they carry no DNS pin, and `set_host` rejects the
    // unbracketed IPv6 form that normalization produces.
    if ip_literal.is_none() {
        url.set_host(Some(&host))
            .map_err(|_| anyhow::Error::msg("Generated image URL host is invalid"))?;
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::Error::msg("Generated image URL must include a valid port"))?;
    Ok((url, host, port))
}

async fn validate_image_target(
    raw_url: &str,
    nat64_prefixes: &[domain_guard::Nat64Prefix],
) -> anyhow::Result<ValidatedImageTarget> {
    let (url, host, port) = parse_public_https_url(raw_url)?;
    let resolved_addrs = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("Failed to resolve generated image host '{host}'"))?
            .collect::<Vec<_>>()
    };
    let ips = resolved_addrs
        .iter()
        .map(|addr| addr.ip())
        .collect::<Vec<_>>();
    domain_guard::validate_resolved_ips_are_public(&host, &ips, nat64_prefixes)?;

    Ok(ValidatedImageTarget {
        url,
        host,
        resolved_addrs,
    })
}

fn generated_image_client_with_builder(
    target: &ValidatedImageTarget,
    builder: reqwest::ClientBuilder,
) -> anyhow::Result<reqwest::Client> {
    let builder = builder
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    let builder = if target.host.parse::<IpAddr>().is_ok() {
        builder
    } else {
        builder.resolve_to_addrs(&target.host, &target.resolved_addrs)
    };
    builder
        .build()
        .context("Failed to build generated image HTTP client")
}

fn generated_image_client(target: &ValidatedImageTarget) -> anyhow::Result<reqwest::Client> {
    generated_image_client_with_builder(target, reqwest::Client::builder())
}

async fn prepare_generated_image_target(
    raw_url: &str,
    nat64_prefixes: &[domain_guard::Nat64Prefix],
) -> anyhow::Result<(ValidatedImageTarget, reqwest::Client)> {
    let target = validate_image_target(raw_url, nat64_prefixes).await?;
    let client = generated_image_client(&target)?;
    Ok((target, client))
}

fn resolve_redirect_url(current: &reqwest::Url, location: &str) -> anyhow::Result<reqwest::Url> {
    current
        .join(location)
        .context("Invalid generated image redirect target")
}

fn resolve_image_filename(filename_arg: Option<&str>, nanos: u128) -> String {
    filename_arg
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            PathBuf::from(s).file_name().map_or_else(
                || "generated_image".to_string(),
                |n| n.to_string_lossy().to_string(),
            )
        })
        .unwrap_or_else(|| format!("generated_image_{nanos}"))
}

/// Format the tool output for a saved image.
///
/// Emits the saved path in a durable `File:` line ONLY — deliberately no
/// routable `[IMAGE:<path>]` marker. A marker would make the multimodal
/// pipeline detour the turn into a vision provider mid-tool-loop, poisoning
/// the transcript with a cross-provider `tool_call_id` / `reasoning_content`
/// mismatch and breaking delivery. The agent reads the `File:` path and
/// delivers the image explicitly via `send_file_telegram.py` instead.
fn format_image_tool_output(
    path_display: &str,
    size_kb: usize,
    model: &str,
    prompt: &str,
) -> String {
    format!(
        "Image generated successfully.\n\
         File: {path_display}\n\
         Size: {size_kb} KB\n\
         Model: {model}\n\
         Prompt: {prompt}",
    )
}

async fn read_fal_success_body(response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let body = response_body::read_bounded(response, Some(FAL_RESPONSE_LIMIT_BYTES))
        .await
        .context("Failed to read fal.ai response")?;
    if body.overflowed {
        anyhow::bail!("fal.ai response exceeds the 1 MiB size limit");
    }
    Ok(body.bytes)
}

async fn read_fal_error_text(response: reqwest::Response) -> anyhow::Result<String> {
    response_body::read_text(response, Some(FAL_ERROR_LIMIT_BYTES))
        .await
        .map(|(text, _)| text)
}

async fn read_generated_image_body(response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let body = response_body::read_bounded(response, Some(GENERATED_IMAGE_LIMIT_BYTES))
        .await
        .context("Failed to read generated image bytes")?;
    if body.overflowed {
        anyhow::bail!(
            "Generated image exceeds the {} MiB size limit",
            GENERATED_IMAGE_LIMIT_BYTES / (1024 * 1024)
        );
    }
    Ok(body.bytes)
}

/// Maximum accepted image size in bytes for either backend (fal download /
/// codex base64 decode). Guards against a hostile or runaway response.
const IMAGE_GEN_MAX_BYTES: usize = 25 * 1024 * 1024;

/// PNG file signature (first 8 bytes). Used to validate the codex-decoded
/// bytes before writing so a partial / non-PNG payload never lands on disk.
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Which backend generates the image.
///
/// `Fal` = fal.ai fast backend (FLUX family, ~10s). `Codex` = ChatGPT Codex
/// `image_generation` tool, higher quality (~90s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Fal,
    Codex,
}

/// Resolve the backend from an optional `quality` argument, falling back to the
/// configured `default_backend`. An unknown value resolves to the safe `Fal`
/// backend with a warning rather than silently routing somewhere unexpected.
pub(crate) fn resolve_backend(quality: Option<&str>, default_backend: &str) -> Backend {
    let choice = quality
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_backend);
    match choice {
        "high" => Backend::Codex,
        "fast" => Backend::Fal,
        other => {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_attrs(::serde_json::json!({ "quality_or_default": other })),
                "image_gen: unknown quality/default_backend value; falling back to fast (fal)"
            );
            Backend::Fal
        }
    }
}

/// Accepted `size` presets and legacy fal FLUX size values. Kept as one set so
/// both the new presets (`square|landscape|portrait|auto`) and the historical
/// FLUX values still validate (the tool was disabled, so this is not a prod
/// break, but explicit callers keep working).
const ACCEPTED_SIZES: &[&str] = &[
    "square",
    "landscape",
    "portrait",
    "auto",
    "square_hd",
    "landscape_4_3",
    "portrait_4_3",
    "landscape_16_9",
    "portrait_16_9",
];

/// Map a size preset to a built-in value for the given fal `size_param`.
/// `"aspect_ratio"` (grok-style models) yields `W:H` ratios; anything else
/// (including the default `"image_size"`) yields FLUX preset names.
pub(crate) fn builtin_size_map(size_param: &str, preset: &str) -> &'static str {
    match size_param {
        "aspect_ratio" => match preset {
            "landscape" | "landscape_16_9" => "16:9",
            "portrait" | "portrait_16_9" => "9:16",
            "landscape_4_3" => "4:3",
            "portrait_4_3" => "3:4",
            _ => "1:1", // square, auto, unknown
        },
        _ => match preset {
            // "image_size" and unknown params → FLUX presets
            "landscape" | "landscape_16_9" => "landscape_16_9",
            "portrait" | "portrait_16_9" => "portrait_16_9",
            "landscape_4_3" => "landscape_4_3",
            "portrait_4_3" => "portrait_4_3",
            _ => "square_hd",
        },
    }
}

/// Reserved fal.ai request body keys that are always set from live call
/// parameters and can never be overridden by config-supplied static fields.
const FAL_RESERVED_KEYS: [&str; 2] = ["prompt", "num_images"];

/// Build the fal.ai request body from config: static `extra` fields first, then
/// the size key (unless empty or a reserved name), then the always-winning
/// reserved `prompt`/`num_images`. Size value = `size_map[preset]` if present,
/// else the built-in map for `size_param` (an unknown `size_param` falls back
/// to the FLUX/`image_size` presets).
fn build_fal_body(
    prompt: &str,
    size: &str,
    size_param: &str,
    size_map: &std::collections::HashMap<String, String>,
    extra: &std::collections::HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in extra {
        map.insert(k.clone(), v.clone());
    }
    if !size_param.is_empty() && !FAL_RESERVED_KEYS.contains(&size_param) {
        let val: String = size_map
            .get(size)
            .cloned()
            .unwrap_or_else(|| builtin_size_map(size_param, size).to_string());
        map.insert(size_param.to_string(), serde_json::Value::String(val));
    }
    map.insert(
        "prompt".into(),
        serde_json::Value::String(prompt.to_string()),
    );
    map.insert("num_images".into(), serde_json::json!(1));
    serde_json::Value::Object(map)
}

/// Map a size preset to a codex `WxH` value (or "auto").
pub(crate) fn map_size_codex(p: &str) -> &'static str {
    match p {
        "landscape" | "landscape_16_9" => "1536x1024",
        "portrait" | "portrait_16_9" => "1024x1536",
        "auto" => "auto",
        _ => "1024x1024",
    }
}

/// Deterministic 8-hex correlation id from a seed (safe_name + prompt). Lets the
/// operator grep the raw error in the log by the same id shown to the user,
/// without pulling in any external crate.
fn short_correlation_id(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// Stable, user-facing message for a codex image failure. Deliberately omits
/// the raw internal error (which goes only to the operator log) and states no
/// fallback: the user is told the quality model failed, never silently served
/// a fast/fal or vector-diagram substitute.
fn codex_image_error_message(correlation_id: &str) -> String {
    format!(
        "Качественная генерация (GPT-image-2) не удалась (код: {correlation_id}). \
Попробуйте ещё раз или явно запросите быстрый режим генерации."
    )
}

/// Standalone dual-backend image generation tool.
///
/// `quality: fast` (default) routes to fal.ai (FLUX family); `quality: high`
/// routes to the ChatGPT Codex `image_generation` tool. Both save the PNG to
/// `{workspace}/images/{filename}.png` and return its path via a durable
/// `File:` line (no routable `[IMAGE:]` marker — see
/// `format_image_tool_output`).
pub struct ImageGenTool {
    security: Arc<SecurityPolicy>,
    workspace_dir: PathBuf,
    /// fal.ai model path for the fast backend (overridable per-call via `model`).
    fal_model: String,
    api_key_env: String,
    persistent_writes: bool,
    /// Backend used when a call omits `quality` ("fast" | "high").
    default_backend: String,
    /// Codex routing model for the high-quality backend.
    codex_model: String,
    /// Auth state dir for the in-process codex OAuth token (high backend).
    codex_state_dir: PathBuf,
    /// Whether the codex auth store encrypts secrets at rest.
    codex_encrypt_secrets: bool,
    /// JSON key that carries the size/aspect value in the fal request body
    /// (e.g. "image_size" for FLUX, "aspect_ratio" for grok; "" to omit size).
    fal_size_param: String,
    /// Preset → model-specific size value, overriding the built-in map.
    fal_size_map: std::collections::HashMap<String, String>,
    /// Static params merged verbatim into the fal request body.
    fal_extra_body: std::collections::HashMap<String, serde_json::Value>,
    /// Base URL for the fal.ai fast backend. Always `"https://fal.run"` in
    /// production; overridable in-crate by tests to point at a mock server
    /// (no trailing slash — callers append `/{model}`).
    fal_base_url: String,
    nat64_prefixes: Vec<domain_guard::Nat64Prefix>,
}

impl ImageGenTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        workspace_dir: PathBuf,
        fal_model: String,
        api_key_env: String,
        nat64_prefixes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Self::new_with_persistence(
            security,
            workspace_dir,
            fal_model,
            api_key_env,
            true,
            "fast".into(),
            "gpt-5.5".into(),
            PathBuf::from("."),
            false,
            "image_size".into(),
            Default::default(),
            Default::default(),
            nat64_prefixes,
        )
    }

    /// Construct with an explicit persistence flag derived from the active
    /// runtime adapter's `has_filesystem_access()`, plus dual-backend config.
    /// Mirrors [`super::file_write::FileWriteTool::new_with_persistence`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_persistence(
        security: Arc<SecurityPolicy>,
        workspace_dir: PathBuf,
        fal_model: String,
        api_key_env: String,
        persistent_writes: bool,
        default_backend: String,
        codex_model: String,
        codex_state_dir: PathBuf,
        codex_encrypt_secrets: bool,
        fal_size_param: String,
        fal_size_map: std::collections::HashMap<String, String>,
        fal_extra_body: std::collections::HashMap<String, serde_json::Value>,
        nat64_prefixes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            security,
            workspace_dir,
            fal_model,
            api_key_env,
            persistent_writes,
            default_backend,
            codex_model,
            codex_state_dir,
            codex_encrypt_secrets,
            fal_size_param,
            fal_size_map,
            fal_extra_body,
            fal_base_url: "https://fal.run".into(),
            nat64_prefixes: domain_guard::parse_nat64_prefixes(
                &nat64_prefixes,
                "security.nat64_prefixes",
            )?,
        })
    }

    /// Build a reusable HTTP client with reasonable timeouts.
    fn http_client() -> anyhow::Result<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to build fal.ai HTTP client")
    }

    async fn download_generated_image(
        image_url: &str,
        nat64_prefixes: &[domain_guard::Nat64Prefix],
    ) -> anyhow::Result<Vec<u8>> {
        let mut current_url =
            reqwest::Url::parse(image_url).context("Invalid generated image URL")?;

        for redirect_count in 0..=MAX_IMAGE_REDIRECTS {
            let (target, client) =
                prepare_generated_image_target(current_url.as_str(), nat64_prefixes).await?;
            let response = client
                .get(target.url.clone())
                .send()
                .await
                .context("Failed to download generated image")?;

            if response.status().is_redirection() {
                if redirect_count == MAX_IMAGE_REDIRECTS {
                    anyhow::bail!("Too many generated image redirects (max {MAX_IMAGE_REDIRECTS})");
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| anyhow::Error::msg("Generated image redirect omitted Location"))?
                    .to_str()
                    .context("Generated image redirect Location is not valid text")?;
                current_url = resolve_redirect_url(&target.url, location)?;
                continue;
            }

            if !response.status().is_success() {
                anyhow::bail!(
                    "Generated image download failed with HTTP {}",
                    response.status()
                );
            }

            return read_generated_image_body(response).await;
        }

        anyhow::bail!("Generated image redirect limit exceeded")
    }

    /// Read an API key from the environment.
    fn read_api_key(env_var: &str) -> Result<String, String> {
        std::env::var(env_var)
            .map(|v| v.trim().to_string())
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("Missing API key: set the {env_var} environment variable"))
    }

    /// Dispatcher: parse shared parameters, resolve the backend from `quality`
    /// (falling back to `default_backend`), then route to fal or codex.
    async fn generate(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // ── Parse shared parameters ────────────────────────────────
        let prompt = match args.get("prompt").and_then(|v| v.as_str()) {
            Some(p) if !p.trim().is_empty() => p.trim().to_string(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some("Missing required parameter: 'prompt'".into()),
                });
            }
        };

        // Sanitize filename — strip path components to prevent traversal.
        // When the caller doesn't provide one, generate a unique default so
        // successive calls without an explicit name never clobber each other.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let safe_name =
            resolve_image_filename(args.get("filename").and_then(|v| v.as_str()), nanos);

        let size = args
            .get("size")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("square")
            .to_string();

        // Validate size against the accepted preset + legacy set.
        if !ACCEPTED_SIZES.contains(&size.as_str()) {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "Invalid size '{size}'. Valid values: {}",
                    ACCEPTED_SIZES.join(", ")
                )),
            });
        }

        let quality = args.get("quality").and_then(|v| v.as_str());
        match resolve_backend(quality, &self.default_backend) {
            Backend::Fal => self.generate_fal(&prompt, &size, &args, &safe_name).await,
            Backend::Codex => self.generate_codex(&prompt, &size, &safe_name).await,
        }
    }

    /// Write generated PNG bytes to `{workspace}/images/{safe_name}.png`,
    /// enforcing the byte cap and (optionally) the PNG signature. On any
    /// failure no partial file is left behind.
    async fn save_image(
        &self,
        bytes: &[u8],
        safe_name: &str,
        model: &str,
        prompt: &str,
        require_png: bool,
    ) -> anyhow::Result<ToolResult> {
        if bytes.len() > IMAGE_GEN_MAX_BYTES {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "Generated image exceeds size cap ({} > {IMAGE_GEN_MAX_BYTES} bytes)",
                    bytes.len()
                )),
            });
        }
        if require_png && !bytes.starts_with(&PNG_MAGIC) {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("Generated image is not a valid PNG (bad signature)".into()),
            });
        }

        let images_dir = self.workspace_dir.join("images");
        tokio::fs::create_dir_all(&images_dir)
            .await
            .context("Failed to create images directory")?;

        let output_path = images_dir.join(format!("{safe_name}.png"));
        if let Err(e) = tokio::fs::write(&output_path, bytes).await {
            // Do not leave a partial file behind on write failure.
            let _ = tokio::fs::remove_file(&output_path).await;
            return Err(anyhow::Error::new(e).context("Failed to write image file"));
        }

        let size_kb = bytes.len() / 1024;
        // Emit a durable `File:` line ONLY — no routable `[IMAGE:…]` marker.
        // A marker would make the multimodal pipeline detour the turn into a
        // vision provider mid-tool-loop, poisoning the transcript with a
        // cross-provider tool_call_id / reasoning mismatch and breaking
        // delivery. The agent delivers the file via send_file_telegram.py.
        let path_display = output_path.display().to_string();
        let output = format_image_tool_output(&path_display, size_kb, model, prompt);
        Ok(ToolResult {
            success: true,
            output: output.into(),
            error: None,
        })
    }

    /// Fast backend: fal.ai synchronous API. `model` (per-call override) applies
    /// only here and is validated as a fal.ai path.
    async fn generate_fal(
        &self,
        prompt: &str,
        size: &str,
        args: &serde_json::Value,
        safe_name: &str,
    ) -> anyhow::Result<ToolResult> {
        let model = args
            .get("model")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.fal_model);
        let model = model.trim();

        // Validate model identifier: must look like a fal.ai model path
        // (e.g. "fal-ai/flux-2/turbo"). Reject values with "..", query
        // strings, or fragments that could redirect the HTTP request.
        if model.contains("..")
            || model.contains('?')
            || model.contains('#')
            || model.contains('\\')
            || model.starts_with('/')
        {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!(
                    "Invalid model identifier '{model}'. \
                     Must be a fal.ai model path (e.g. 'fal-ai/flux-2/turbo')."
                )),
            });
        }

        // ── Read API key ───────────────────────────────────────────
        let api_key = match Self::read_api_key(&self.api_key_env) {
            Ok(k) => k,
            Err(msg) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(msg),
                });
            }
        };

        // ── Call fal.ai ────────────────────────────────────────────
        let client = Self::http_client()?;
        let url = format!("{}/{model}", self.fal_base_url);

        let body = build_fal_body(
            prompt,
            size,
            &self.fal_size_param,
            &self.fal_size_map,
            &self.fal_extra_body,
        );

        let resp = client
            .post(&url)
            .header("Authorization", format!("Key {api_key}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("fal.ai request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = read_fal_error_text(resp).await.unwrap_or_default();
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(format!("fal.ai API error ({status}): {body_text}")),
            });
        }

        let fal_body = read_fal_success_body(resp).await?;
        let resp_json: serde_json::Value =
            serde_json::from_slice(&fal_body).context("Failed to parse fal.ai response as JSON")?;

        let image_url = resp_json
            .pointer("/images/0/url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ::zeroclaw_log::record!(
                    ERROR,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure),
                    "image_gen: fal.ai response missing image URL"
                );
                anyhow::Error::msg("No image URL in fal.ai response")
            })?;

        // ── Download image ─────────────────────────────────────────
        let bytes = match Self::download_generated_image(image_url, &self.nat64_prefixes).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(error.to_string()),
                });
            }
        };

        // fal may return PNG/JPEG/WEBP depending on the model; enforce the byte
        // cap but not the PNG signature here.
        self.save_image(&bytes, safe_name, model, prompt, false)
            .await
    }

    /// High-quality backend: ChatGPT Codex `image_generation` tool. `model`
    /// (fal override) does NOT apply here — codex uses `codex_model`.
    async fn generate_codex(
        &self,
        prompt: &str,
        size: &str,
        safe_name: &str,
    ) -> anyhow::Result<ToolResult> {
        let bytes = match zeroclaw_providers::openai_codex::generate_image_png(
            &self.codex_state_dir,
            self.codex_encrypt_secrets,
            prompt,
            map_size_codex(size),
            "png",
            &self.codex_model,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                // Raw internal error → operator log only (never the user-facing text).
                let cid = short_correlation_id(&format!("{safe_name}|{prompt}"));
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Fail)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "phase": "codex_image_generation",
                            "correlation_id": cid,
                            "error": e.to_string(),
                        })),
                    "image_gen: codex quality:high failed"
                );
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some(codex_image_error_message(&cid)),
                });
            }
        };

        // codex returns PNG (output_format=png) → enforce the signature.
        self.save_image(&bytes, safe_name, &self.codex_model, prompt, true)
            .await
    }
}

#[async_trait]
impl Tool for ImageGenTool {
    fn name(&self) -> &str {
        "image_gen"
    }

    fn description(&self) -> &str {
        "Generate an image from a text prompt. quality: fast (fal.ai fast model, default) \
         or high (Codex). Saves a PNG to the workspace images directory and returns \
         the file path. size: square|landscape|portrait|auto. model overrides the \
         fal model for the fast backend only."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Text prompt describing the image to generate."
                },
                "quality": {
                    "type": "string",
                    "enum": ["fast", "high"],
                    "description": "Backend: 'fast' (fal.ai) or 'high' (Codex). Defaults to the configured backend."
                },
                "filename": {
                    "type": "string",
                    "description": "Output filename without extension (default: 'generated_image'). Saved as PNG in workspace/images/."
                },
                "size": {
                    "type": "string",
                    "enum": ["square", "landscape", "portrait", "auto"],
                    "description": "Image aspect ratio / size preset (default: 'square')."
                },
                "model": {
                    "type": "string",
                    "description": "fal.ai model path for the fast backend only (overrides the configured model). Ignored when quality=high."
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Security: image generation is a side-effecting action (HTTP + file write).
        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "image_gen")
        {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(error),
            });
        }

        let mut result = self.generate(args).await?;
        // A generated image saved to an ephemeral workspace never reaches the
        // host and is lost at session end; warn loudly on success
        if !self.persistent_writes && result.success {
            result.output = with_ephemeral_workspace_warning(&result.output).into();
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zeroclaw_config::autonomy::AutonomyLevel;
    use zeroclaw_config::policy::SecurityPolicy;

    async fn held_open_chunked_response(
        byte_count: usize,
    ) -> (
        reqwest::Response,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        let server = zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 64 * 1024];
            let mut remaining = byte_count;
            while remaining > 0 {
                let chunk_len = remaining.min(chunk.len());
                stream
                    .write_all(format!("{chunk_len:x}\r\n").as_bytes())
                    .await
                    .unwrap();
                stream.write_all(&chunk[..chunk_len]).await.unwrap();
                stream.write_all(b"\r\n").await.unwrap();
                remaining -= chunk_len;
            }
            let _ = release_rx.await;
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });

        (
            reqwest::get(format!("http://{addr}")).await.unwrap(),
            release_tx,
            server,
        )
    }

    async fn finish_held_open_response(
        release: tokio::sync::oneshot::Sender<()>,
        server: tokio::task::JoinHandle<()>,
    ) {
        let _ = release.send(());
        server.await.unwrap();
    }

    fn test_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        })
    }

    fn test_tool() -> ImageGenTool {
        ImageGenTool::new(
            test_security(),
            std::env::temp_dir(),
            "fal-ai/flux-2/turbo".into(),
            "FAL_API_KEY".into(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn generated_image_target_rejects_private_and_userinfo_urls() {
        for url in [
            "https://127.0.0.1/image.png",
            "https://169.254.169.254/latest/meta-data",
            "https://user@example.com/image.png",
        ] {
            assert!(parse_public_https_url(url).is_err(), "accepted {url}");
        }
    }

    #[tokio::test]
    async fn generated_image_redirect_to_private_target_is_rejected() {
        let current = reqwest::Url::parse("https://cdn.example.com/image.png").unwrap();
        let redirect = resolve_redirect_url(&current, "https://127.0.0.1/private.png").unwrap();

        assert!(
            prepare_generated_image_target(redirect.as_str(), &[])
                .await
                .is_err()
        );
    }

    #[test]
    fn generated_image_target_requires_https() {
        assert!(parse_public_https_url("http://example.com/image.png").is_err());
        assert!(parse_public_https_url("https://example.com/image.png").is_ok());
    }

    #[test]
    fn generated_image_target_rejects_trailing_dot_host() {
        assert!(parse_public_https_url("https://example.com./image.png").is_err());
    }

    /// The returned URL must carry the host that was actually validated, not
    /// the raw spelling. `normalize_domain` strips a leading dot, so
    /// `https://.example.com/` validates and pins `example.com` while the raw
    /// URL still asks for `.example.com`. The pin is keyed on the normalized
    /// host, so a mismatch means `resolve_to_addrs` never matches and reqwest
    /// performs its own unvalidated lookup for the request host.
    #[test]
    fn generated_image_target_url_host_matches_the_validated_host() {
        let (url, host, _port) = parse_public_https_url("https://.example.com/img.png")
            .expect("leading-dot host normalizes to a public host");

        assert_eq!(host, "example.com", "host must normalize");
        assert_eq!(
            url.host_str(),
            Some(host.as_str()),
            "returned URL must request the validated host, otherwise the DNS \
             pin keyed on '{host}' never matches and reqwest re-resolves \
             '{:?}' unvalidated",
            url.host_str()
        );
    }

    #[tokio::test]
    async fn generated_image_target_accepts_public_ipv6_literal_without_dns() {
        let (target, _client) =
            prepare_generated_image_target("https://[2606:4700:4700::1111]/image.png", &[])
                .await
                .unwrap();
        let expected_ip = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();

        assert_eq!(target.host, expected_ip.to_string());
        assert_eq!(
            target.resolved_addrs,
            vec![SocketAddr::new(expected_ip, 443)]
        );
    }

    #[tokio::test]
    async fn generated_image_client_clears_proxy_configuration() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let direct_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct_addr = direct_listener.local_addr().unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let direct_task = zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = direct_listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
                )
                .await
                .unwrap();
        });
        let proxy_task = zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = proxy_listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy",
                )
                .await
                .unwrap();
        });

        let target = ValidatedImageTarget {
            url: reqwest::Url::parse(&format!("http://image.test:{}/", direct_addr.port()))
                .unwrap(),
            host: "image.test".to_string(),
            resolved_addrs: vec![direct_addr],
        };
        let proxy = reqwest::Proxy::http(format!("http://{proxy_addr}")).unwrap();
        let proxied_response = reqwest::Client::builder()
            .proxy(proxy.clone())
            .resolve_to_addrs(&target.host, &target.resolved_addrs)
            .build()
            .unwrap()
            .get(target.url.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(proxied_response.text().await.unwrap(), "proxy");
        proxy_task.await.unwrap();

        let direct_response =
            generated_image_client_with_builder(&target, reqwest::Client::builder().proxy(proxy))
                .unwrap()
                .get(target.url.clone())
                .send()
                .await
                .unwrap();

        assert_eq!(direct_response.text().await.unwrap(), "direct");
        direct_task.await.unwrap();
    }

    #[tokio::test]
    async fn generated_image_body_rejects_oversized_chunked_response() {
        let (response, release, server) =
            held_open_chunked_response(GENERATED_IMAGE_LIMIT_BYTES + 1).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_generated_image_body(response),
        )
        .await;
        finish_held_open_response(release, server).await;
        let error = result
            .expect("generated image reader waited for EOF after crossing its limit")
            .unwrap_err();

        assert!(error.to_string().contains("20 MiB size limit"));
    }

    #[tokio::test]
    async fn fal_success_body_rejects_oversized_chunked_response() {
        let (response, release, server) =
            held_open_chunked_response(FAL_RESPONSE_LIMIT_BYTES + 1).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_fal_success_body(response),
        )
        .await;
        finish_held_open_response(release, server).await;
        let error = result
            .expect("fal.ai success reader waited for EOF after crossing its limit")
            .unwrap_err();

        assert!(error.to_string().contains("1 MiB size limit"));
    }

    #[tokio::test]
    async fn fal_error_body_is_bounded_during_streaming() {
        let (response, release, server) =
            held_open_chunked_response(FAL_ERROR_LIMIT_BYTES + 1).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_fal_error_text(response),
        )
        .await;
        finish_held_open_response(release, server).await;
        let body = result
            .expect("fal.ai error reader waited for EOF after crossing its limit")
            .unwrap();

        assert_eq!(body.len(), FAL_ERROR_LIMIT_BYTES);
        assert!(body.bytes().all(|byte| byte == b'x'));
    }

    #[tokio::test]
    async fn fal_client_does_not_follow_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = zeroclaw_spawn::spawn!(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/unchecked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let response = ImageGenTool::http_client()
            .unwrap()
            .get(format!("http://{addr}/start"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.unwrap();
    }

    #[test]
    fn tool_name() {
        let tool = test_tool();
        assert_eq!(tool.name(), "image_gen");
    }

    #[test]
    fn codex_error_message_is_user_facing_no_internals() {
        let msg = super::codex_image_error_message("abc12345");
        assert!(msg.contains("Качественная генерация"));
        assert!(msg.contains("abc12345"));
        // no internal string / no fallback wording
        for bad in ["missing", "image_generation_call", "fal", "diagram"] {
            assert!(!msg.to_lowercase().contains(bad), "leaked: {bad}");
        }
    }

    #[test]
    fn tool_description_is_nonempty() {
        let tool = test_tool();
        assert!(!tool.description().is_empty());
        assert!(tool.description().contains("image"));
    }

    #[test]
    fn tool_schema_has_required_prompt() {
        let tool = test_tool();
        let schema = tool.parameters_schema();
        assert_eq!(schema["required"], json!(["prompt"]));
        assert!(schema["properties"]["prompt"].is_object());
    }

    #[test]
    fn tool_schema_has_optional_params() {
        let tool = test_tool();
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["filename"].is_object());
        assert!(schema["properties"]["size"].is_object());
        assert!(schema["properties"]["model"].is_object());
        assert!(schema["properties"]["quality"].is_object());
    }

    #[test]
    fn size_preset_maps_per_backend() {
        assert_eq!(
            builtin_size_map("image_size", "landscape"),
            "landscape_16_9"
        );
        assert_eq!(map_size_codex("landscape"), "1536x1024");
        assert_eq!(map_size_codex("auto"), "auto");
        assert_eq!(builtin_size_map("image_size", "square"), "square_hd");
    }

    #[test]
    fn builtin_size_map_covers_families_and_4_3() {
        assert_eq!(
            builtin_size_map("image_size", "landscape"),
            "landscape_16_9"
        );
        assert_eq!(builtin_size_map("image_size", "square"), "square_hd");
        assert_eq!(
            builtin_size_map("image_size", "landscape_4_3"),
            "landscape_4_3"
        );
        assert_eq!(builtin_size_map("aspect_ratio", "landscape"), "16:9");
        assert_eq!(builtin_size_map("aspect_ratio", "portrait"), "9:16");
        assert_eq!(builtin_size_map("aspect_ratio", "square"), "1:1");
        assert_eq!(builtin_size_map("aspect_ratio", "auto"), "1:1");
        assert_eq!(builtin_size_map("aspect_ratio", "landscape_4_3"), "4:3");
        assert_eq!(builtin_size_map("aspect_ratio", "portrait_4_3"), "3:4");
    }

    #[test]
    fn build_fal_body_default_is_flux_compatible() {
        let body = build_fal_body(
            "a cat",
            "square",
            "image_size",
            &Default::default(),
            &Default::default(),
        );
        assert_eq!(body["prompt"], "a cat");
        assert_eq!(body["num_images"], 1);
        assert_eq!(body["image_size"], "square_hd");
        assert!(body.get("aspect_ratio").is_none());
    }

    #[test]
    fn build_fal_body_grok_uses_aspect_ratio_and_extra() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("resolution".to_string(), serde_json::json!("1k"));
        extra.insert("output_format".to_string(), serde_json::json!("png"));
        let body = build_fal_body(
            "вывеска ОТКРЫТО",
            "landscape",
            "aspect_ratio",
            &Default::default(),
            &extra,
        );
        assert_eq!(body["aspect_ratio"], "16:9");
        assert_eq!(body["resolution"], "1k");
        assert_eq!(body["output_format"], "png");
        assert!(body.get("image_size").is_none());
    }

    #[test]
    fn build_fal_body_empty_size_param_omits_size() {
        let body = build_fal_body("x", "square", "", &Default::default(), &Default::default());
        assert!(body.get("image_size").is_none());
        assert!(body.get("aspect_ratio").is_none());
    }

    #[test]
    fn build_fal_body_reserved_keys_win() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("prompt".to_string(), serde_json::json!("HIJACK"));
        extra.insert("num_images".to_string(), serde_json::json!(9));
        extra.insert("aspect_ratio".to_string(), serde_json::json!("2:1"));
        let body = build_fal_body(
            "real",
            "landscape",
            "aspect_ratio",
            &Default::default(),
            &extra,
        );
        assert_eq!(body["prompt"], "real");
        assert_eq!(body["num_images"], 1);
        assert_eq!(body["aspect_ratio"], "16:9");
    }

    #[test]
    fn build_fal_body_size_param_as_reserved_is_ignored() {
        let body = build_fal_body(
            "real",
            "landscape",
            "prompt",
            &Default::default(),
            &Default::default(),
        );
        assert_eq!(body["prompt"], "real");
    }

    #[test]
    fn build_fal_body_partial_map_falls_back_to_builtin() {
        let mut map = std::collections::HashMap::new();
        map.insert("portrait".to_string(), "9:20".to_string());
        let body = build_fal_body("x", "landscape", "aspect_ratio", &map, &Default::default());
        assert_eq!(body["aspect_ratio"], "16:9");
    }

    #[test]
    fn description_has_no_hardcoded_default_model() {
        let t = test_tool();
        assert!(!t.description().to_lowercase().contains("flux-2/turbo"));
        let schema = t.parameters_schema();
        let model_desc = schema["properties"]["model"]["description"]
            .as_str()
            .unwrap_or("");
        assert!(!model_desc.contains("fal-ai/flux-2/turbo"));
    }

    #[test]
    fn resolve_backend_uses_quality_then_default() {
        assert_eq!(resolve_backend(Some("high"), "fast"), Backend::Codex);
        assert_eq!(resolve_backend(Some("fast"), "high"), Backend::Fal);
        assert_eq!(resolve_backend(None, "fast"), Backend::Fal);
        assert_eq!(resolve_backend(None, "high"), Backend::Codex);
    }

    #[test]
    fn resolve_backend_unknown_defaults_to_fal_safely() {
        assert_eq!(resolve_backend(None, "bogus"), Backend::Fal);
        assert_eq!(resolve_backend(Some("weird"), "high"), Backend::Fal);
    }

    #[test]
    fn schema_advertises_quality_param() {
        let s = test_tool().parameters_schema();
        assert!(s["properties"]["quality"].is_object());
    }

    #[test]
    fn tool_spec_roundtrip() {
        let tool = test_tool();
        let spec = tool.spec();
        assert_eq!(spec.name, "image_gen");
        assert!(spec.parameters.is_object());
    }

    #[tokio::test]
    async fn missing_prompt_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("prompt"));
    }

    #[tokio::test]
    async fn empty_prompt_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({"prompt": "   "})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("prompt"));
    }

    #[tokio::test]
    async fn missing_api_key_returns_error() {
        // Temporarily ensure the env var is unset.
        let original = std::env::var("FAL_API_KEY_TEST_IMAGE_GEN").ok();
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FAL_API_KEY_TEST_IMAGE_GEN") };

        let tool = ImageGenTool::new(
            test_security(),
            std::env::temp_dir(),
            "fal-ai/flux-2/turbo".into(),
            "FAL_API_KEY_TEST_IMAGE_GEN".into(),
            Vec::new(),
        )
        .unwrap();
        let result = tool
            .execute(json!({"prompt": "a sunset over the ocean"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("FAL_API_KEY_TEST_IMAGE_GEN")
        );

        // Restore if it was set.
        if let Some(val) = original {
            // SAFETY: test-only, single-threaded test runner.
            unsafe { std::env::set_var("FAL_API_KEY_TEST_IMAGE_GEN", val) };
        }
    }

    #[tokio::test]
    async fn invalid_size_returns_error() {
        // Set a dummy key so we get past the key check.
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::set_var("FAL_API_KEY_TEST_SIZE", "dummy_key") };

        let tool = ImageGenTool::new(
            test_security(),
            std::env::temp_dir(),
            "fal-ai/flux-2/turbo".into(),
            "FAL_API_KEY_TEST_SIZE".into(),
            Vec::new(),
        )
        .unwrap();
        let result = tool
            .execute(json!({"prompt": "test", "size": "invalid_size"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("Invalid size"));

        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FAL_API_KEY_TEST_SIZE") };
    }

    #[tokio::test]
    async fn read_only_autonomy_blocks_execution() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        });
        let tool = ImageGenTool::new(
            security,
            std::env::temp_dir(),
            "fal-ai/flux-2/turbo".into(),
            "FAL_API_KEY".into(),
            Vec::new(),
        )
        .unwrap();
        let result = tool.execute(json!({"prompt": "test image"})).await.unwrap();
        assert!(!result.success);
        let err = result.error.as_deref().unwrap();
        assert!(
            err.contains("read-only") || err.contains("image_gen"),
            "expected read-only or image_gen in error, got: {err}"
        );
    }

    #[tokio::test]
    async fn invalid_model_with_traversal_returns_error() {
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::set_var("FAL_API_KEY_TEST_MODEL", "dummy_key") };

        let tool = ImageGenTool::new(
            test_security(),
            std::env::temp_dir(),
            "fal-ai/flux-2/turbo".into(),
            "FAL_API_KEY_TEST_MODEL".into(),
            Vec::new(),
        )
        .unwrap();
        let result = tool
            .execute(json!({"prompt": "test", "model": "../../evil-endpoint"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("Invalid model identifier")
        );

        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FAL_API_KEY_TEST_MODEL") };
    }

    #[test]
    fn read_api_key_missing() {
        let result = ImageGenTool::read_api_key("DEFINITELY_NOT_SET_ZC_TEST_12345");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("DEFINITELY_NOT_SET_ZC_TEST_12345")
        );
    }

    #[test]
    fn filename_traversal_is_sanitized() {
        // Verify that path traversal in filenames is stripped to just the final component.
        let sanitized = PathBuf::from("../../etc/passwd").file_name().map_or_else(
            || "generated_image".to_string(),
            |n| n.to_string_lossy().to_string(),
        );
        assert_eq!(sanitized, "passwd");

        // ".." alone has no file_name, falls back to default.
        let sanitized = PathBuf::from("..").file_name().map_or_else(
            || "generated_image".to_string(),
            |n| n.to_string_lossy().to_string(),
        );
        assert_eq!(sanitized, "generated_image");
    }

    #[test]
    fn resolve_image_filename_default_is_non_clobbering_and_unique() {
        // Exercises the PRODUCTION filename-selection helper an omitted
        // filename must yield a unique timestamped name, never the bare
        // `generated_image` that would clobber prior generations, and two
        // default calls must differ. Fails if the code reverts to a fixed name.
        let a = resolve_image_filename(None, 1_000);
        let b = resolve_image_filename(None, 2_000);
        assert_eq!(a, "generated_image_1000");
        assert_ne!(
            a, "generated_image",
            "default must not clobber the bare name"
        );
        assert_ne!(a, b, "successive default names must differ");
        // An explicit filename is used verbatim, with path components stripped.
        assert_eq!(resolve_image_filename(Some("my_pic"), 1_000), "my_pic");
        assert_eq!(
            resolve_image_filename(Some("../../etc/passwd"), 1_000),
            "passwd"
        );
        // Blank/whitespace filename falls back to the timestamped default.
        assert_eq!(
            resolve_image_filename(Some("   "), 1_000),
            "generated_image_1000"
        );
    }

    #[test]
    fn image_output_emits_file_line_without_image_marker() {
        // Exercises the PRODUCTION output formatter: the saved path must appear
        // in the durable `File:` line, and the output must NOT carry a routable
        // `[IMAGE:<path>]` marker. A marker would make the multimodal pipeline
        // detour the turn into a vision provider mid-tool-loop, poisoning the
        // transcript (cross-provider tool_call_id / reasoning mismatch) and
        // breaking delivery. The agent delivers the file via the `File:` path.
        let path = "/ws/images/generated_image_42.png";
        let out = format_image_tool_output(path, 12, "fal-ai/flux", "a cat");
        assert!(
            out.contains(&format!("File: {path}")),
            "output must carry a durable File: line: {out}"
        );
        assert!(
            !out.contains("[IMAGE:"),
            "output must NOT carry a routable [IMAGE:<path>] marker: {out}"
        );
    }

    #[test]
    fn read_api_key_present() {
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::set_var("ZC_IMAGE_GEN_TEST_KEY", "test_value_123") };
        let result = ImageGenTool::read_api_key("ZC_IMAGE_GEN_TEST_KEY");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_value_123");
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("ZC_IMAGE_GEN_TEST_KEY") };
    }

    /// Wire-level proof that `generate_fal` actually POSTs the body
    /// `build_fal_body` assembles — not just that the pure function returns the
    /// right `serde_json::Value` in isolation. Configures the tool like the
    /// grok backend (`aspect_ratio` + extras) and captures the real HTTP
    /// request against a `wiremock` server (via the `fal_base_url` seam) to
    /// assert `aspect_ratio` (not `image_size`), the extras, and the
    /// `Authorization: Key <token>` header all land on the wire.
    #[tokio::test]
    async fn generate_fal_wire_body_carries_aspect_ratio_not_image_size() {
        use tempfile::TempDir;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        // Unique per-test env var — never touch the shared FAL_API_KEY.
        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::set_var("FAL_API_KEY_TEST_WIRE", "dummy_key_wire") };

        let tmp = TempDir::new().unwrap();
        let mock_server = MockServer::start().await;

        let mut extra = std::collections::HashMap::new();
        extra.insert("resolution".to_string(), serde_json::json!("1k"));
        extra.insert("output_format".to_string(), serde_json::json!("png"));

        let mut tool = ImageGenTool::new_with_persistence(
            test_security(),
            tmp.path().to_path_buf(),
            "xai/grok-imagine-image".into(),
            "FAL_API_KEY_TEST_WIRE".into(),
            true,
            "fast".into(),
            "gpt-5.5".into(),
            PathBuf::from("."),
            false,
            "aspect_ratio".into(),
            Default::default(),
            extra,
            Vec::new(),
        )
        .unwrap();
        tool.fal_base_url = mock_server.uri();

        let image_url = format!("{}/img.png", mock_server.uri());
        Mock::given(method("POST"))
            .and(path("/xai/grok-imagine-image"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "images": [{ "url": image_url }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = tool
            .execute(json!({
                "prompt": "вывеска ОТКРЫТО",
                "quality": "fast",
                "size": "landscape"
            }))
            .await
            .unwrap();

        // fork(#24): upstream v0.8.5 download guard rejects the plain-http mock image URL; the wire body is still asserted below.
        assert!(!result.success);
        assert!(
            result.error.as_deref().is_some_and(|e| e.contains("HTTPS")),
            "expected the HTTPS download guard, got: {:?}",
            result.error
        );

        let received = mock_server.received_requests().await.unwrap();
        let post_req: &Request = received
            .iter()
            .find(|r| r.url.path() == "/xai/grok-imagine-image")
            .expect("expected a POST to the fal model path");

        let body: serde_json::Value = post_req.body_json().unwrap();
        assert_eq!(body["aspect_ratio"], "16:9");
        assert!(body.get("image_size").is_none());
        assert_eq!(body["resolution"], "1k");
        assert_eq!(body["output_format"], "png");
        assert_eq!(body["prompt"], "вывеска ОТКРЫТО");

        let auth = post_req
            .headers
            .get("Authorization")
            .expect("Authorization header missing")
            .to_str()
            .unwrap();
        assert!(
            auth.starts_with("Key "),
            "unexpected Authorization header: {auth}"
        );

        // SAFETY: test-only, single-threaded test runner.
        unsafe { std::env::remove_var("FAL_API_KEY_TEST_WIRE") };
    }
}
