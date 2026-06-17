//! LLM-driven memory consolidation.
//!
//! After each conversation turn, extracts structured information:
//! - `history_entry`: A timestamped summary for the daily conversation log.
//! - `memory_update`: New facts, preferences, or decisions worth remembering
//!   long-term (or `null` if nothing new was learned).
//!
//! This two-phase approach replaces the naive raw-message auto-save with
//! semantic extraction, similar to Nanobot's `save_memory` tool call pattern.

use crate::conflict;
use crate::importance;
use crate::traits::{Memory, MemoryCategory};
use zeroclaw_api::model_provider::ModelProvider;

/// Output of consolidation extraction.
#[derive(Debug, serde::Deserialize)]
pub struct ConsolidationResult {
    /// Brief timestamped summary for the conversation history log.
    pub history_entry: String,
    /// New facts/preferences/decisions to store long-term, or None.
    pub memory_update: Option<String>,
    /// Atomic facts extracted from the turn (when consolidation_extract_facts is enabled).
    #[serde(default)]
    pub facts: Vec<String>,
    /// Observed trend or pattern (when consolidation_extract_facts is enabled).
    #[serde(default)]
    pub trend: Option<String>,
}

// Fork patch: prompt rewritten so extracted facts come back in the
// conversation's language (this deployment is Russian-centric). EN facts in a
// RU context surface in `[Memory context]` of RU turns and degrade recall
// (EN-fact ↔ RU-query embedding similarity is lower).
const CONSOLIDATION_SYSTEM_PROMPT: &str = r#"Ты — движок консолидации памяти. По одному ходу диалога извлеки:
1. "history_entry": краткое summary того, что произошло в этом ходе (1–2 предложения). Укажи ключевую тему или действие.
2. "memory_update": любые НОВЫЕ факты, предпочтения, решения или обязательства, которые стоит запомнить надолго. Верни null, если ничего нового не узнал.

Пиши history_entry и memory_update на ТОМ ЖЕ ЯЗЫКЕ, на котором идёт диалог (обычно русский).
Ответь ТОЛЬКО валидным JSON: {"history_entry": "...", "memory_update": "..." или null}
Не добавляй никакого текста вне JSON-объекта."#;

/// Run two-phase LLM-driven consolidation on a conversation turn.
///
/// Phase 1: Write a history entry to the Daily memory category.
/// Phase 2: Write a memory update to the Core category (if the LLM identified new facts).
///
/// This function is designed to be called fire-and-forget via `zeroclaw_spawn::spawn!`.
/// Strip channel media markers (e.g. `[IMAGE:/local/path]`, `[DOCUMENT:...]`)
/// that contain local filesystem paths.  These must never be forwarded to
/// upstream model_provider APIs — they would leak local paths and cause API errors.
fn strip_media_markers(text: &str) -> String {
    // Matches [IMAGE:...], [DOCUMENT:...], [FILE:...], [VIDEO:...], [VOICE:...], [AUDIO:...]
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\[(?:IMAGE|DOCUMENT|FILE|VIDEO|VOICE|AUDIO):[^\]]*\]").unwrap()
    });
    RE.replace_all(text, "[media attachment]").into_owned()
}

pub async fn consolidate_turn(
    model_provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    memory: &dyn Memory,
    user_message: &str,
    assistant_response: &str,
) -> anyhow::Result<()> {
    let turn_text = format!(
        "User: {}\nAssistant: {}",
        strip_media_markers(user_message),
        strip_media_markers(assistant_response),
    );

    // Truncate very long turns to avoid wasting tokens on consolidation.
    // Use char-boundary-safe slicing to prevent panic on multi-byte UTF-8 (e.g. CJK text).
    let truncated = if turn_text.len() > 4000 {
        let end = turn_text
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 4000)
            .last()
            .unwrap_or(0);
        format!("{}…", &turn_text[..end])
    } else {
        turn_text.clone()
    };

    let raw = model_provider
        .chat_with_system(
            Some(CONSOLIDATION_SYSTEM_PROMPT),
            &truncated,
            model,
            temperature,
        )
        .await?;

    let result: ConsolidationResult = parse_consolidation_response(&raw, &turn_text);

    // Phase 1: Write history entry to Daily category.
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    let history_key = format!("daily_{date}_{}", uuid::Uuid::new_v4());
    memory
        .store(
            &history_key,
            &result.history_entry,
            MemoryCategory::Daily,
            None,
        )
        .await?;

    // Phase 2: Write memory update to Core category (if present).
    if let Some(ref update) = result.memory_update
        && !update.trim().is_empty()
    {
        let mem_key = format!("core_{}", uuid::Uuid::new_v4());

        // Compute importance score heuristically.
        let imp = importance::compute_importance(update, &MemoryCategory::Core);

        // Detect conflicting Core memories BEFORE storing the new entry, so the
        // new entry itself is never a candidate for being superseded.
        //
        // Fork patch: upstream discards this Vec (only `Err` is handled) and
        // never calls `mark_superseded`, so conflict detection was a no-op —
        // stale Core facts were never retired and recall surfaced both old and
        // new. We capture the ids and mark them superseded after the store.
        let superseded_ids = match conflict::check_and_resolve_conflicts(
            memory,
            &mem_key,
            update,
            &MemoryCategory::Core,
            0.85,
        )
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                ::zeroclaw_log::record!(
                    DEBUG,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_attrs(::serde_json::json!({"error": format!("{}", e)})),
                    "conflict check skipped"
                );
                Vec::new()
            }
        };

        // Store with importance metadata.
        memory
            .store_with_metadata(
                &mem_key,
                update,
                MemoryCategory::Core,
                None,
                None,
                Some(imp),
            )
            .await?;

        // Retire the older conflicting facts: recall filters
        // `superseded_by IS NULL`, so this is what actually de-duplicates Core.
        // The marker value is the new entry's key — only NULL-ness gates recall
        // (no FK/JOIN reads the value), and the new row's internal id is not
        // available here without an extra round-trip.
        if !superseded_ids.is_empty() {
            let refs: Vec<&str> = superseded_ids.iter().map(|s| s.as_str()).collect();
            if let Err(e) = memory.mark_superseded(&refs, &mem_key).await {
                ::zeroclaw_log::record!(
                    DEBUG,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_attrs(::serde_json::json!({"error": format!("{}", e)})),
                    "mark_superseded skipped"
                );
            }
        }
    }

    Ok(())
}

/// Parse the LLM's consolidation response, with fallback for malformed JSON.
fn parse_consolidation_response(raw: &str, fallback_text: &str) -> ConsolidationResult {
    // Try to extract JSON from the response (LLM may wrap in markdown code blocks).
    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    serde_json::from_str(cleaned).unwrap_or_else(|_| {
        // Fallback: use truncated turn text as history entry.
        // Use char-boundary-safe slicing to prevent panic on multi-byte UTF-8.
        let summary = if fallback_text.len() > 200 {
            let end = fallback_text
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= 200)
                .last()
                .unwrap_or(0);
            format!("{}…", &fallback_text[..end])
        } else {
            fallback_text.to_string()
        };
        ConsolidationResult {
            history_entry: summary,
            memory_update: None,
            facts: Vec::new(),
            trend: None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_json_response() {
        let raw = r#"{"history_entry": "User asked about Rust.", "memory_update": "User prefers Rust over Go."}"#;
        let result = parse_consolidation_response(raw, "fallback");
        assert_eq!(result.history_entry, "User asked about Rust.");
        assert_eq!(
            result.memory_update.as_deref(),
            Some("User prefers Rust over Go.")
        );
    }

    #[test]
    fn parse_json_with_null_memory() {
        let raw = r#"{"history_entry": "Routine greeting.", "memory_update": null}"#;
        let result = parse_consolidation_response(raw, "fallback");
        assert_eq!(result.history_entry, "Routine greeting.");
        assert!(result.memory_update.is_none());
    }

    #[test]
    fn parse_json_wrapped_in_code_block() {
        let raw =
            "```json\n{\"history_entry\": \"Discussed deployment.\", \"memory_update\": null}\n```";
        let result = parse_consolidation_response(raw, "fallback");
        assert_eq!(result.history_entry, "Discussed deployment.");
    }

    #[test]
    fn fallback_on_malformed_response() {
        let raw = "I'm sorry, I can't do that.";
        let result = parse_consolidation_response(raw, "User: hello\nAssistant: hi");
        assert_eq!(result.history_entry, "User: hello\nAssistant: hi");
        assert!(result.memory_update.is_none());
    }

    #[test]
    fn fallback_truncates_long_text() {
        let long_text = "x".repeat(500);
        let result = parse_consolidation_response("invalid", &long_text);
        // 200 bytes + "…" (3 bytes in UTF-8) = 203
        assert!(result.history_entry.len() <= 203);
    }

    #[test]
    fn fallback_truncates_cjk_text_without_panic() {
        // Each CJK character is 3 bytes in UTF-8; byte index 200 may land
        // inside a character. This must not panic.
        let cjk_text = "二手书项目".repeat(50); // 250 chars = 750 bytes
        let result = parse_consolidation_response("invalid", &cjk_text);
        assert!(
            result
                .history_entry
                .is_char_boundary(result.history_entry.len())
        );
        assert!(result.history_entry.ends_with('…'));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::sqlite::SqliteMemory;
    use async_trait::async_trait;
    use tempfile::TempDir;
    use zeroclaw_api::model_provider::ModelProvider;

    /// Returns a fixed JSON reply. `chat` keeps its trait default (unused here).
    struct StubProvider {
        reply: String,
    }

    #[async_trait]
    impl ModelProvider for StubProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(self.reply.clone())
        }
    }

    impl zeroclaw_api::attribution::Attributable for StubProvider {
        fn role(&self) -> zeroclaw_api::attribution::Role {
            zeroclaw_api::attribution::Role::Provider(
                zeroclaw_api::attribution::ProviderKind::Model(
                    zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "StubProvider"
        }
    }

    #[tokio::test]
    async fn consolidate_turn_writes_daily_and_core() {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new("test", tmp.path()).unwrap();
        let provider = StubProvider {
            reply: r#"{"history_entry": "Обсудили деплой.", "memory_update": "Олег предпочитает деплой через CI."}"#.to_string(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            "Как деплоить?",
            "Через CI.",
        )
        .await
        .unwrap();

        let daily = mem.list(Some(&MemoryCategory::Daily), None).await.unwrap();
        assert_eq!(daily.len(), 1, "one Daily history_entry");
        assert_eq!(daily[0].content, "Обсудили деплой.");

        let core = mem.list(Some(&MemoryCategory::Core), None).await.unwrap();
        assert_eq!(core.len(), 1, "one Core memory_update");
        assert!(core[0].content.contains("CI"));
    }

    #[tokio::test]
    async fn consolidate_turn_null_update_writes_only_daily() {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new("test", tmp.path()).unwrap();
        let provider = StubProvider {
            reply: r#"{"history_entry": "Дежурное приветствие.", "memory_update": null}"#
                .to_string(),
        };

        consolidate_turn(&provider, "test-model", None, &mem, "Привет", "Привет!")
            .await
            .unwrap();

        let daily = mem.list(Some(&MemoryCategory::Daily), None).await.unwrap();
        assert_eq!(daily.len(), 1);
        let core = mem.list(Some(&MemoryCategory::Core), None).await.unwrap();
        assert!(core.is_empty(), "no Core entry when memory_update is null");
    }
}
