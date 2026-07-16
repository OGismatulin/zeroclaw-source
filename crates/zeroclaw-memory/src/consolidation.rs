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
use crate::dedup::{self, DedupAction};
use crate::importance;
use crate::merge;
use crate::policy::PolicyEnforcer;
use crate::policy_gate;
use crate::traits::{Memory, MemoryCategory, StoreOptions};
use zeroclaw_api::model_provider::ModelProvider;
use zeroclaw_config::schema::MemoryConfig;
use zeroclaw_providers::ProviderDispatch;

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
        regex::Regex::new(r"\[(?:IMAGE|DOCUMENT|FILE|VIDEO|VOICE|AUDIO):[^\]]*\]")
            .expect("media-tag regex must compile")
    });
    RE.replace_all(text, "[media attachment]").into_owned()
}

pub async fn consolidate_turn(
    model_provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    memory: &dyn Memory,
    memory_config: &MemoryConfig,
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

    let raw = ProviderDispatch::from_ref(model_provider)
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

        // Merge resolution: adopt the upstream v0.8.3 durable-seam write path
        // (policy write-gate + near-duplicate dedup) and carry fork patch #18
        // (LLM judge in place of the similarity-threshold conflict check).

        // A (upstream v0.8.3 durable seam): fail-closed policy write-gate on the
        // autonomous consolidation path.
        let policy = PolicyEnforcer::new(&memory_config.policy);
        if let Err(e) =
            policy_gate::validate_store(memory, &policy, "default", &MemoryCategory::Core).await
        {
            ::zeroclaw_log::record!(
                WARN,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Reject)
                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                    .with_attrs(::serde_json::json!({"error": e.to_string()})),
                "memory consolidation write denied by policy"
            );
            anyhow::bail!("memory consolidation write denied by policy: {e}");
        }

        // Recall the nearest Core candidates ONCE; shared by the upstream dedup
        // gate and the fork #18 judge. Tolerant of recall failure (fork
        // resilience): an empty set means "dedup inserts, judge supersedes
        // nothing", so a Core update is never dropped on a recall hiccup.
        let recalled = memory
            .recall(update, 10, None, None, None)
            .await
            .unwrap_or_default();

        // A (upstream v0.8.3 durable seam): write-time near-duplicate detection.
        // No-op unless `[memory].dedup_on_write` is enabled (default false).
        let dedup_candidates = dedup::core_candidates(recalled.clone());
        match dedup::dedup_gate(&dedup_candidates, update, memory_config) {
            DedupAction::Insert => {}
            DedupAction::Reject { dup_of } => {
                ::zeroclaw_log::record!(
                    DEBUG,
                    ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                        .with_attrs(::serde_json::json!({"duplicate_of": dup_of})),
                    "memory consolidation skipped duplicate core update"
                );
                return Ok(());
            }
            DedupAction::Merge { into } => {
                if let Some(survivor) = dedup_candidates.iter().find(|entry| entry.id == into) {
                    let merged = merge::merge_into_survivor(survivor, update);
                    let options = StoreOptions {
                        namespace: Some(survivor.namespace.clone()),
                        importance: merged.importance,
                        ..StoreOptions::default()
                    };
                    memory
                        .store_with_options(
                            &survivor.key,
                            &merged.content,
                            MemoryCategory::Core,
                            survivor.session_id.as_deref(),
                            options,
                        )
                        .await?;
                    return Ok(());
                }
            }
        }

        // Fork patch #18: replace the similarity-threshold conflict check
        // (`check_and_resolve_conflicts`) with an LLM judge. A hardcoded
        // threshold cannot cleanly separate "contradiction" from "mere
        // relatedness" (cos between "language is Python" and "language is Rust"
        // was only 0.78). Let the judge decide which pre-existing Core facts the
        // new fact makes outdated. `judge_conflicts` is best-effort and returns
        // empty on any provider/parse error (supersede nothing).
        let candidates: Vec<_> = recalled
            .into_iter()
            .filter(|c| {
                matches!(c.category, MemoryCategory::Core)
                    && c.key != mem_key
                    && c.content != *update
            })
            .collect();
        let superseded_ids =
            conflict::judge_conflicts(model_provider, model, temperature, update, &candidates)
                .await
                .unwrap_or_default();

        // Store with importance metadata.
        let options = StoreOptions {
            importance: Some(imp),
            ..StoreOptions::default()
        };
        memory
            .store_with_options(&mem_key, update, MemoryCategory::Core, None, options)
            .await?;

        // Retire the older conflicting facts (fork #18): recall filters
        // `superseded_by IS NULL`, so marking supersede is what actually
        // de-duplicates Core. The marker value is the new entry's key — only
        // NULL-ness gates recall (no FK/JOIN reads the value), and the new row's
        // internal id is not available here without an extra round-trip.
        // Gated by the upstream v0.8.3 `conflict_supersede_enabled` kill-switch
        // (default on): the judge is the detector, this flag is the operator
        // switch for whether its verdict is applied.
        if !superseded_ids.is_empty() && memory_config.conflict_supersede_enabled {
            // Observability (#18): record what the judge retired and why.
            let update_preview: String = update.chars().take(120).collect();
            let superseded_contents: Vec<String> = superseded_ids
                .iter()
                .filter_map(|id| {
                    candidates
                        .iter()
                        .find(|c| &c.id == id)
                        .map(|c| c.content.chars().take(120).collect::<String>())
                })
                .collect();
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({
                        "new_key": mem_key,
                        "new_content": update_preview,
                        "superseded_ids": superseded_ids,
                        "superseded_contents": superseded_contents,
                    })),
                "judge superseded Core facts"
            );

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

    /// Returns a canned reply chosen by inspecting the system prompt: the
    /// consolidation extraction prompt vs the Core-dedup judge prompt. The
    /// judge prompt is detected by its unique marker word ("устаревшими").
    /// `chat` keeps its trait default (unused here).
    struct StubProvider {
        extraction_reply: String,
        judge_reply: String,
    }

    #[async_trait]
    impl ModelProvider for StubProvider {
        async fn chat_with_system(
            &self,
            system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            let is_judge = system_prompt
                .map(|p| p.contains("устаревшими"))
                .unwrap_or(false);
            if is_judge {
                // Sentinel: pick the 1-based index of the candidate line that
                // mentions "Python", so the test is independent of recall order.
                if self.judge_reply == "AUTO_PYTHON" {
                    for line in _message.lines() {
                        if line.contains("Python")
                            && let Some((num, _)) = line.split_once('.')
                            && let Ok(n) = num.trim().parse::<i64>()
                        {
                            return Ok(format!("[{n}]"));
                        }
                    }
                    return Ok("[]".into());
                }
                Ok(self.judge_reply.clone())
            } else {
                Ok(self.extraction_reply.clone())
            }
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
            extraction_reply: r#"{"history_entry": "Обсудили деплой.", "memory_update": "Олег предпочитает деплой через CI."}"#.to_string(),
            judge_reply: "[]".into(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            &zeroclaw_config::schema::MemoryConfig::default(),
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
            extraction_reply:
                r#"{"history_entry": "Дежурное приветствие.", "memory_update": null}"#.to_string(),
            judge_reply: "[]".into(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            &zeroclaw_config::schema::MemoryConfig::default(),
            "Привет",
            "Привет!",
        )
        .await
        .unwrap();

        let daily = mem.list(Some(&MemoryCategory::Daily), None).await.unwrap();
        assert_eq!(daily.len(), 1);
        let core = mem.list(Some(&MemoryCategory::Core), None).await.unwrap();
        assert!(core.is_empty(), "no Core entry when memory_update is null");
    }

    /// Seed two Core facts; consolidation introduces a fact that genuinely
    /// contradicts one of them (language Python -> Rust). The judge targets the
    /// Python fact, which must drop out of recall, while the adjacent
    /// non-conflicting PHP fact and the new Rust fact survive.
    #[tokio::test]
    async fn consolidate_supersedes_real_contradiction() {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new("test", tmp.path()).unwrap();

        mem.store_with_metadata(
            "core_python",
            "Основной язык программирования пользователя — Python.",
            MemoryCategory::Core,
            None,
            None,
            Some(0.9),
        )
        .await
        .unwrap();
        mem.store_with_metadata(
            "core_php",
            "Пользователь пишет микросервисы на PHP.",
            MemoryCategory::Core,
            None,
            None,
            Some(0.7),
        )
        .await
        .unwrap();

        let provider = StubProvider {
            extraction_reply: r#"{"history_entry": "Сменил основной язык.", "memory_update": "Основной язык программирования пользователя — Rust."}"#.to_string(),
            judge_reply: "AUTO_PYTHON".into(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            &zeroclaw_config::schema::MemoryConfig::default(),
            "Теперь пишу на Rust",
            "Понял, основной язык — Rust.",
        )
        .await
        .unwrap();

        let recalled = mem
            .recall("основной язык программирования", 20, None, None, None)
            .await
            .unwrap();
        let contents: Vec<&str> = recalled.iter().map(|e| e.content.as_str()).collect();

        assert!(
            !contents.iter().any(|c| c.contains("Python")),
            "superseded Python fact must not surface in recall: {contents:?}"
        );
        assert!(
            contents.iter().any(|c| c.contains("Rust")),
            "new Rust fact must surface: {contents:?}"
        );

        // The adjacent PHP fact is on a different topic, so it only surfaces for
        // a PHP-matching query — assert it is still recallable (not superseded).
        let php = mem
            .recall("микросервисы PHP", 20, None, None, None)
            .await
            .unwrap();
        assert!(
            php.iter().any(|e| e.content.contains("PHP")),
            "adjacent non-conflicting PHP fact must be kept: {:?}",
            php.iter().map(|e| e.content.clone()).collect::<Vec<_>>()
        );
    }

    /// Same seed as the contradiction test, but the judge returns `[]` — nothing
    /// is superseded and both pre-existing Core facts remain recallable.
    #[tokio::test]
    async fn consolidate_keeps_adjacent_when_judge_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new("test", tmp.path()).unwrap();

        mem.store_with_metadata(
            "core_python",
            "Основной язык программирования пользователя — Python.",
            MemoryCategory::Core,
            None,
            None,
            Some(0.9),
        )
        .await
        .unwrap();
        mem.store_with_metadata(
            "core_php",
            "Пользователь пишет микросервисы на PHP.",
            MemoryCategory::Core,
            None,
            None,
            Some(0.7),
        )
        .await
        .unwrap();

        let provider = StubProvider {
            extraction_reply: r#"{"history_entry": "Сменил основной язык.", "memory_update": "Основной язык программирования пользователя — Rust."}"#.to_string(),
            judge_reply: "[]".into(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            &zeroclaw_config::schema::MemoryConfig::default(),
            "Теперь пишу на Rust",
            "Понял.",
        )
        .await
        .unwrap();

        let recalled = mem
            .recall("основной язык программирования", 20, None, None, None)
            .await
            .unwrap();
        let contents: Vec<&str> = recalled.iter().map(|e| e.content.as_str()).collect();

        assert!(
            contents.iter().any(|c| c.contains("Python")),
            "judge returned empty -> Python fact must remain: {contents:?}"
        );

        let php = mem
            .recall("микросервисы PHP", 20, None, None, None)
            .await
            .unwrap();
        assert!(
            php.iter().any(|e| e.content.contains("PHP")),
            "PHP fact must remain: {:?}",
            php.iter().map(|e| e.content.clone()).collect::<Vec<_>>()
        );
    }

    /// The judge returns non-JSON garbage. `judge_conflicts` must fall back to
    /// "supersede nothing" — no pre-existing Core fact is retired.
    #[tokio::test]
    async fn consolidate_safe_fallback_on_judge_garbage() {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new("test", tmp.path()).unwrap();

        mem.store_with_metadata(
            "core_python",
            "Основной язык программирования пользователя — Python.",
            MemoryCategory::Core,
            None,
            None,
            Some(0.9),
        )
        .await
        .unwrap();

        let provider = StubProvider {
            extraction_reply: r#"{"history_entry": "Сменил язык.", "memory_update": "Основной язык программирования пользователя — Rust."}"#.to_string(),
            judge_reply: "не json".into(),
        };

        consolidate_turn(
            &provider,
            "test-model",
            None,
            &mem,
            &zeroclaw_config::schema::MemoryConfig::default(),
            "Теперь пишу на Rust",
            "Понял.",
        )
        .await
        .unwrap();

        let recalled = mem
            .recall("основной язык программирования", 20, None, None, None)
            .await
            .unwrap();
        let contents: Vec<&str> = recalled.iter().map(|e| e.content.as_str()).collect();

        assert!(
            contents.iter().any(|c| c.contains("Python")),
            "garbage judge reply -> safe fallback, Python fact must remain: {contents:?}"
        );
    }
}
