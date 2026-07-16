//! Conflict resolution for memory entries.
//!
//! On the consolidation path (#18), `judge_conflicts` asks an LLM which existing
//! Core facts a new fact makes obsolete (direct contradiction / same-attribute
//! replacement), then those are marked superseded. This replaced the older
//! similarity-threshold check (`check_and_resolve_conflicts`, retained below for
//! any other/no callers) — a measurement showed cosine similarity cannot cleanly
//! separate contradiction from mere relatedness.

use super::traits::{Memory, MemoryCategory, MemoryEntry};
use zeroclaw_api::model_provider::ModelProvider;

/// System prompt for the Core-dedup LLM judge (#18).
///
/// Conservative on purpose: a measurement showed cosine similarity cannot
/// cleanly separate "contradiction" from "mere relatedness" (cos between
/// "language is Python" and "language is Rust" was only 0.78). The judge is
/// asked to mark ONLY facts whose attribute value the new fact replaces.
///
/// The marker word "устаревшими" is what the test stub matches on to detect
/// the judge prompt — keep it present.
const JUDGE_SYSTEM_PROMPT: &str = r#"Ты — строгий арбитр памяти. Тебе дают НОВЫЙ факт о пользователе и пронумерованный список СУЩЕСТВУЮЩИХ фактов.

Определи, какие из существующих фактов новый факт делает устаревшими — то есть прямо противоречит им или заменяет значение того же самого атрибута (например, сменился основной язык программирования, город, должность, имя, предпочтение).

ПРАВИЛА:
- Помечай факт только если новый факт ЗАМЕНЯЕТ значение того же атрибута или прямо ему противоречит.
- НЕ помечай факты, которые просто связаны по теме, дополняют новый факт или относятся к другому атрибуту.
- Если ни один факт не устарел — верни пустой массив.

Ответь СТРОГО JSON-массивом номеров устаревших фактов, например: [2]
Если устаревших нет: []
Не добавляй никакого текста вне JSON-массива."#;

/// Ask an LLM which existing Core facts the new fact makes outdated (#18).
///
/// Returns the `id`s of `candidates` the judge marks as superseded. This is a
/// safe, best-effort operation: any provider error or unparseable reply yields
/// an empty Vec (supersede nothing) — it never propagates an error, never
/// panics, and never supersedes on doubt.
pub async fn judge_conflicts(
    provider: &dyn ModelProvider,
    model: &str,
    temperature: Option<f64>,
    new_content: &str,
    candidates: &[MemoryEntry],
) -> anyhow::Result<Vec<String>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // Build a 1-based numbered list of existing facts.
    let mut list = String::new();
    for (i, c) in candidates.iter().enumerate() {
        list.push_str(&format!("{}. {}\n", i + 1, c.content));
    }
    let msg = format!(
        "НОВЫЙ факт:\n{new_content}\n\nСУЩЕСТВУЮЩИЕ факты:\n{list}\nКакие существующие факты устарели?"
    );

    let raw = match provider
        .chat_with_system(Some(JUDGE_SYSTEM_PROMPT), &msg, model, temperature)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            ::zeroclaw_log::record!(
                DEBUG,
                ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Note)
                    .with_attrs(::serde_json::json!({"error": format!("{}", e)})),
                "judge_conflicts provider call failed; superseding nothing"
            );
            return Ok(Vec::new());
        }
    };

    // Tolerant parse: slice from the first `[` to the LAST `]` (widest span,
    // tolerates surrounding prose) and parse as Vec<i64>. Not a balanced-bracket
    // parser: a nested array in that span fails to parse and yields []. Any
    // failure is safe here — it means "supersede nothing".
    let indices: Vec<i64> = match (raw.find('['), raw.rfind(']')) {
        (Some(start), Some(end)) if end > start => {
            serde_json::from_str::<Vec<i64>>(&raw[start..=end]).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    // Map valid 1-based indices in range to candidate ids.
    let mut superseded = Vec::new();
    for n in indices {
        if n >= 1 && (n as usize) <= candidates.len() {
            superseded.push(candidates[(n as usize) - 1].id.clone());
        }
    }

    Ok(superseded)
}

/// Check for conflicting memories and mark old ones as superseded.
///
/// Returns the list of entry IDs that were superseded.
// NOTE: superseded by judge_conflicts on the consolidation path (#18); retained for any other/no callers.
pub async fn check_and_resolve_conflicts(
    memory: &dyn Memory,
    key: &str,
    content: &str,
    category: &MemoryCategory,
    threshold: f64,
) -> anyhow::Result<Vec<String>> {
    // Only check conflicts for Core memories
    if !matches!(category, MemoryCategory::Core) {
        return Ok(Vec::new());
    }

    // Search for similar existing entries
    let candidates = memory.recall(content, 10, None, None, None).await?;

    let mut superseded = Vec::new();
    for candidate in &candidates {
        if candidate.key == key {
            continue; // Same key = update, not conflict
        }
        if !matches!(candidate.category, MemoryCategory::Core) {
            continue;
        }
        if let Some(score) = candidate.score
            && score > threshold
            && candidate.content != content
        {
            superseded.push(candidate.id.clone());
        }
    }

    Ok(superseded)
}

/// Mark entries as superseded in SQLite by setting their `superseded_by` column.
pub fn mark_superseded(
    conn: &rusqlite::Connection,
    superseded_ids: &[String],
    new_id: &str,
) -> anyhow::Result<()> {
    if superseded_ids.is_empty() {
        return Ok(());
    }

    for id in superseded_ids {
        conn.execute(
            "UPDATE memories SET superseded_by = ?1 WHERE id = ?2",
            rusqlite::params![new_id, id],
        )?;
    }

    Ok(())
}

/// Simple text-based conflict detection without embeddings.
///
/// Uses token overlap (Jaccard similarity) as a fast approximation
/// when vector embeddings are unavailable.
pub fn jaccard_similarity(a: &str, b: &str) -> f64 {
    let words_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let words_b: std::collections::HashSet<&str> = b.split_whitespace().collect();

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }
    if words_a.is_empty() || words_b.is_empty() {
        return 0.0;
    }

    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Find potentially conflicting entries using text similarity when embeddings
/// are not available. Returns entries above the threshold.
pub fn find_text_conflicts(
    entries: &[MemoryEntry],
    new_content: &str,
    threshold: f64,
) -> Vec<String> {
    entries
        .iter()
        .filter(|e| {
            matches!(e.category, MemoryCategory::Core)
                && e.superseded_by.is_none()
                && jaccard_similarity(&e.content, new_content) > threshold
                && e.content != new_content
        })
        .map(|e| e.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_entry(id: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            key: id.into(),
            content: content.into(),
            category: MemoryCategory::Core,
            timestamp: "now".into(),
            session_id: None,
            score: None,
            namespace: "default".into(),
            importance: Some(0.7),
            superseded_by: None,
            kind: None,
            pinned: false,
            tenant_id: None,
            agent_alias: None,
            agent_id: None,
        }
    }

    /// Returns a fixed judge reply for any chat_with_system call.
    struct JudgeStub {
        reply: String,
    }

    #[async_trait::async_trait]
    impl ModelProvider for JudgeStub {
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

    impl zeroclaw_api::attribution::Attributable for JudgeStub {
        fn role(&self) -> zeroclaw_api::attribution::Role {
            zeroclaw_api::attribution::Role::Provider(
                zeroclaw_api::attribution::ProviderKind::Model(
                    zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "JudgeStub"
        }
    }

    #[tokio::test]
    async fn judge_conflicts_empty_candidates_short_circuits() {
        let provider = JudgeStub {
            reply: "[1]".into(),
        };
        let ids = judge_conflicts(&provider, "m", None, "new fact", &[])
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn judge_conflicts_maps_index_to_id() {
        let provider = JudgeStub {
            reply: "[1]".into(),
        };
        let candidates = vec![core_entry("a", "lang Python"), core_entry("b", "city NYC")];
        let ids = judge_conflicts(&provider, "m", None, "lang Rust", &candidates)
            .await
            .unwrap();
        assert_eq!(ids, vec!["a".to_string()]);
    }

    #[tokio::test]
    async fn judge_conflicts_empty_array_supersedes_nothing() {
        let provider = JudgeStub { reply: "[]".into() };
        let candidates = vec![core_entry("a", "lang Python")];
        let ids = judge_conflicts(&provider, "m", None, "lang Rust", &candidates)
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn judge_conflicts_garbage_reply_supersedes_nothing() {
        let provider = JudgeStub {
            reply: "не json вовсе".into(),
        };
        let candidates = vec![core_entry("a", "lang Python")];
        let ids = judge_conflicts(&provider, "m", None, "lang Rust", &candidates)
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn judge_conflicts_out_of_range_index_ignored() {
        let provider = JudgeStub {
            reply: "[5, 1]".into(),
        };
        let candidates = vec![core_entry("a", "lang Python")];
        let ids = judge_conflicts(&provider, "m", None, "lang Rust", &candidates)
            .await
            .unwrap();
        assert_eq!(ids, vec!["a".to_string()]);
    }

    #[test]
    fn jaccard_identical_strings() {
        let sim = jaccard_similarity("hello world", "hello world");
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_disjoint_strings() {
        let sim = jaccard_similarity("hello world", "foo bar");
        assert!(sim.abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_partial_overlap() {
        let sim = jaccard_similarity("the quick brown fox", "the slow brown dog");
        // overlap: "the", "brown" = 2; union: "the", "quick", "brown", "fox", "slow", "dog" = 6
        assert!((sim - 2.0 / 6.0).abs() < 0.01);
    }

    #[test]
    fn jaccard_empty_strings() {
        assert!((jaccard_similarity("", "") - 1.0).abs() < f64::EPSILON);
        assert!(jaccard_similarity("hello", "").abs() < f64::EPSILON);
        assert!(jaccard_similarity("", "hello").abs() < f64::EPSILON);
    }

    #[test]
    fn find_text_conflicts_filters_correctly() {
        let entries = vec![
            MemoryEntry {
                id: "1".into(),
                key: "pref".into(),
                content: "User prefers Rust for systems work".into(),
                category: MemoryCategory::Core,
                timestamp: "now".into(),
                session_id: None,
                score: None,
                namespace: "default".into(),
                importance: Some(0.7),
                superseded_by: None,
                kind: None,
                pinned: false,
                tenant_id: None,
                agent_alias: None,
                agent_id: None,
            },
            MemoryEntry {
                id: "2".into(),
                key: "daily1".into(),
                content: "User prefers Rust for systems work".into(),
                category: MemoryCategory::Daily,
                timestamp: "now".into(),
                session_id: None,
                score: None,
                namespace: "default".into(),
                importance: Some(0.3),
                superseded_by: None,
                kind: None,
                pinned: false,
                tenant_id: None,
                agent_alias: None,
                agent_id: None,
            },
        ];

        // Only Core entries should be flagged
        let conflicts = find_text_conflicts(&entries, "User now prefers Go for systems work", 0.3);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], "1");
    }

    #[test]
    fn jaccard_deduplicates_repeated_words() {
        // Token sets ignore repeats: {a, b} vs {a, b} are identical.
        assert!((jaccard_similarity("a a b", "a b b") - 1.0).abs() < f64::EPSILON);
        // {a, b} vs {a} -> intersection 1 / union 2.
        assert!((jaccard_similarity("a a b", "a") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn find_text_conflicts_skips_superseded_and_identical() {
        let entry = |id: &str, content: &str, superseded: Option<String>| MemoryEntry {
            id: id.into(),
            key: "k".into(),
            content: content.into(),
            category: MemoryCategory::Core,
            timestamp: "now".into(),
            session_id: None,
            score: None,
            namespace: "default".into(),
            importance: Some(0.7),
            superseded_by: superseded,
            kind: None,
            pinned: false,
            tenant_id: None,
            agent_alias: None,
            agent_id: None,
        };
        let entries = vec![
            entry("active", "User prefers Rust for systems work", None),
            entry(
                "old",
                "User prefers Rust for systems work",
                Some("x".into()),
            ),
        ];

        // The already-superseded "old" entry is skipped; only "active" conflicts.
        let conflicts = find_text_conflicts(&entries, "User now prefers Go for systems work", 0.3);
        assert_eq!(conflicts, vec!["active".to_string()]);

        // An identical new_content is an update, not a conflict.
        let none = find_text_conflicts(&entries, "User prefers Rust for systems work", 0.3);
        assert!(none.is_empty());
    }
}
