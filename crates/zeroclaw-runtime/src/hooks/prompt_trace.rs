use std::path::PathBuf;

use async_trait::async_trait;
use zeroclaw_api::model_provider::{ChatMessage, ChatResponse};

use super::traits::HookHandler;

/// Writes the exact LLM input/output to a per-user JSONL trace file.
///
/// Enabled via `ZEROCLAW_PROMPT_TRACE`; raw (no scrub). Panic-safe: every
/// IO/serialize error is swallowed so a trace failure never aborts a turn.
pub struct PromptTraceHook {
    /// `<workspace_dir>/logs/prompt-trace.jsonl`
    path: PathBuf,
    max_bytes: u64,
}

impl PromptTraceHook {
    pub fn new(workspace_dir: PathBuf, max_bytes: u64) -> Self {
        let path = workspace_dir.join("logs").join("prompt-trace.jsonl");
        Self { path, max_bytes }
    }

    fn now_rfc3339() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    /// Rotate keeping 3 backups (.1 -> .2 -> .3) when file >= max_bytes.
    /// Best-effort: ignores all errors.
    fn rotate_if_needed(&self) {
        let too_big = std::fs::metadata(&self.path)
            .map(|m| m.len() >= self.max_bytes)
            .unwrap_or(false);
        if !too_big {
            return;
        }
        let p = |n: u32| self.path.with_extension(format!("jsonl.{n}"));
        let _ = std::fs::rename(p(2), p(3));
        let _ = std::fs::rename(p(1), p(2));
        let _ = std::fs::rename(&self.path, p(1));
    }

    fn append_line(&self, value: &serde_json::Value) {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        self.rotate_if_needed();
        let line = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[async_trait]
impl HookHandler for PromptTraceHook {
    fn name(&self) -> &str {
        "prompt_trace"
    }

    async fn on_llm_input(&self, messages: &[ChatMessage], model: &str) {
        // messages == &prepared_messages.messages, model == active_model (set by caller).
        let msgs = match serde_json::to_value(messages) {
            Ok(v) => v,
            Err(_) => return,
        };
        let line = serde_json::json!({
            "kind": "input",
            "ts": Self::now_rfc3339(),
            "model": model,
            "messages_count": messages.len(),
            "messages": msgs,
        });
        self.append_line(&line);
    }

    async fn on_llm_output(&self, response: &ChatResponse) {
        // ChatResponse/TokenUsage have NO Serialize derive — build JSON manually.
        // `response` is borrowed and the fields are not Copy, so clone what we keep.
        let line = serde_json::json!({
            "kind": "output",
            "ts": Self::now_rfc3339(),
            "response": {
                "text": response.text.clone(),
                "tool_calls": response.tool_calls.clone(),
                "reasoning_content": response.reasoning_content.clone(),
                "usage": response.usage.as_ref().map(|u| serde_json::json!({
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                    "cached_input_tokens": u.cached_input_tokens,
                })),
            },
        });
        self.append_line(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_input_line_as_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let hook = PromptTraceHook::new(dir.path().to_path_buf(), 50 * 1024 * 1024);
        let msgs = vec![ChatMessage::system("SYS"), ChatMessage::user("hello")];
        hook.on_llm_input(&msgs, "deepseek-v4-flash").await;

        let path = dir.path().join("logs").join("prompt-trace.jsonl");
        let body = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], "input");
        assert_eq!(v["model"], "deepseek-v4-flash");
        assert_eq!(v["messages_count"], 2);
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][1]["content"], "hello");
    }

    #[tokio::test]
    async fn writes_output_line_without_model_field() {
        let dir = tempfile::tempdir().unwrap();
        let hook = PromptTraceHook::new(dir.path().to_path_buf(), 50 * 1024 * 1024);
        let resp = ChatResponse {
            text: Some("hi".into()),
            tool_calls: vec![],
            usage: None,
            reasoning_content: None,
        };
        hook.on_llm_output(&resp).await;
        let body = std::fs::read_to_string(dir.path().join("logs/prompt-trace.jsonl")).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().last().unwrap()).unwrap();
        assert_eq!(v["kind"], "output");
        assert!(v.get("model").is_none());
        assert_eq!(v["response"]["text"], "hi");
    }

    #[tokio::test]
    async fn output_serializes_usage_when_present() {
        use zeroclaw_api::model_provider::TokenUsage;
        let dir = tempfile::tempdir().unwrap();
        let hook = PromptTraceHook::new(dir.path().to_path_buf(), 50 * 1024 * 1024);
        let resp = ChatResponse {
            text: None,
            tool_calls: vec![],
            usage: Some(TokenUsage {
                input_tokens: Some(123),
                output_tokens: Some(45),
                cached_input_tokens: Some(7),
            }),
            reasoning_content: None,
        };
        hook.on_llm_output(&resp).await;
        let body = std::fs::read_to_string(dir.path().join("logs/prompt-trace.jsonl")).unwrap();
        let v: serde_json::Value = serde_json::from_str(body.lines().last().unwrap()).unwrap();
        assert_eq!(v["response"]["usage"]["input_tokens"], 123);
        assert_eq!(v["response"]["usage"]["output_tokens"], 45);
        assert_eq!(v["response"]["usage"]["cached_input_tokens"], 7);
    }

    #[tokio::test]
    async fn rotates_at_threshold_keeping_three_backups() {
        let dir = tempfile::tempdir().unwrap();
        // 1 byte threshold => every write after the first triggers a rotation.
        let hook = PromptTraceHook::new(dir.path().to_path_buf(), 1);
        let msgs = vec![ChatMessage::user("x")];
        for _ in 0..3 {
            hook.on_llm_input(&msgs, "m").await;
        }
        assert!(dir.path().join("logs/prompt-trace.jsonl.1").exists());
    }

    #[tokio::test]
    async fn never_panics_when_dir_unwritable() {
        // A file where the parent dir should be => create_dir_all/open fail,
        // but the hook must return cleanly without panicking.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let hook = PromptTraceHook::new(blocker, 50 * 1024 * 1024);
        hook.on_llm_input(&[ChatMessage::user("x")], "m").await;
    }
}
