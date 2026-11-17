struct LargeOutputTestTool {
    payload_bytes: usize,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    advance_virtual_time: Option<Duration>,
}

zeroclaw_api::mock_tool_attribution!(LargeOutputTestTool);

#[async_trait]
impl Tool for LargeOutputTestTool {
    fn name(&self) -> &str {
        "echo_tool"
    }
    fn description(&self) -> &str {
        "Test tool returning configurable payload and optional virtual delay"
    }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "step": { "type": "integer" } },
            "required": ["step"]
        })
    }
    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if let Some(delay) = self.advance_virtual_time {
            tokio::time::sleep(delay).await;
        }
        let step = args.get("step").and_then(|v| v.as_u64()).unwrap_or(n as u64);
        let body = format!(
            "step={step} marker=FACT_{step} {}",
            "x".repeat(self.payload_bytes)
        );
        Ok(ToolResult {
            success: true,
            output: body.into(),
            error: None,
        })
    }
}

#[derive(Clone)]
struct CapturedChatRequest {
    messages: Vec<zeroclaw_providers::ChatMessage>,
    tools_len: Option<usize>,
}

struct CapturingCompactionModelProvider {
    requests: Arc<std::sync::Mutex<Vec<CapturedChatRequest>>>,
    reported_tokens_per_call: Arc<dyn Fn(usize) -> Option<u64> + Send + Sync>,
    tool_rounds: usize,
    emit_structured_final: bool,
}

impl ::zeroclaw_api::attribution::Attributable for CapturingCompactionModelProvider {
    fn role(&self) -> ::zeroclaw_api::attribution::Role {
        ::zeroclaw_api::attribution::Role::Provider(
            ::zeroclaw_api::attribution::ProviderKind::Model(
                ::zeroclaw_api::attribution::ModelProviderKind::Custom,
            ),
        )
    }
    fn alias(&self) -> &str {
        "CapturingCompactionModelProvider"
    }
}

#[async_trait]
impl ModelProvider for CapturingCompactionModelProvider {
    fn capabilities(&self) -> zeroclaw_api::model_provider::ProviderCapabilities {
        zeroclaw_api::model_provider::ProviderCapabilities {
            native_tool_calling: true,
            ..Default::default()
        }
    }

    async fn chat_with_system(
        &self,
        _system_prompt: Option<&str>,
        _message: &str,
        _model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        Ok("- summarized earlier facts FACT_1 FACT_2".to_string())
    }

    async fn chat(
        &self,
        request: ChatRequest<'_>,
        _model: &str,
        _temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        if request.tools.is_none()
            && request
                .messages
                .first()
                .is_some_and(|m| m.role == "system" && m.content.contains("compaction engine"))
        {
            return Ok(ChatResponse {
                text: Some("- compacted summary preserving FACT_1 FACT_2".to_string()),
                tool_calls: Vec::new(),
                usage: Some(zeroclaw_providers::traits::TokenUsage {
                    input_tokens: Some(120),
                    output_tokens: Some(30),
                    cached_input_tokens: None,
                }),
                reasoning_content: None,
            });
        }

        let mut guard = self.requests.lock().unwrap();
        let call_idx = guard.len();
        guard.push(CapturedChatRequest {
            messages: request.messages.to_vec(),
            tools_len: request.tools.map(|t| t.len()),
        });
        drop(guard);

        let usage = (self.reported_tokens_per_call)(call_idx).map(|input_tokens| {
            zeroclaw_providers::traits::TokenUsage {
                input_tokens: Some(input_tokens),
                output_tokens: Some(50),
                cached_input_tokens: None,
            }
        });

        if request.tools.is_none() || call_idx >= self.tool_rounds {
            let text = if self.emit_structured_final {
                "```json\n{\"report_markdown\":\"Partial report based on verified steps\",\"applicability\":\"applicable\",\"evidence\":[],\"open_questions\":[\"Remaining checks stopped at deadline\"]}\n```".to_string()
            } else {
                "final report complete".to_string()
            };
            return Ok(ChatResponse {
                text: Some(text),
                tool_calls: Vec::new(),
                usage,
                reasoning_content: None,
            });
        }

        let step = call_idx + 1;
        Ok(ChatResponse {
            text: None,
            tool_calls: vec![ToolCall {
                id: format!("call_{step}"),
                name: "echo_tool".to_string(),
                arguments: format!("{{\"step\":{step}}}"),
                extra_content: None,
            }],
            usage,
            reasoning_content: None,
        })
    }
}

fn compaction_test_delegate(
    profile: RuntimeProfileConfig,
    tools: Vec<Arc<dyn Tool>>,
) -> (DelegateTool, AliasedAgentConfig) {
    use zeroclaw_config::autonomy::{DelegationMode, DelegationPolicy};

    let mut root_config = Config::default();
    root_config
        .runtime_profiles
        .insert("agentic_test".to_string(), profile);
    let agent_cfg = agentic_agent_config();
    root_config
        .agents
        .insert("caller".to_string(), agent_cfg.clone());
    root_config
        .agents
        .insert("agentic".to_string(), agent_cfg.clone());
    root_config.risk_profiles.insert(
        "agentic_test".to_string(),
        RiskProfileConfig {
            delegation_policy: DelegationPolicy {
                mode: DelegationMode::Allow,
            },
            allowed_tools: vec!["echo_tool".to_string()],
            ..Default::default()
        },
    );
    let root_config = Arc::new(root_config);
    let caller_security = Arc::new(SecurityPolicy::for_agent(&root_config, "caller").unwrap());
    let tool = DelegateTool::new(root_config.agents.clone(), None, caller_security)
        .with_caller_alias("caller")
        .with_runtime_profiles(root_config.runtime_profiles.clone())
        .with_risk_profiles(root_config.risk_profiles.clone())
        .with_root_config(root_config)
        .with_parent_tools(Arc::new(RwLock::new(tools)));
    (tool, agent_cfg)
}

#[tokio::test]
async fn delegate_single_turn_context_is_compacted() {
    let mut profile = RuntimeProfileConfig {
        agentic: true,
        max_tool_iterations: 20,
        max_context_tokens: Some(353_000),
        max_tool_result_chars: Some(200_000),
        ..Default::default()
    };
    profile.context_compression = zeroclaw_config::scattered_types::ContextCompressionConfig {
        enabled: true,
        threshold_ratio: 0.70,
        protect_first_n: 0,
        protect_last_n: 2,
        max_passes: 2,
        tool_result_retrim_chars: 200,
        ..Default::default()
    };
    let (tool, agent_cfg) = compaction_test_delegate(
        profile,
        vec![Arc::new(LargeOutputTestTool {
            payload_bytes: 8_000,
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            advance_virtual_time: None,
        })],
    );

    let captured = Arc::new(std::sync::Mutex::new(Vec::<CapturedChatRequest>::new()));
    let provider = CapturingCompactionModelProvider {
        requests: Arc::clone(&captured),
        reported_tokens_per_call: Arc::new(|idx| match idx {
            0 => Some(2_000),
            1 => Some(120_000),
            2 => Some(720_700),
            _ => Some(80_000),
        }),
        tool_rounds: 5,
        emit_structured_final: false,
    };

    let task_prompt =
        "TASK_CONTRACT: Return exact JSON with report_markdown, evidence, open_questions.";
    let result = tool
        .execute_agentic(
            "agentic",
            &agent_cfg,
            "openai.codex_luna",
            "gpt-6-luna",
            &provider,
            task_prompt,
            Some(0.2),
        )
        .await
        .unwrap();

    assert!(result.success, "delegate failed: {:?}", result.error);
    let reqs = captured.lock().unwrap();
    assert!(
        reqs.len() >= 5,
        "expected multi-round requests, got {}",
        reqs.len()
    );

    let total_chars = |req: &CapturedChatRequest| -> usize {
        req.messages.iter().map(|m| m.content.len()).sum()
    };
    let before_compaction_chars = total_chars(&reqs[2]);
    let after_compaction_chars = total_chars(&reqs[3]);
    assert!(
        after_compaction_chars < before_compaction_chars,
        "single-turn context must compact after 720700 reported tokens: req[2]={before_compaction_chars}, req[3]={after_compaction_chars}"
    );
    for (idx, req) in reqs.iter().enumerate() {
        assert!(
            req.messages
                .iter()
                .any(|m| m.role == "user" && m.content.contains(task_prompt)),
            "original task/output contract must survive compaction at req[{idx}]"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn delegate_work_deadline_returns_structured_report() {
    let mut profile = RuntimeProfileConfig {
        agentic: true,
        max_tool_iterations: 200,
        agentic_timeout_secs: Some(4800),
        max_context_tokens: Some(1_048_576),
        ..Default::default()
    };
    profile.context_compression = zeroclaw_config::scattered_types::ContextCompressionConfig {
        enabled: true,
        threshold_ratio: 0.70,
        ..Default::default()
    };
    let tool_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (tool, agent_cfg) = compaction_test_delegate(
        profile,
        vec![Arc::new(LargeOutputTestTool {
            payload_bytes: 100,
            calls: Arc::clone(&tool_calls),
            advance_virtual_time: Some(Duration::from_secs(900)),
        })],
    );

    let captured = Arc::new(std::sync::Mutex::new(Vec::<CapturedChatRequest>::new()));
    let provider = CapturingCompactionModelProvider {
        requests: Arc::clone(&captured),
        reported_tokens_per_call: Arc::new(|_| Some(2_000)),
        tool_rounds: 200,
        emit_structured_final: true,
    };

    let start = tokio::time::Instant::now();
    let result = tool
        .execute_agentic(
            "agentic",
            &agent_cfg,
            "openai.codex_luna",
            "gpt-6-luna",
            &provider,
            "Analyze DV-1 and return fenced JSON with report_markdown, evidence, open_questions.",
            Some(0.2),
        )
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert!(
        result.success,
        "delegate must return structured report before hard timeout 4800s; elapsed={elapsed:?}, error={:?}",
        result.error
    );
    assert!(elapsed < Duration::from_secs(4800), "elapsed={elapsed:?}");
    assert_eq!(
        tool_calls.load(std::sync::atomic::Ordering::SeqCst),
        5,
        "no new tools may start after crossing W=4500s"
    );
    let reqs = captured.lock().unwrap();
    let last_req = reqs.last().expect("final request captured");
    assert_eq!(
        last_req.tools_len, None,
        "finalization request after work deadline must be tools-free"
    );
    let out = result.output.into_string();
    assert!(out.contains("report_markdown"), "got: {out}");
    assert!(out.contains("open_questions"), "got: {out}");
    assert!(
        !out.contains("maximum tool iterations"),
        "must not emit false max-iterations footer: {out}"
    );
}

#[test]
fn delegate_calibration_accounts_for_schemas_new_payload_and_model_switch() {
    use crate::agent::turn::delegate_control::{DelegateRunControl, RequestPopulationSnapshot};
    use zeroclaw_api::tool::ToolSpec;
    use zeroclaw_config::scattered_types::ContextCompressionConfig;

    let mut model_windows = HashMap::new();
    model_windows.insert("gpt-6-luna".to_string(), 353_000);
    model_windows.insert("glm-5.3".to_string(), 200_000);
    let compression = ContextCompressionConfig {
        threshold_ratio: 0.70,
        model_windows,
        ..Default::default()
    };
    let control = DelegateRunControl::new(
        Duration::from_secs(4800),
        tokio::time::Instant::now(),
        compression,
        1_048_576,
        None,
    );
    assert_eq!(control.context_window_for_model("gpt-6-luna"), 353_000);
    assert_eq!(control.threshold_for_model("gpt-6-luna"), 247_100);
    assert_eq!(control.context_window_for_model("glm-5.3"), 200_000);
    assert_eq!(control.threshold_for_model("glm-5.3"), 140_000);

    let history_before = vec![
        zeroclaw_providers::ChatMessage::system("sys"),
        zeroclaw_providers::ChatMessage::user("task"),
    ];
    let big_schema = ToolSpec::new(
        "heavy_tool",
        "Tool with large schema",
        serde_json::json!({
            "type": "object",
            "properties": {
                "blob": { "type": "string", "description": "x".repeat(4000) }
            }
        }),
    );
    let snap =
        RequestPopulationSnapshot::snapshot_request(&history_before, &history_before, Some(&[big_schema]));
    let uncalibrated = snap.build_calibration(None);
    assert!(
        uncalibrated.estimate(&history_before) > 1_000,
        "native tool schemas must contribute to population estimate"
    );

    let reported_from_provider = 20_000u64;
    let calibrated = snap.build_calibration(Some(reported_from_provider));
    let before_new_round = calibrated.estimate(&history_before);
    assert!(
        (before_new_round as i64 - reported_from_provider as i64).abs() <= 10,
        "calibrated estimate before new round must match reported usage: {before_new_round}"
    );

    let mut history_after_round = history_before.clone();
    history_after_round.push(zeroclaw_providers::ChatMessage::assistant("calling"));
    history_after_round.push(zeroclaw_providers::ChatMessage::tool("y".repeat(8_000)));
    let after_new_round = calibrated.estimate(&history_after_round);
    assert!(
        after_new_round > reported_from_provider as usize + 5_000,
        "new tool payload must be scaled into next request estimate, not denominator: {after_new_round}"
    );
}

#[tokio::test]
async fn delegate_compaction_preserves_multi_tool_text_utf8_images_exempt_and_reasoning() {
    use crate::agent::context_compressor::{ContextCompressor, DelegateCompressionCalibration};
    use crate::agent::turn::ResolvedModelAccess;
    use zeroclaw_config::scattered_types::ContextCompressionConfig;

    let config = ContextCompressionConfig {
        enabled: true,
        threshold_ratio: 0.50,
        protect_first_n: 0,
        protect_last_n: 2,
        max_passes: 2,
        tool_result_retrim_chars: 120,
        tool_result_trim_exempt: vec!["EXEMPT_KEEP".to_string()],
        ..Default::default()
    };
    let compressor = ContextCompressor::new(config, 2_000);
    let provider = CapturingCompactionModelProvider {
        requests: Arc::new(std::sync::Mutex::new(Vec::new())),
        reported_tokens_per_call: Arc::new(|_| None),
        tool_rounds: 0,
        emit_structured_final: false,
    };
    let access = ResolvedModelAccess {
        model_provider: &provider,
        provider_name: "test",
        model: "test-model",
        temperature: None,
    };

    let task_msg = "ORIGINAL_TASK_UTF8: Привет мир 🚀 contract=JSON";
    let mut native_history = vec![
        zeroclaw_providers::ChatMessage::system("SYSTEM_PROMPT"),
        zeroclaw_providers::ChatMessage::user(task_msg),
        zeroclaw_providers::ChatMessage::assistant(
            serde_json::json!({
                "content": "running batch",
                "reasoning_content": "REASONING_KEEP_ME",
                "tool_calls": [
                    {"id": "c1", "name": "echo_tool", "arguments": "{}"},
                    {"id": "c2", "name": "echo_tool", "arguments": "{}"}
                ]
            })
            .to_string(),
        ),
        zeroclaw_providers::ChatMessage::tool(
            serde_json::json!({
                "tool_call_id": "c1",
                "content": format!("EXEMPT_KEEP {}", "абв".repeat(600))
            })
            .to_string(),
        ),
        zeroclaw_providers::ChatMessage::tool(
            serde_json::json!({
                "tool_call_id": "c2",
                "content": format!("data:image/png;base64,{}", "A".repeat(3000))
            })
            .to_string(),
        ),
        zeroclaw_providers::ChatMessage::assistant(
            serde_json::json!({
                "content": null,
                "tool_calls": [{"id": "c3", "name": "echo_tool", "arguments": "{}"}]
            })
            .to_string(),
        ),
        zeroclaw_providers::ChatMessage::tool(
            serde_json::json!({"tool_call_id": "c3", "content": "recent tail result"}).to_string(),
        ),
    ];

    let outcome = compressor
        .compress_for_delegate(
            &mut native_history,
            1_000,
            &access,
            &DelegateCompressionCalibration::default(),
            Duration::from_secs(10),
            None,
        )
        .await
        .unwrap();
    assert!(outcome.made_progress);
    assert_eq!(native_history[0].content, "SYSTEM_PROMPT");
    assert_eq!(native_history[1].content, task_msg);
    assert!(
        native_history
            .iter()
            .any(|m| m.role == "assistant" && m.content.contains("REASONING_KEEP_ME")),
        "reasoning_content must be preserved across compaction"
    );
    let tail_c3_asst = native_history
        .iter()
        .position(|m| m.role == "assistant" && m.content.contains("\"c3\""))
        .expect("tail c3 assistant kept");
    assert!(
        native_history[tail_c3_asst + 1].role == "tool"
            && native_history[tail_c3_asst + 1].content.contains("\"c3\""),
        "tail c3 assistant/tool pair must stay intact without orphans"
    );

    let mut text_history = vec![
        zeroclaw_providers::ChatMessage::system("SYSTEM_PROMPT"),
        zeroclaw_providers::ChatMessage::user(task_msg),
        zeroclaw_providers::ChatMessage::assistant("<tool_call>echo 1</tool_call>"),
        zeroclaw_providers::ChatMessage::user(format!(
            "[Tool results]\nЮникод_{}",
            "я".repeat(3000)
        )),
        zeroclaw_providers::ChatMessage::assistant("<tool_call>echo 2</tool_call>"),
        zeroclaw_providers::ChatMessage::user("[Tool results]\nrecent text result"),
    ];
    let text_outcome = compressor
        .compress_for_delegate(
            &mut text_history,
            800,
            &access,
            &DelegateCompressionCalibration::default(),
            Duration::from_secs(10),
            None,
        )
        .await
        .unwrap();
    assert!(text_outcome.made_progress);
    assert_eq!(text_history[0].content, "SYSTEM_PROMPT");
    assert_eq!(text_history[1].content, task_msg);
    assert!(
        text_history
            .iter()
            .any(|m| m.content.contains("recent text result")),
        "protected tail text tool result must survive"
    );
}

#[tokio::test]
async fn delegate_compaction_cancellation_fallback_and_cost_metering() {
    use crate::agent::context_compressor::{ContextCompressor, DelegateCompressionCalibration};
    use crate::agent::cost::{TOOL_LOOP_COST_TRACKING_CONTEXT, ToolLoopCostTrackingContext};
    use crate::agent::turn::ResolvedModelAccess;
    use zeroclaw_config::scattered_types::ContextCompressionConfig;

    struct SlowOrFailSummarizerProvider {
        delay: Duration,
        fail_with: Option<String>,
        empty: bool,
    }
    impl ::zeroclaw_api::attribution::Attributable for SlowOrFailSummarizerProvider {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "SlowOrFailSummarizerProvider"
        }
    }
    #[async_trait]
    impl ModelProvider for SlowOrFailSummarizerProvider {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            unreachable!()
        }
        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if let Some(ref msg) = self.fail_with {
                anyhow::bail!("{msg}");
            }
            Ok(ChatResponse {
                text: Some(if self.empty {
                    "   ".to_string()
                } else {
                    "metered summary".to_string()
                }),
                tool_calls: Vec::new(),
                usage: Some(zeroclaw_providers::traits::TokenUsage {
                    input_tokens: Some(333),
                    output_tokens: Some(77),
                    cached_input_tokens: None,
                }),
                reasoning_content: None,
            })
        }
    }

    let make_history = || {
        vec![
            zeroclaw_providers::ChatMessage::system("SYS"),
            zeroclaw_providers::ChatMessage::user("TASK"),
            zeroclaw_providers::ChatMessage::assistant("a1 ".repeat(1000)),
            zeroclaw_providers::ChatMessage::assistant("a2 ".repeat(1000)),
            zeroclaw_providers::ChatMessage::user("recent"),
        ]
    };

    // 1. Cancellation during summarization must return ToolLoopCancelled without mutating history.
    let compressor = ContextCompressor::new(
        ContextCompressionConfig {
            enabled: true,
            protect_first_n: 2,
            protect_last_n: 1,
            max_passes: 1,
            ..Default::default()
        },
        1_000,
    );
    let slow_provider = SlowOrFailSummarizerProvider {
        delay: Duration::from_secs(30),
        fail_with: None,
        empty: false,
    };
    let access = ResolvedModelAccess {
        model_provider: &slow_provider,
        provider_name: "custom",
        model: "m",
        temperature: None,
    };
    let token = CancellationToken::new();
    let cancel_clone = token.clone();
    ::zeroclaw_spawn::spawn!(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel_clone.cancel();
    });
    let mut candidate = make_history();
    let err = compressor
        .compress_for_delegate(
            &mut candidate,
            500,
            &access,
            &DelegateCompressionCalibration::default(),
            Duration::from_secs(10),
            Some(&token),
        )
        .await
        .unwrap_err();
    assert!(crate::agent::turn::is_tool_loop_cancelled(&err));

    // 2. Provider error falls back to excerpt with explicit diagnostic metadata (not LLM summary).
    let err_provider = SlowOrFailSummarizerProvider {
        delay: Duration::ZERO,
        fail_with: Some("503 upstream failed SECRET_KEY_RAW".to_string()),
        empty: false,
    };
    let err_access = ResolvedModelAccess {
        model_provider: &err_provider,
        provider_name: "custom",
        model: "m",
        temperature: None,
    };
    let mut err_history = make_history();
    let err_outcome = compressor
        .compress_for_delegate(
            &mut err_history,
            500,
            &err_access,
            &DelegateCompressionCalibration::default(),
            Duration::from_secs(10),
            None,
        )
        .await
        .unwrap();
    assert!(err_outcome.used_fallback_excerpt);
    assert!(err_outcome.fallback_reason.is_some());
    assert!(
        err_history
            .iter()
            .any(|m| m.content.contains("[CONTEXT EXCERPT")),
        "fallback excerpt must not be labeled as confirmed LLM summary"
    );

    // 3. Successful summarizer call is metered through TOOL_LOOP_COST_TRACKING_CONTEXT.
    let tmp = TempDir::new().unwrap();
    let tracker = Arc::new(
        crate::cost::CostTracker::new(zeroclaw_config::schema::CostConfig::default(), tmp.path())
            .unwrap(),
    );
    let cost_ctx = ToolLoopCostTrackingContext::new(tracker, Arc::new(HashMap::new()));
    let metered_provider = SlowOrFailSummarizerProvider {
        delay: Duration::ZERO,
        fail_with: None,
        empty: false,
    };
    let metered_access = ResolvedModelAccess {
        model_provider: &metered_provider,
        provider_name: "custom",
        model: "m",
        temperature: None,
    };
    let mut metered_history = make_history();
    TOOL_LOOP_COST_TRACKING_CONTEXT
        .scope(Some(cost_ctx.clone()), async {
            compressor
                .compress_for_delegate(
                    &mut metered_history,
                    500,
                    &metered_access,
                    &DelegateCompressionCalibration::default(),
                    Duration::from_secs(10),
                    None,
                )
                .await
                .unwrap()
        })
        .await;
    let usage = cost_ctx.snapshot_turn_usage();
    assert_eq!(usage.input_tokens, 333);
    assert_eq!(usage.output_tokens, 77);
}

#[tokio::test]
async fn delegate_control_rejects_incompatible_canonical_mirror() {
    use crate::agent::turn::{
        DelegateRunControl, LoopKnobs, ResolvedAgentExecution, ResolvedIo, ResolvedModelAccess,
        ResolvedRuntimeKnobs, ToolLoop, run_tool_call_loop,
    };
    use zeroclaw_config::scattered_types::ContextCompressionConfig;

    let provider = OneToolThenFinalModelProvider;
    let registry = crate::tools::scoped::ScopedToolRegistry::from_raw_for_test(Vec::new());
    let observer = NoopObserver;
    let multimodal = zeroclaw_config::schema::MultimodalConfig::default();
    let pacing = zeroclaw_config::schema::PacingConfig::default();
    let knobs = LoopKnobs::default();
    let mut history = vec![zeroclaw_providers::ChatMessage::user("hi")];
    let mut canonical = Vec::new();
    let control = DelegateRunControl::new(
        Duration::from_secs(60),
        tokio::time::Instant::now(),
        ContextCompressionConfig::default(),
        10_000,
        None,
    );

    let err = run_tool_call_loop(ToolLoop {
        exec: ResolvedAgentExecution::resolve(
            ResolvedModelAccess {
                model_provider: &provider,
                provider_name: "test",
                model: "m",
                temperature: None,
            },
            ResolvedIo {
                tools_registry: &registry,
                observer: &observer,
                silent: true,
                approval: None,
                multimodal_config: &multimodal,
                config: None,
                hooks: None,
                activated_tools: None,
                model_switch_callback: None,
                receipt_generator: None,
            },
            ResolvedRuntimeKnobs {
                max_tool_iterations: 5,
                excluded_tools: &[],
                dedup_exempt_tools: &[],
                pacing: &pacing,
                strict_tool_parsing: false,
                parallel_tools: false,
                max_tool_result_chars: 1000,
                context_token_budget: 10_000,
                knobs: &knobs,
            },
        ),
        final_response_min_chars: None,
        history: &mut history,
        channel_name: "delegate",
        channel_reply_target: None,
        cancellation_token: None,
        on_delta: None,
        shared_budget: None,
        channel: None,
        collected_receipts: None,
        event_tx: None,
        steering: None,
        new_messages_out: Some(&mut canonical),
        image_cache: None,
        memory: None,
        ingress: zeroclaw_api::ingress::IngressContext::sub_turn(),
        agent_alias: Some("agentic"),
        parent_agent_alias: None,
        turn_id: "canonical-mismatch-test",
        sop_reassembly: None,
        delegate_control: Some(control),
    })
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("canonical"),
        "expected explicit canonical mirror incompatibility error, got: {err}"
    );
}

#[tokio::test]
async fn delegate_disabled_and_no_progress_pressure_finalize_cleanly() {
    for enabled in [false, true] {
        let mut profile = RuntimeProfileConfig {
            agentic: true,
            max_tool_iterations: 50,
            max_context_tokens: Some(1_000),
            max_tool_result_chars: Some(100_000),
            ..Default::default()
        };
        profile.context_compression = zeroclaw_config::scattered_types::ContextCompressionConfig {
            enabled,
            threshold_ratio: 0.50,
            protect_first_n: 2,
            protect_last_n: 10,
            emergency_protect_last_n: 10,
            tool_result_retrim_chars: 0,
            ..Default::default()
        };
        let (tool, agent_cfg) = compaction_test_delegate(
            profile,
            vec![Arc::new(LargeOutputTestTool {
                payload_bytes: 2_000,
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                advance_virtual_time: None,
            })],
        );

        let captured = Arc::new(std::sync::Mutex::new(Vec::<CapturedChatRequest>::new()));
        let provider = CapturingCompactionModelProvider {
            requests: Arc::clone(&captured),
            reported_tokens_per_call: Arc::new(|_| Some(5_000)),
            tool_rounds: 50,
            emit_structured_final: true,
        };
        let result = tool
            .execute_agentic(
                "agentic",
                &agent_cfg,
                "openai.codex_luna",
                "gpt-6-luna",
                &provider,
                "Analyze DV-2 and return fenced JSON.",
                None,
            )
            .await
            .unwrap();
        assert!(
            result.success,
            "enabled={enabled} must finalize cleanly instead of looping infinitely: {:?}",
            result.error
        );
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 2, "must stop after 1 round + 1 tools-free final");
        assert_eq!(reqs.last().unwrap().tools_len, None);
        assert!(!result.output.into_string().contains("maximum tool iterations"));
    }
}

#[tokio::test(start_paused = true)]
async fn delegate_final_failure_empty_and_long_tool_timeout_remain_failed() {
    struct TerminalEdgeProvider {
        mode: &'static str,
    }
    impl ::zeroclaw_api::attribution::Attributable for TerminalEdgeProvider {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "TerminalEdgeProvider"
        }
    }
    #[async_trait]
    impl ModelProvider for TerminalEdgeProvider {
        fn capabilities(&self) -> zeroclaw_api::model_provider::ProviderCapabilities {
            zeroclaw_api::model_provider::ProviderCapabilities {
                native_tool_calling: true,
                ..Default::default()
            }
        }
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            unreachable!()
        }
        async fn chat(
            &self,
            request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            if request.tools.is_none() {
                return match self.mode {
                    "error" => anyhow::bail!("final provider error"),
                    "empty" => Ok(ChatResponse {
                        text: Some("<think>only reasoning</think>".to_string()),
                        tool_calls: Vec::new(),
                        usage: None,
                        reasoning_content: None,
                    }),
                    _ => unreachable!(),
                };
            }
            Ok(ChatResponse {
                text: None,
                tool_calls: vec![ToolCall {
                    id: "c1".to_string(),
                    name: "echo_tool".to_string(),
                    arguments: "{\"step\":1}".to_string(),
                    extra_content: None,
                }],
                usage: Some(zeroclaw_providers::traits::TokenUsage {
                    input_tokens: Some(100),
                    output_tokens: Some(10),
                    cached_input_tokens: None,
                }),
                reasoning_content: None,
            })
        }
    }

    for mode in ["error", "empty"] {
        let profile = RuntimeProfileConfig {
            agentic: true,
            max_tool_iterations: 50,
            agentic_timeout_secs: Some(100),
            ..Default::default()
        };
        let (tool, agent_cfg) = compaction_test_delegate(
            profile,
            vec![Arc::new(LargeOutputTestTool {
                payload_bytes: 10,
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                advance_virtual_time: Some(Duration::from_secs(80)),
            })],
        );
        let provider = TerminalEdgeProvider { mode };
        let res = tool
            .execute_agentic("agentic", &agent_cfg, "test", "m", &provider, "run", None)
            .await
            .unwrap();
        assert!(!res.success, "mode={mode} must fail honestly");
        assert!(res.output.is_empty(), "mode={mode} must have empty output");
    }

    // Long tool exceeding H=100s must NOT be cancelled at W=75s, must NOT retry, and must time out at H=100s.
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let profile = RuntimeProfileConfig {
        agentic: true,
        max_tool_iterations: 50,
        agentic_timeout_secs: Some(100),
        ..Default::default()
    };
    let (tool, agent_cfg) = compaction_test_delegate(
        profile,
        vec![Arc::new(LargeOutputTestTool {
            payload_bytes: 10,
            calls: Arc::clone(&calls),
            advance_virtual_time: Some(Duration::from_secs(150)),
        })],
    );
    let provider = TerminalEdgeProvider { mode: "error" };
    let res = tool
        .execute_agentic("agentic", &agent_cfg, "test", "m", &provider, "run", None)
        .await
        .unwrap();
    assert!(!res.success);
    assert!(res.output.is_empty());
    assert!(res.error.as_deref().unwrap_or("").contains("timed out after 100s"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delegate_span_records_target_runtime_profile_and_redacts_secrets() {
    use ::zeroclaw_log::Instrument as _;

    let _writer_guard = zeroclaw_log::__private_test_writer_lock();
    let _hook_guard = zeroclaw_log::__private_test_hook_lock();
    zeroclaw_log::try_install_capture_subscriber();
    let mut rx = zeroclaw_log::subscribe_or_install();
    while rx.try_recv().is_ok() {}

    let secret = "MARKER_SECRET_998877";
    let mut profile = RuntimeProfileConfig {
        agentic: true,
        max_tool_iterations: 10,
        max_context_tokens: Some(1_000),
        ..Default::default()
    };
    profile.context_compression = zeroclaw_config::scattered_types::ContextCompressionConfig {
        enabled: true,
        threshold_ratio: 0.50,
        protect_first_n: 2,
        protect_last_n: 2,
        max_passes: 1,
        tool_result_retrim_chars: 100,
        ..Default::default()
    };
    let (mut tool, mut agent_cfg) = compaction_test_delegate(
        profile.clone(),
        vec![Arc::new(LargeOutputTestTool {
            payload_bytes: 3_000,
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            advance_virtual_time: None,
        })],
    );
    agent_cfg.runtime_profile = "jira_research".into();
    let mut cfg = (**tool.root_config.as_ref().unwrap()).clone();
    cfg.runtime_profiles.insert("jira_research".to_string(), profile);
    cfg.agents.get_mut("agentic").unwrap().runtime_profile = "jira_research".into();
    tool = tool
        .with_runtime_profiles(cfg.runtime_profiles.clone())
        .with_root_config(Arc::new(cfg));

    let provider = CapturingCompactionModelProvider {
        requests: Arc::new(std::sync::Mutex::new(Vec::new())),
        reported_tokens_per_call: Arc::new(|idx| if idx == 0 { Some(5_000) } else { Some(200) }),
        tool_rounds: 2,
        emit_structured_final: false,
    };

    let parent_span = ::zeroclaw_log::info_span!(
        target: "zeroclaw_log_internal_scope",
        "zeroclaw_scope",
        runtime_profile = "jira_analysis",
        risk_profile = "parent_risk",
    );
    let res = tool
        .execute_agentic(
            "agentic",
            &agent_cfg,
            "openai.codex_luna",
            "gpt-6-luna",
            &provider,
            &format!("Task containing {secret}"),
            None,
        )
        .instrument(parent_span)
        .await
        .unwrap();
    assert!(res.success, "{:?}", res.error);

    let events: Vec<serde_json::Value> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let maintenance = events
        .iter()
        .find(|ev| ev["message"] == "delegate_context_maintenance")
        .expect("delegate_context_maintenance event emitted");
    assert_eq!(
        maintenance["zeroclaw"]["runtime_profile"], "jira_research",
        "delegate span must reflect target runtime_profile, not parent's jira_analysis: {maintenance}"
    );
    assert_eq!(maintenance["zeroclaw"]["agent_alias"], "agentic");
    assert!(
        !maintenance.to_string().contains(secret),
        "secret marker must never appear in compaction log event: {maintenance}"
    );
}

