const PRIVATE_REASONING_FIXTURE: &str = "fixture-private-reasoning";
const ROUNDTRIP_REJECTION_FIXTURE: &str =
    "The `reasoning_content` in the thinking mode must be passed back to the API.";

struct CountingReasoningEcho(Arc<std::sync::atomic::AtomicUsize>);

impl ::zeroclaw_api::attribution::Attributable for CountingReasoningEcho {
    fn role(&self) -> ::zeroclaw_api::attribution::Role {
        ::zeroclaw_api::attribution::Attributable::role(&EchoTool)
    }
    fn alias(&self) -> &str {
        "echo_tool"
    }
}

#[async_trait]
impl Tool for CountingReasoningEcho {
    fn name(&self) -> &str {
        "echo_tool"
    }
    fn description(&self) -> &str {
        "Echoes a value."
    }
    fn parameters_schema(&self) -> serde_json::Value {
        EchoTool.parameters_schema()
    }
    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        EchoTool.execute(args).await
    }
}

async fn start_reasoning_delegate_server(
    mode: &'static str,
) -> (
    LocalChatServer,
    Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = bodies.clone();
    let task = zeroclaw_spawn::spawn!(async move {
        let mut continuation = 0;
        loop {
            let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                break;
            };
            let raw = read_http_request(&mut socket).await;
            let request = http_request_json(&raw);
            captured.lock().unwrap().push(request.clone());
            let has_tool = request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["role"] == "tool");
            if !has_tool {
                let mut response = chat_completion_tool_call(
                    "echo_tool",
                    "call_thinking_echo",
                    json!({"value": "ping"}),
                );
                if mode == "normal" || mode == "whole400" {
                    response["choices"][0]["message"]["reasoning_content"] =
                        json!(PRIVATE_REASONING_FIXTURE);
                }
                write_chat_response(&mut socket, &raw, response).await;
                continue;
            }
            continuation += 1;
            if (mode == "h2_stream" && continuation == 1)
                || (mode == "h2_fallback" && continuation <= 2)
            {
                socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 14\r\nconnection: close\r\n\r\ndata: [DONE]\n\n").await.unwrap();
                continue;
            }
            let repaired = request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|message| message["role"] == "assistant")
                .all(|message| {
                    message["reasoning_content"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                });
            let reject = mode != "normal"
                && (!repaired
                    || mode == "whole400"
                    || mode == "persistent400"
                    || mode == "auth"
                    || mode == "rate"
                    || mode == "other400");
            if reject {
                let status = match mode {
                    "auth" => 401,
                    "rate" => 429,
                    _ => 400,
                };
                let mut body = json!({"error": {"message": ROUNDTRIP_REJECTION_FIXTURE}});
                if mode == "h3" && request["reasoning_effort"] != "none" {
                    body = json!({"error": {"message": "tools are not supported with reasoning_effort high"}});
                } else if mode == "h4" {
                    body = json!({"error": {"metadata": {"raw": body.to_string()}}});
                } else if mode == "h5" {
                    body = json!({"error": {"message": format!("{}{}", "x".repeat(600), ROUNDTRIP_REJECTION_FIXTURE)}});
                } else if mode == "other400" {
                    body = json!({"error": {"message": "invalid temperature"}});
                }
                let (status, content_type, payload) = if mode == "h1" && request["stream"] == true {
                    (
                        200,
                        "text/event-stream",
                        format!("data: {body}\n\ndata: [DONE]\n\n"),
                    )
                } else {
                    (status, "application/json", body.to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status} Rejected\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            } else {
                write_chat_response(&mut socket, &raw, json!({"choices": [{"message": {"content": "ROUNDTRIP-OK", "reasoning_content": PRIVATE_REASONING_FIXTURE}}]})).await;
            }
        }
    });
    (LocalChatServer { uri, _task: task }, bodies)
}

async fn check_delegate_reasoning_mode(
    mode: &'static str,
    expected_success: bool,
    expected_repairs: usize,
) {
    check_delegate_reasoning_mode_capture(mode, expected_success, expected_repairs, false).await;
}

async fn check_delegate_reasoning_mode_capture(
    mode: &'static str,
    expected_success: bool,
    expected_repairs: usize,
    inject_foreign_request: bool,
) {
    let _writer_guard = zeroclaw_log::__private_test_writer_lock();
    let _hook_guard = zeroclaw_log::__private_test_hook_lock();
    zeroclaw_log::try_install_capture_subscriber();
    let previous_hook = zeroclaw_log::current_broadcast_hook();
    let _restore_hook = scopeguard::guard(previous_hook, |hook| match hook {
        Some(hook) => zeroclaw_log::set_broadcast_hook(hook),
        None => zeroclaw_log::clear_broadcast_hook(),
    });
    let (sender, mut receiver) = tokio::sync::broadcast::channel(65_536);
    zeroclaw_log::set_broadcast_hook(sender);
    let foreign_turn_id = uuid::Uuid::new_v4().to_string();
    if inject_foreign_request {
        ::zeroclaw_log::record!(
            INFO,
            ::zeroclaw_log::Event::new(module_path!(), ::zeroclaw_log::Action::Send)
                .with_category(::zeroclaw_log::EventCategory::Provider)
                .with_attrs(json!({
                    "model": "foreign-fixture-model",
                    "trace_id": foreign_turn_id,
                    "agent_alias": "foreign-fixture-agent",
                    "iteration": 1,
                    "messages_count": 1,
                })),
            "llm_request"
        );
    }
    let (server, captured) = start_reasoning_delegate_server(mode).await;
    let (config, _fixture_dir) = fallback_delegate_config_with_native_tools(
        server.uri.clone(),
        server.uri.clone(),
        true,
        Some(true),
        Some(true),
    );
    let mut config = (*config).clone();
    let fixture_id = uuid::Uuid::new_v4().simple().to_string();
    let delegate_alias = format!("reasoning_{mode}_{fixture_id}");
    let fixture_model = format!("reasoning-model-{fixture_id}");
    let target = config.agents.remove("target").unwrap();
    config.agents.insert(delegate_alias.clone(), target);
    if mode == "h2_fallback" {
        config.reliability.provider_retries = 1;
    }
    let primary = config.providers.models.custom.get_mut("primary").unwrap();
    primary.base.fallback.clear();
    primary.base.model = Some(fixture_model.clone());
    primary.base.provider_extra = Some(json!({"reasoning_effort": "high"}));
    let executions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tool = fallback_delegate_tool(Arc::new(config), None).with_parent_tools(Arc::new(
        RwLock::new(vec![Arc::new(CountingReasoningEcho(executions.clone()))]),
    ));
    let result = tool
        .execute(json!({"agent": delegate_alias, "prompt": "Use echo once and return the result"}))
        .await
        .unwrap();
    let bodies = captured.lock().unwrap().clone();
    assert_eq!(
        result.success,
        expected_success,
        "mode={mode}; requests={}; error={:?}",
        bodies.len(),
        result.error
    );
    assert_eq!(
        executions.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "mode={mode}"
    );
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains(PRIVATE_REASONING_FIXTURE)
    );
    assert!(!bodies.is_empty());
    for body in &bodies {
        assert_eq!(body["model"], fixture_model);
        let messages = body["messages"].as_array().unwrap();
        for result in messages.iter().filter(|message| message["role"] == "tool") {
            assert!(
                messages
                    .iter()
                    .filter(|message| message["role"] == "assistant")
                    .flat_map(|message| message["tool_calls"].as_array().into_iter().flatten())
                    .any(|call| call["id"] == result["tool_call_id"])
            );
        }
    }
    let mut events = Vec::new();
    loop {
        match receiver.try_recv() {
            Ok(event) => events.push(event),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(error) => panic!("log capture lost events: {error:?}"),
        }
    }
    if inject_foreign_request {
        assert!(events.iter().any(|event| {
            event["message"] == "llm_request"
                && event["attributes"]["trace_id"] == foreign_turn_id
                && event["attributes"]["model"] == "foreign-fixture-model"
        }));
    }
    let requests = events
        .iter()
        .filter(|event| {
            event["message"] == "llm_request"
                && (event["attributes"]["model"] == fixture_model
                    || event["zeroclaw"]["agent_alias"] == delegate_alias)
        })
        .collect::<Vec<_>>();
    assert!(!requests.is_empty(), "mode={mode}; missing owned request");
    assert_eq!(requests[0]["attributes"]["iteration"], 1);
    let original_turn_id = requests[0]["attributes"]["trace_id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(original_turn_id).is_ok());
    assert!(requests.iter().all(|event| {
        event["attributes"]["model"] == fixture_model
            && event["zeroclaw"]["agent_alias"] == delegate_alias
            && event["attributes"]["trace_id"] == original_turn_id
    }));
    if inject_foreign_request {
        let foreign_position = events
            .iter()
            .position(|event| {
                event["message"] == "llm_request"
                    && event["attributes"]["trace_id"] == foreign_turn_id
            })
            .unwrap();
        let owned_position = events
            .iter()
            .position(|event| event["id"] == requests[0]["id"])
            .unwrap();
        assert!(foreign_position < owned_position);
        assert_ne!(foreign_turn_id, original_turn_id);
    }
    let rejects = events
        .iter()
        .filter(|event| {
            event["message"].as_str() == Some("reasoning_roundtrip_rejected")
                && (event["attributes"]["agent_alias"] == delegate_alias
                    || event["attributes"]["model"] == fixture_model)
        })
        .collect::<Vec<_>>();
    assert!(rejects.iter().all(|event| {
        event["attributes"]["agent_alias"] == delegate_alias
            && event["attributes"]["model"] == fixture_model
            && event["attributes"]["trace_id"] == original_turn_id
    }));
    let repairs = rejects
        .iter()
        .filter(|event| event["attributes"]["repaired"] == true)
        .count();
    assert_eq!(
        repairs,
        expected_repairs,
        "mode={mode}; requests={}; rejection_shapes={:?}",
        bodies.len(),
        rejects
            .iter()
            .map(|event| &event["attributes"])
            .collect::<Vec<_>>()
    );
    let turn_ids = rejects
        .iter()
        .map(|event| event["attributes"]["trace_id"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    if expected_repairs > 0 {
        assert!(turn_ids.contains(original_turn_id));
        assert_eq!(
            turn_ids.len(),
            1,
            "repair must stay in the original delegate turn"
        );
        assert!(
            rejects
                .iter()
                .all(|event| event["attributes"]["agent_alias"] == delegate_alias)
        );
        assert!(
            bodies.last().unwrap()["messages"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|message| message["role"] == "assistant")
                .all(|message| message["reasoning_content"] == "[reasoning recovered]")
        );
    }
    if mode == "normal" {
        assert_eq!(bodies.len(), 2);
        assert!(bodies.iter().all(|body| body["stream"] == true));
        let assistants = bodies[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "assistant")
            .collect::<Vec<_>>();
        assert_eq!(assistants.len(), 1);
        assert!(
            assistants
                .iter()
                .all(|message| message["reasoning_content"] == PRIVATE_REASONING_FIXTURE)
        );
    }
    if mode == "h3" {
        assert!(bodies.iter().any(|body| body["reasoning_effort"] == "none"));
    }
    if mode == "h2_stream" || mode == "h2_fallback" {
        let stream_flags = bodies
            .iter()
            .map(|body| body["stream"] == true)
            .collect::<Vec<_>>();
        let expected_stream_flags = if mode == "h2_stream" {
            vec![true, true, true, true]
        } else {
            vec![true, true, true, false, true]
        };
        assert_eq!(stream_flags, expected_stream_flags, "mode={mode}");
        assert!(
            bodies[1]["messages"] == bodies[2]["messages"],
            "mode={mode}; the stream retry must retain the same history"
        );
        if mode == "h2_fallback" {
            assert!(
                bodies[2]["messages"] == bodies[3]["messages"],
                "the JSON fallback must retain the same history"
            );
        }
    }
    if mode == "persistent400" {
        assert_eq!(rejects.len(), 2);
        assert_eq!(bodies.len(), 3);
    }
    let logged = serde_json::to_string(&events).unwrap();
    assert!(!logged.contains(PRIVATE_REASONING_FIXTURE));
    server._task.abort();
}

#[tokio::test]
async fn delegate_stream_preserves_reasoning_on_next_request() {
    check_delegate_reasoning_mode("normal", true, 0).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_rejection_repairs_once() {
    check_delegate_reasoning_mode("once400", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h1_in_band_rejection_repairs_once() {
    check_delegate_reasoning_mode("h1", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h2_stream_retry_repairs_once() {
    check_delegate_reasoning_mode("h2_stream", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h2_json_fallback_repairs_once() {
    check_delegate_reasoning_mode("h2_fallback", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h3_capability_retry_repairs_once() {
    check_delegate_reasoning_mode("h3", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_repair_joins_owned_request_amid_foreign_events() {
    check_delegate_reasoning_mode_capture("h3", true, 1, true).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h4_router_envelope_repairs_once() {
    check_delegate_reasoning_mode("h4", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h5_tail_rejection_repairs_once() {
    check_delegate_reasoning_mode("h5", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_h6_typed_cause_repairs_once() {
    check_delegate_reasoning_mode("h6", true, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_complete_history_is_not_repaired() {
    check_delegate_reasoning_mode("whole400", false, 0).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_persistent_rejection_stops_after_one_repair() {
    check_delegate_reasoning_mode("persistent400", false, 1).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_auth_does_not_repair() {
    check_delegate_reasoning_mode("auth", false, 0).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_rate_limit_does_not_repair() {
    check_delegate_reasoning_mode("rate", false, 0).await;
}
#[tokio::test]
async fn delegate_stream_roundtrip_other_400_does_not_repair() {
    check_delegate_reasoning_mode("other400", false, 0).await;
}

#[tokio::test]
async fn delegate_stream_reasoning_survives_main_history_owner_next_turn() {
    let (server, captured) = start_reasoning_delegate_server("normal").await;
    let (config, _fixture_dir) = fallback_delegate_config_with_native_tools(
        server.uri.clone(),
        server.uri.clone(),
        true,
        Some(true),
        Some(true),
    );
    let mut config = (*config).clone();
    config
        .providers
        .models
        .custom
        .get_mut("primary")
        .unwrap()
        .base
        .fallback
        .clear();
    let tool = fallback_delegate_tool(Arc::new(config.clone()), None);
    let (provider, _, _) = tool
        .build_target_provider("custom.primary", "custom", None)
        .unwrap();
    assert!(provider.supports_reasoning_only_history());
    let registry =
        crate::tools::scoped::ScopedToolRegistry::from_raw_for_test(vec![Box::new(EchoTool)]);
    let mut history = vec![
        ChatMessage::system("fixture"),
        ChatMessage::user("first turn"),
    ];
    for index in 0..2 {
        if index == 1 {
            history.push(ChatMessage::user("next turn"));
        }
        let response = crate::agent::loop_::agent_turn(
            Some(&config),
            provider.as_ref(),
            &mut history,
            &registry,
            &NoopObserver,
            "custom.primary",
            "primary-model",
            Some(0.0),
            true,
            "webhook",
            None,
            &config.multimodal,
            6,
            None,
            &[],
            &[],
            None,
            None,
            false,
            false,
            0,
            32_000,
            None,
            None,
            None,
            zeroclaw_api::ingress::TurnOrigin::SubTurn,
            None,
            Some("caller"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(response, "ROUNDTRIP-OK");
        let final_entry =
            serde_json::from_str::<serde_json::Value>(&history.last().unwrap().content);
        assert!(
            final_entry
                .as_ref()
                .is_ok_and(|value| value["reasoning_content"] == PRIVATE_REASONING_FIXTURE),
            "final history is structured={} reasoning_present={}",
            final_entry.is_ok(),
            final_entry
                .as_ref()
                .is_ok_and(|value| value.get("reasoning_content").is_some())
        );
    }
    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 3);
    let assistants = bodies[2]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "assistant")
        .collect::<Vec<_>>();
    assert_eq!(assistants.len(), 2);
    assert!(
        assistants
            .iter()
            .all(|message| message["reasoning_content"] == PRIVATE_REASONING_FIXTURE)
    );
    server._task.abort();
}
