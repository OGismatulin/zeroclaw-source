struct CancellationFixtureProvider {
    commands: Vec<String>,
    calls: AtomicUsize,
    summaries: AtomicUsize,
    summary_started: tokio::sync::Semaphore,
    summary_pending: bool,
    summary_dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationFixtureProvider {
    fn new(commands: &[&str], summary_pending: bool) -> Self {
        Self {
            commands: commands.iter().map(|v| (*v).into()).collect(),
            calls: AtomicUsize::new(0),
            summaries: AtomicUsize::new(0),
            summary_started: tokio::sync::Semaphore::new(0),
            summary_pending,
            summary_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

struct SummaryDropFlag(Arc<std::sync::atomic::AtomicBool>);
impl Drop for SummaryDropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl ModelProvider for CancellationFixtureProvider {
    fn supports_native_tools(&self) -> bool {
        true
    }
    async fn chat_with_system(
        &self,
        _: Option<&str>,
        _: &str,
        _: &str,
        _: Option<f64>,
    ) -> anyhow::Result<String> {
        self.summaries.fetch_add(1, Ordering::SeqCst);
        let _drop = SummaryDropFlag(self.summary_dropped.clone());
        self.summary_started.add_permits(1);
        if self.summary_pending {
            std::future::pending::<()>().await;
        }
        Ok("summary".into())
    }
    async fn chat(
        &self,
        _: zeroclaw_providers::ChatRequest<'_>,
        _: &str,
        _: Option<f64>,
    ) -> anyhow::Result<zeroclaw_providers::ChatResponse> {
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        let tool_calls = if first {
            self.commands.iter().enumerate().map(|(index, name)| zeroclaw_providers::ToolCall {
                id: format!("cancel-call-{index}"), name: "shell".into(), extra_content: None,
                arguments: serde_json::json!({"command": format!("python3 cancellation_fixture.py {name}"), "timeout_secs":30}).to_string(),
            }).collect()
        } else {
            vec![]
        };
        Ok(zeroclaw_providers::ChatResponse {
            text: tool_calls.is_empty().then(|| "successor-executed".into()),
            tool_calls,
            usage: None,
            reasoning_content: None,
        })
    }
}
impl ::zeroclaw_api::attribution::Attributable for CancellationFixtureProvider {
    fn role(&self) -> ::zeroclaw_api::attribution::Role {
        ::zeroclaw_api::attribution::Role::System
    }
    fn alias(&self) -> &str {
        "cancellation-fixture"
    }
}

async fn cancellation_webhook(
    state: AppState,
    message: &str,
    session: &str,
) -> (StatusCode, serde_json::Value) {
    let mut headers = HeaderMap::new();
    headers.insert("x-session-id", session.parse().unwrap());
    let response = handle_webhook(
        State(state),
        test_connect_info(),
        Query(WebhookQuery::default()),
        headers,
        Ok(Json(WebhookBody {
            message: message.into(),
            model: None,
            provider: None,
        })),
    )
    .await
    .into_response();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn wait_cancellation_marker(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("tool never started: {}", path.display()));
}

async fn assert_webhook_supersession(commands: &[&str], parallel: bool) {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("cancellation_fixture.py"),
            "import os,sys,time\nfrom pathlib import Path\nname=sys.argv[1]\nPath(name+'.pid').write_text(str(os.getpid()))\nPath(name+'.start').write_text('начало')\nif name.startswith('blocked'):\n while not Path('release').exists(): time.sleep(0.01)\nPath(name+'.end').write_text('конец')\nprint(name+'-done')\n").unwrap();
    let provider = Arc::new(CancellationFixtureProvider::new(commands, false));
    let state = make_test_state(provider.clone(), Arc::new(MockMemory));
    {
        let mut config = state.config.write();
        let profile = config.risk_profiles.get_mut("default").unwrap();
        profile.level = zeroclaw_config::autonomy::AutonomyLevel::Full;
        profile.allowed_commands = vec!["python3".into()];
        profile.auto_approve = vec!["shell".into()];
        profile.forbidden_paths.clear();
        config.agents.get_mut("default").unwrap().workspace.path =
            Some(workspace.path().to_path_buf());
        config.runtime_profiles.insert(
            "cancellation".into(),
            zeroclaw_config::schema::RuntimeProfileConfig {
                parallel_tools: Some(parallel),
                ..Default::default()
            },
        );
        config.agents.get_mut("default").unwrap().runtime_profile = "cancellation".into();
    }
    let first_state = state.clone();
    let mut first = ::zeroclaw_spawn::spawn!(async move {
        cancellation_webhook(first_state, "first", "tg_cancel").await
    });
    wait_cancellation_marker(&workspace.path().join("blocked.start")).await;
    if parallel {
        wait_cancellation_marker(&workspace.path().join("blocked2.start")).await;
    }
    let second_state = state.clone();
    let second = ::zeroclaw_spawn::spawn!(async move {
        cancellation_webhook(second_state, "second", "tg_cancel").await
    });
    let first_result = tokio::time::timeout(Duration::from_secs(2), &mut first).await;
    if first_result.is_err() {
        std::fs::write(workspace.path().join("release"), "cleanup").unwrap();
        let _ = first.await;
        let _ = second.await;
        panic!("superseded webhook must return cancelled before releasing the tool barrier");
    }
    let (status, body) = first_result.unwrap().unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "cancelled");
    assert!(!workspace.path().join("release").exists());
    assert!(
        !workspace.path().join("blocked.end").exists(),
        "cancelled shell must not reach its end marker"
    );
    assert!(
        !workspace.path().join("next.start").exists(),
        "superseded turn must not start another tool"
    );
    let (status, body) = second.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["response"], "successor-executed");
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        2,
        "only M1 and M2 may invoke the provider"
    );
    assert_eq!(provider.summaries.load(Ordering::SeqCst), 0);
    let session = state.webhook_session.lock().await;
    let history = &session.as_ref().unwrap().history;
    assert!(
        history
            .iter()
            .any(|m| m.content.contains("[turn cancelled]"))
    );
    assert!(
        history
            .iter()
            .any(|m| m.content.contains(&i18n::get_required_cli_string(
                "turn-tool-interrupted-before-result"
            )))
    );
    if commands.contains(&"completed") {
        assert!(workspace.path().join("completed.end").exists());
        assert!(
            history.iter().any(|m| m.content.contains("completed-done")),
            "completed result must survive supersession"
        );
    }
    assert!(state.cancel_tokens.lock().unwrap().is_empty());
}

#[tokio::test]
async fn webhook_supersession_interrupts_started_tool() {
    assert_webhook_supersession(&["blocked"], false).await;
}
#[tokio::test]
async fn webhook_supersession_does_not_start_next_tool() {
    assert_webhook_supersession(&["completed", "blocked", "next"], false).await;
}
#[tokio::test]
async fn webhook_supersession_parallel_batch() {
    assert_webhook_supersession(&["blocked", "blocked2"], true).await;
}

#[tokio::test]
async fn webhook_cancellation_drops_pending_pre_and_post_compression() {
    for pre_turn in [true, false] {
        let provider = Arc::new(CancellationFixtureProvider::new(&[], true));
        let state = make_test_state(provider.clone(), Arc::new(MockMemory));
        seed_cancellation_history(
            &state,
            if pre_turn {
                "previous-model"
            } else {
                "test-model"
            },
        )
        .await;
        let handle = register_cancel_token(&state, "tg_cancel");
        let token = handle.1.clone();
        let future_state = state.clone();
        let future_provider = provider.clone();
        let mut task = ::zeroclaw_spawn::spawn!(async move {
            run_gateway_webhook_agentic(
                &future_state,
                future_provider.as_ref(),
                "mock",
                "test-model",
                None,
                "cancel summarizer",
                Some("tg_cancel"),
                Some(handle),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(3), provider.summary_started.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        token.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
            panic!("cancellation must drop pending compression and release the session");
        }
        assert!(matches!(
            result.unwrap().unwrap().unwrap(),
            TurnOutcome::Cancelled
        ));
        assert!(provider.summary_dropped.load(Ordering::SeqCst));
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            usize::from(!pre_turn)
        );
        assert_eq!(provider.summaries.load(Ordering::SeqCst), 1);
        assert!(
            state
                .webhook_session
                .lock()
                .await
                .as_ref()
                .unwrap()
                .history
                .iter()
                .any(|m| m.content.contains("retained-question"))
        );
        assert!(state.cancel_tokens.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn webhook_second_lock_timeout_preserves_third_registration() {
    let provider = Arc::new(MockModelProvider::default());
    let mut state = make_test_state(provider.clone(), Arc::new(MockMemory));
    state.webhook_lock_timeout_secs = 1;
    let guard = state.webhook_session.lock().await;
    let first = register_cancel_token(&state, "tg_cancel");
    let second_state = state.clone();
    let second = ::zeroclaw_spawn::spawn!(async move {
        cancellation_webhook(second_state, "second", "tg_cancel").await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.cancel_token_seq.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let third_state = state.clone();
    let third = ::zeroclaw_spawn::spawn!(async move {
        cancellation_webhook(third_state, "third", "tg_cancel").await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.cancel_token_seq.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (status, body) = second.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error_code"], "previous_turn_stuck");
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert!(first.1.is_cancelled());
    {
        let tokens = state.cancel_tokens.lock().unwrap();
        let (id, token) = tokens.get("tg_cancel").unwrap();
        assert_eq!(*id, 3);
        assert!(!token.is_cancelled(), "M2 timeout must preserve M3 token");
    }
    drop(guard);
    let (status, body) = third.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "only M3 executes; M2 is never queued or retried"
    );
    assert!(state.cancel_tokens.lock().unwrap().is_empty());
}
