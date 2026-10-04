use super::ModelProvider;
use super::dispatch::{
    ProviderDispatch, mark_current_dispatch_composite, stream_as_dispatch_composite,
};
use super::reliable::ProviderCandidateDescriptor;
use super::traits::{
    ChatMessage, ChatRequest, ChatResponse, StreamChunk, StreamEvent, StreamOptions, StreamResult,
};
use async_trait::async_trait;
use futures_util::stream::BoxStream;

pub struct ModelPinnedProvider {
    descriptor: ProviderCandidateDescriptor,
    inner: Box<dyn ModelProvider>,
}

impl ModelPinnedProvider {
    pub fn new(descriptor: ProviderCandidateDescriptor, inner: Box<dyn ModelProvider>) -> Self {
        assert!(
            descriptor.pinned_model().is_some(),
            "ModelPinnedProvider requires a pinned candidate descriptor"
        );
        Self { descriptor, inner }
    }

    fn pinned_model(&self) -> &str {
        self.descriptor
            .pinned_model()
            .expect("validated by ModelPinnedProvider::new")
    }
}

#[async_trait]
impl ModelProvider for ModelPinnedProvider {
    fn has_stable_request_identity(&self, model: &str) -> bool {
        model == self.pinned_model() && self.inner.has_stable_request_identity(self.pinned_model())
    }

    fn capabilities(&self) -> super::traits::ProviderCapabilities {
        self.inner.capabilities()
    }

    fn capabilities_for_model(&self, _model: &str) -> super::traits::ProviderCapabilities {
        self.inner.capabilities_for_model(self.pinned_model())
    }

    fn vision_limited_by(&self, _model: &str) -> Option<String> {
        self.inner.vision_limited_by(self.pinned_model())
    }

    fn has_mixed_native_tool_support_for_model(&self, _model: &str) -> bool {
        self.inner
            .has_mixed_native_tool_support_for_model(self.pinned_model())
    }

    fn default_temperature(&self) -> f64 {
        self.inner.default_temperature()
    }

    fn default_max_tokens(&self) -> u32 {
        self.inner.default_max_tokens()
    }

    fn default_timeout_secs(&self) -> u64 {
        self.inner.default_timeout_secs()
    }

    fn default_base_url(&self) -> Option<&str> {
        self.inner.default_base_url()
    }

    fn default_wire_api(&self) -> &str {
        self.inner.default_wire_api()
    }

    fn convert_tools(&self, tools: &[zeroclaw_api::tool::ToolSpec]) -> super::traits::ToolsPayload {
        self.inner.convert_tools(tools)
    }

    fn supports_native_tools(&self) -> bool {
        self.inner.supports_native_tools()
    }

    fn supports_vision(&self) -> bool {
        self.inner.supports_vision()
    }

    fn supports_reasoning_only_history(&self) -> bool {
        self.inner.supports_reasoning_only_history()
    }

    // fork(#52)
    fn delegate_turns_should_stream(&self) -> bool {
        self.inner.delegate_turns_should_stream()
    }

    fn supports_streaming(&self) -> bool {
        self.inner.supports_streaming()
    }

    fn supports_streaming_tool_events(&self) -> bool {
        self.inner.supports_streaming_tool_events()
    }

    async fn list_models(&self) -> anyhow::Result<Vec<String>> {
        ProviderDispatch::from_ref(&*self.inner).list_models().await
    }

    async fn warmup(&self) -> anyhow::Result<()> {
        ProviderDispatch::from_ref(&*self.inner).warmup().await
    }

    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        _model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        mark_current_dispatch_composite();
        ProviderDispatch::from_ref(&*self.inner)
            .chat_with_system(system_prompt, message, self.pinned_model(), temperature)
            .await
    }

    async fn chat_with_history(
        &self,
        messages: &[ChatMessage],
        _model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<String> {
        mark_current_dispatch_composite();
        ProviderDispatch::from_ref(&*self.inner)
            .chat_with_history(messages, self.pinned_model(), temperature)
            .await
    }

    async fn chat(
        &self,
        request: ChatRequest<'_>,
        _model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        mark_current_dispatch_composite();
        ProviderDispatch::from_ref(&*self.inner)
            .chat(request, self.pinned_model(), temperature)
            .await
    }

    async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[serde_json::Value],
        _model: &str,
        temperature: Option<f64>,
    ) -> anyhow::Result<ChatResponse> {
        mark_current_dispatch_composite();
        ProviderDispatch::from_ref(&*self.inner)
            .chat_with_tools(messages, tools, self.pinned_model(), temperature)
            .await
    }

    fn stream_chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        _model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> BoxStream<'static, StreamResult<StreamChunk>> {
        stream_as_dispatch_composite(
            ProviderDispatch::from_ref(&*self.inner).stream_chat_with_system(
                system_prompt,
                message,
                self.pinned_model(),
                temperature,
                options,
            ),
        )
    }

    fn stream_chat_with_history(
        &self,
        messages: &[ChatMessage],
        _model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> BoxStream<'static, StreamResult<StreamChunk>> {
        stream_as_dispatch_composite(
            ProviderDispatch::from_ref(&*self.inner).stream_chat_with_history(
                messages,
                self.pinned_model(),
                temperature,
                options,
            ),
        )
    }

    fn stream_chat(
        &self,
        request: ChatRequest<'_>,
        _model: &str,
        temperature: Option<f64>,
        options: StreamOptions,
    ) -> BoxStream<'static, StreamResult<StreamEvent>> {
        stream_as_dispatch_composite(ProviderDispatch::from_ref(&*self.inner).stream_chat(
            request,
            self.pinned_model(),
            temperature,
            options,
        ))
    }
}

impl zeroclaw_api::attribution::Attributable for ModelPinnedProvider {
    fn role(&self) -> zeroclaw_api::attribution::Role {
        self.inner.role()
    }
    fn alias(&self) -> &str {
        self.descriptor.actual_provider()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use zeroclaw_api::model_provider::ModelProvider;

    struct ReasoningHistoryMock(bool);

    #[async_trait]
    impl ModelProvider for ReasoningHistoryMock {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(String::new())
        }

        fn supports_reasoning_only_history(&self) -> bool {
            self.0
        }

        fn delegate_turns_should_stream(&self) -> bool {
            self.0
        }
    }
    impl ::zeroclaw_api::attribution::Attributable for ReasoningHistoryMock {
        fn role(&self) -> ::zeroclaw_api::attribution::Role {
            ::zeroclaw_api::attribution::Role::Provider(
                ::zeroclaw_api::attribution::ProviderKind::Model(
                    ::zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }
        fn alias(&self) -> &str {
            "ReasoningHistoryMock"
        }
    }

    fn pinned(inner: bool) -> ModelPinnedProvider {
        ModelPinnedProvider::new(
            ProviderCandidateDescriptor::pinned("deepseek", Some("pro"), "deepseek-v4-pro"),
            Box::new(ReasoningHistoryMock(inner)),
        )
    }

    // Fork patch #33: aliases that pin `model` (deepseek.pro, custom.cline_qwen)
    // are wrapped here; without the forward the capability is silently false and
    // the producer patch never reaches production.
    #[test]
    fn model_pin_forwards_reasoning_only_history() {
        assert!(pinned(true).supports_reasoning_only_history());
        assert!(!pinned(false).supports_reasoning_only_history());
    }

    #[test]
    fn arc_blanket_forwards_reasoning_only_history() {
        let provider: Arc<dyn ModelProvider> = Arc::new(ReasoningHistoryMock(true));
        assert!(provider.supports_reasoning_only_history());
        let provider: Arc<dyn ModelProvider> = Arc::new(ReasoningHistoryMock(false));
        assert!(!provider.supports_reasoning_only_history());
    }

    #[test]
    fn model_pin_and_arc_forward_delegate_turns_should_stream() {
        assert!(pinned(true).delegate_turns_should_stream());
        assert!(!pinned(false).delegate_turns_should_stream());
        let provider: Arc<dyn ModelProvider> = Arc::new(ReasoningHistoryMock(true));
        assert!(provider.delegate_turns_should_stream());
        let provider: Arc<dyn ModelProvider> = Arc::new(ReasoningHistoryMock(false));
        assert!(!provider.delegate_turns_should_stream());
    }

    use crate::traits::ProviderCapabilities;

    struct ModelAwareCapabilityProvider;

    impl zeroclaw_api::attribution::Attributable for ModelAwareCapabilityProvider {
        fn role(&self) -> zeroclaw_api::attribution::Role {
            zeroclaw_api::attribution::Role::Provider(
                zeroclaw_api::attribution::ProviderKind::Model(
                    zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }

        fn alias(&self) -> &str {
            "model_aware_capability"
        }
    }

    #[async_trait]
    impl ModelProvider for ModelAwareCapabilityProvider {
        fn capabilities_for_model(&self, model: &str) -> ProviderCapabilities {
            ProviderCapabilities {
                native_tool_calling: model == "pinned-model",
                ..ProviderCapabilities::default()
            }
        }

        fn vision_limited_by(&self, model: &str) -> Option<String> {
            (model == "pinned-model").then(|| "fallback.alias".to_string())
        }

        fn has_mixed_native_tool_support_for_model(&self, model: &str) -> bool {
            model == "pinned-model"
        }

        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok(String::new())
        }
    }

    #[test]
    fn capability_queries_use_the_pinned_model() {
        let provider = ModelPinnedProvider::new(
            ProviderCandidateDescriptor::pinned("custom", Some("pinned"), "pinned-model"),
            Box::new(ModelAwareCapabilityProvider),
        );

        assert!(
            provider
                .capabilities_for_model("ignored-request-model")
                .native_tool_calling,
            "model-aware capabilities must be queried with the pinned model"
        );
        assert!(
            provider.has_mixed_native_tool_support_for_model("ignored-request-model"),
            "mixed-chain detection must be queried with the pinned model"
        );
        assert_eq!(
            provider
                .vision_limited_by("ignored-request-model")
                .as_deref(),
            Some("fallback.alias"),
            "vision attribution must be queried with the pinned model"
        );
    }

    struct AccountedLeaf;

    impl zeroclaw_api::attribution::Attributable for AccountedLeaf {
        fn role(&self) -> zeroclaw_api::attribution::Role {
            zeroclaw_api::attribution::Role::Provider(
                zeroclaw_api::attribution::ProviderKind::Model(
                    zeroclaw_api::attribution::ModelProviderKind::Custom,
                ),
            )
        }

        fn alias(&self) -> &str {
            "configured.inner"
        }
    }

    #[async_trait]
    impl ModelProvider for AccountedLeaf {
        async fn chat_with_system(
            &self,
            _system_prompt: Option<&str>,
            _message: &str,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<String> {
            Ok("ok".to_string())
        }

        async fn chat(
            &self,
            _request: ChatRequest<'_>,
            _model: &str,
            _temperature: Option<f64>,
        ) -> anyhow::Result<ChatResponse> {
            Ok(ChatResponse {
                text: Some("ok".to_string()),
                tool_calls: Vec::new(),
                usage: None,
                reasoning_content: None,
            })
        }
    }

    #[tokio::test]
    async fn accounting_through_model_pin_keeps_inner_identity_and_pinned_model() {
        let pinned = ModelPinnedProvider::new(
            ProviderCandidateDescriptor::pinned("custom", Some("pin-wrapper"), "served-model"),
            Box::new(AccountedLeaf),
        );
        let messages = vec![ChatMessage::user("hello")];
        let outcome = ProviderDispatch::from_ref(&pinned)
            .chat_accounted_outcome(
                ChatRequest {
                    messages: &messages,
                    tools: None,
                    thinking: None,
                },
                "requested-model",
                None,
            )
            .await;

        assert!(outcome.result.is_ok());
        assert_eq!(outcome.accounting.attempts().len(), 1);
        let leaf = &outcome.accounting.attempts()[0];
        assert_eq!(
            (leaf.provider_ref(), leaf.model()),
            ("configured.inner", "served-model")
        );
    }
}
