//! Fallback LLM provider for ZeptoClaw
//!
//! This module provides a [`FallbackProvider`] that chains two LLM providers:
//! if the primary provider fails, the request is automatically retried against
//! a secondary (fallback) provider. This is useful for high-availability
//! configurations where one provider may experience intermittent outages.
//!
//! # Example
//!
//! ```rust,ignore
//! use zeptoclaw::providers::fallback::FallbackProvider;
//! use zeptoclaw::providers::claude::ClaudeProvider;
//! use zeptoclaw::providers::openai::OpenAIProvider;
//!
//! let primary = Box::new(ClaudeProvider::new("claude-key"));
//! let fallback = Box::new(OpenAIProvider::new("openai-key"));
//! let provider = FallbackProvider::new(primary, fallback);
//! // If Claude fails, the request is automatically retried against OpenAI.
//! ```

use std::fmt;

use async_trait::async_trait;
use tracing::warn;

use crate::error::Result;
use crate::session::Message;

use super::{ChatOptions, LLMProvider, LLMResponse, StreamEvent, ToolDefinition};

/// A provider that chains a primary and a fallback LLM provider.
///
/// When a request to the primary provider fails, the error is logged and the
/// same request is forwarded to the fallback provider. If both providers fail,
/// the fallback provider's error is returned (as the more recent failure).
pub struct FallbackProvider {
    primary: Box<dyn LLMProvider>,
    fallback: Box<dyn LLMProvider>,
    /// Pre-computed composite name in the form `"primary -> fallback"`.
    composite_name: String,
}

impl fmt::Debug for FallbackProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FallbackProvider")
            .field("primary", &self.primary.name())
            .field("fallback", &self.fallback.name())
            .finish()
    }
}

impl FallbackProvider {
    /// Create a new fallback provider.
    ///
    /// # Arguments
    /// * `primary` - The preferred provider, tried first for every request.
    /// * `fallback` - The backup provider, used only when the primary fails.
    pub fn new(primary: Box<dyn LLMProvider>, fallback: Box<dyn LLMProvider>) -> Self {
        let composite_name = format!("{} -> {}", primary.name(), fallback.name());
        Self {
            primary,
            fallback,
            composite_name,
        }
    }
}

#[async_trait]
impl LLMProvider for FallbackProvider {
    fn name(&self) -> &str {
        &self.composite_name
    }

    fn default_model(&self) -> &str {
        self.primary.default_model()
    }

    async fn chat(
        &self,
        messages: Vec<Message>,
        tools: Vec<ToolDefinition>,
        model: Option<&str>,
        options: ChatOptions,
    ) -> Result<LLMResponse> {
        match self
            .primary
            .chat(messages.clone(), tools.clone(), model, options.clone())
            .await
        {
            Ok(response) => Ok(response),
            Err(primary_err) => {
                warn!(
                    primary = self.primary.name(),
                    fallback = self.fallback.name(),
                    error = %primary_err,
                    "Primary provider failed, falling back"
                );
                self.fallback.chat(messages, tools, model, options).await
            }
        }
    }

    async fn chat_stream(
        &self,
        messages: Vec<Message>,
        tools: Vec<ToolDefinition>,
        model: Option<&str>,
        options: ChatOptions,
    ) -> Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        match self
            .primary
            .chat_stream(messages.clone(), tools.clone(), model, options.clone())
            .await
        {
            Ok(receiver) => Ok(receiver),
            Err(primary_err) => {
                warn!(
                    primary = self.primary.name(),
                    fallback = self.fallback.name(),
                    error = %primary_err,
                    "Primary provider streaming failed, falling back"
                );
                self.fallback
                    .chat_stream(messages, tools, model, options)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ZeptoError;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // ---------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------

    /// A provider that always returns a successful response.
    struct SuccessProvider {
        name: &'static str,
    }

    impl fmt::Debug for SuccessProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SuccessProvider")
                .field("name", &self.name)
                .finish()
        }
    }

    #[async_trait]
    impl LLMProvider for SuccessProvider {
        fn name(&self) -> &str {
            self.name
        }

        fn default_model(&self) -> &str {
            "success-model-v1"
        }

        async fn chat(
            &self,
            _messages: Vec<Message>,
            _tools: Vec<ToolDefinition>,
            _model: Option<&str>,
            _options: ChatOptions,
        ) -> Result<LLMResponse> {
            Ok(LLMResponse::text(&format!("success from {}", self.name)))
        }
    }

    /// A provider that always returns an error.
    struct FailProvider {
        name: &'static str,
    }

    impl fmt::Debug for FailProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FailProvider")
                .field("name", &self.name)
                .finish()
        }
    }

    #[async_trait]
    impl LLMProvider for FailProvider {
        fn name(&self) -> &str {
            self.name
        }

        fn default_model(&self) -> &str {
            "fail-model-v1"
        }

        async fn chat(
            &self,
            _messages: Vec<Message>,
            _tools: Vec<ToolDefinition>,
            _model: Option<&str>,
            _options: ChatOptions,
        ) -> Result<LLMResponse> {
            Err(ZeptoError::Provider("provider failed".into()))
        }
    }

    /// A provider that counts how many times `chat()` is called and returns success.
    struct CountingProvider {
        name: &'static str,
        call_count: Arc<AtomicU32>,
    }

    impl fmt::Debug for CountingProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CountingProvider")
                .field("name", &self.name)
                .field("call_count", &self.call_count.load(Ordering::SeqCst))
                .finish()
        }
    }

    #[async_trait]
    impl LLMProvider for CountingProvider {
        fn name(&self) -> &str {
            self.name
        }

        fn default_model(&self) -> &str {
            "counting-model-v1"
        }

        async fn chat(
            &self,
            _messages: Vec<Message>,
            _tools: Vec<ToolDefinition>,
            _model: Option<&str>,
            _options: ChatOptions,
        ) -> Result<LLMResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(LLMResponse::text(&format!("success from {}", self.name)))
        }
    }

    // ---------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_fallback_provider_name() {
        let provider = FallbackProvider::new(
            Box::new(SuccessProvider { name: "alpha" }),
            Box::new(SuccessProvider { name: "beta" }),
        );

        assert_eq!(provider.name(), "alpha -> beta");
    }

    #[test]
    fn test_fallback_provider_default_model() {
        let provider = FallbackProvider::new(
            Box::new(SuccessProvider { name: "primary" }),
            Box::new(SuccessProvider { name: "fallback" }),
        );

        // Should delegate to primary's default_model.
        assert_eq!(provider.default_model(), "success-model-v1");
    }

    #[tokio::test]
    async fn test_fallback_uses_primary_when_available() {
        let provider = FallbackProvider::new(
            Box::new(SuccessProvider { name: "primary" }),
            Box::new(SuccessProvider { name: "fallback" }),
        );

        let response = provider
            .chat(vec![], vec![], None, ChatOptions::default())
            .await
            .expect("primary should succeed");

        assert_eq!(response.content, "success from primary");
    }

    #[tokio::test]
    async fn test_fallback_uses_secondary_on_primary_failure() {
        let provider = FallbackProvider::new(
            Box::new(FailProvider { name: "primary" }),
            Box::new(SuccessProvider { name: "fallback" }),
        );

        let response = provider
            .chat(vec![], vec![], None, ChatOptions::default())
            .await
            .expect("fallback should succeed after primary failure");

        assert_eq!(response.content, "success from fallback");
    }

    #[tokio::test]
    async fn test_fallback_returns_error_when_both_fail() {
        let provider = FallbackProvider::new(
            Box::new(FailProvider { name: "primary" }),
            Box::new(FailProvider { name: "fallback" }),
        );

        let result = provider
            .chat(vec![], vec![], None, ChatOptions::default())
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ZeptoError::Provider(_)),
            "expected Provider error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_fallback_primary_not_called_twice() {
        let call_count = Arc::new(AtomicU32::new(0));

        let provider = FallbackProvider::new(
            Box::new(CountingProvider {
                name: "primary",
                call_count: Arc::clone(&call_count),
            }),
            Box::new(SuccessProvider { name: "fallback" }),
        );

        let response = provider
            .chat(vec![], vec![], None, ChatOptions::default())
            .await
            .expect("primary should succeed");

        assert_eq!(response.content, "success from primary");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "primary should be called exactly once"
        );
    }
}
