//! Providers module - LLM providers (OpenAI, Anthropic, etc.)
//!
//! This module defines the `LLMProvider` trait and common types for
//! interacting with various LLM providers. Each provider (OpenAI, Claude, etc.)
//! implements the `LLMProvider` trait to provide a consistent interface.
//!
//! # Example
//!
//! ```rust,ignore
//! use zeptoclaw::providers::{LLMProvider, ChatOptions, ToolDefinition};
//! use zeptoclaw::providers::claude::ClaudeProvider;
//! use zeptoclaw::session::Message;
//!
//! async fn example() {
//!     let provider = ClaudeProvider::new("your-api-key");
//!     let messages = vec![Message::user("Hello!")];
//!     let options = ChatOptions::new().with_max_tokens(1000);
//!
//!     let response = provider.chat(messages, vec![], None, options).await.unwrap();
//!     println!("Response: {}", response.content);
//! }
//! ```

pub mod claude;
pub mod fallback;
pub mod openai;
mod registry;
pub mod retry;
mod types;

/// Provider IDs currently supported by the runtime.
pub const RUNTIME_SUPPORTED_PROVIDERS: &[&str] = &["anthropic", "openai"];

pub use claude::ClaudeProvider;
pub use fallback::FallbackProvider;
pub use openai::OpenAIProvider;
pub use registry::{
    configured_provider_names, configured_unsupported_provider_names, resolve_runtime_provider,
    ProviderSpec, RuntimeProviderSelection, PROVIDER_REGISTRY,
};
pub use retry::RetryProvider;
pub use types::{
    ChatOptions, LLMProvider, LLMResponse, LLMToolCall, StreamEvent, ToolDefinition, Usage,
};
