//! Tool types for ZeptoClaw
//!
//! This module defines the core types for tool execution, including the `Tool` trait
//! that all tools must implement, and the `ToolContext` struct that provides
//! execution context to tools.

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;

/// Trait that all tools must implement.
///
/// Tools are executable functions that the LLM can call to perform actions
/// like searching the web, reading files, or interacting with external services.
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use serde_json::Value;
/// use zeptoclaw::tools::{Tool, ToolContext};
/// use zeptoclaw::error::Result;
///
/// struct MyTool;
///
/// #[async_trait]
/// impl Tool for MyTool {
///     fn name(&self) -> &str { "my_tool" }
///     fn description(&self) -> &str { "Does something useful" }
///     fn parameters(&self) -> Value {
///         serde_json::json!({
///             "type": "object",
///             "properties": {},
///             "required": []
///         })
///     }
///     async fn execute(&self, _args: Value, _ctx: &ToolContext) -> Result<String> {
///         Ok("Done!".to_string())
///     }
/// }
/// ```
#[async_trait]
pub trait Tool: Send + Sync {
    /// Get the tool name.
    ///
    /// This name is used to identify the tool when the LLM requests it.
    /// It should be unique within a registry.
    fn name(&self) -> &str;

    /// Get the tool description.
    ///
    /// This description is sent to the LLM to help it understand
    /// when and how to use the tool.
    fn description(&self) -> &str;

    /// Get the JSON schema for the tool's parameters.
    ///
    /// This schema describes what arguments the tool accepts.
    /// It follows the JSON Schema specification.
    fn parameters(&self) -> Value;

    /// Execute the tool with the given arguments.
    ///
    /// # Arguments
    /// * `args` - The JSON arguments passed by the LLM
    /// * `ctx` - The execution context (channel, chat_id, workspace, etc.)
    ///
    /// # Returns
    /// A string result that will be sent back to the LLM.
    async fn execute(&self, args: Value, ctx: &ToolContext) -> Result<String>;

    /// Get a compact (shorter) description for token-constrained environments.
    ///
    /// Defaults to the full description. Override in individual tools for
    /// shorter versions (~40% token savings).
    fn compact_description(&self) -> &str {
        self.description()
    }
}

/// Context provided to tools during execution.
///
/// This struct contains information about the execution environment,
/// such as which channel/chat the request came from and the workspace.
#[derive(Debug, Clone, Default)]
pub struct ToolContext {
    /// The channel name (e.g., "telegram", "discord", "cli")
    pub channel: Option<String>,
    /// The chat/conversation ID within the channel
    pub chat_id: Option<String>,
    /// The workspace directory for file operations
    pub workspace: Option<String>,
}

impl ToolContext {
    /// Create a new empty tool context.
    ///
    /// # Example
    /// ```
    /// use zeptoclaw::tools::ToolContext;
    ///
    /// let ctx = ToolContext::new();
    /// assert!(ctx.channel.is_none());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the channel and chat ID.
    ///
    /// # Arguments
    /// * `channel` - The channel name (e.g., "telegram")
    /// * `chat_id` - The chat/conversation ID
    ///
    /// # Example
    /// ```
    /// use zeptoclaw::tools::ToolContext;
    ///
    /// let ctx = ToolContext::new()
    ///     .with_channel("telegram", "123456");
    /// assert_eq!(ctx.channel.as_deref(), Some("telegram"));
    /// assert_eq!(ctx.chat_id.as_deref(), Some("123456"));
    /// ```
    pub fn with_channel(mut self, channel: &str, chat_id: &str) -> Self {
        self.channel = Some(channel.to_string());
        self.chat_id = Some(chat_id.to_string());
        self
    }

    /// Set the workspace directory.
    ///
    /// # Arguments
    /// * `workspace` - The workspace directory path
    ///
    /// # Example
    /// ```
    /// use zeptoclaw::tools::ToolContext;
    ///
    /// let ctx = ToolContext::new()
    ///     .with_workspace("/home/user/project");
    /// assert_eq!(ctx.workspace.as_deref(), Some("/home/user/project"));
    /// ```
    pub fn with_workspace(mut self, workspace: &str) -> Self {
        self.workspace = Some(workspace.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_context_new() {
        let ctx = ToolContext::new();
        assert!(ctx.channel.is_none());
        assert!(ctx.chat_id.is_none());
        assert!(ctx.workspace.is_none());
    }

    #[test]
    fn test_tool_context_default() {
        let ctx = ToolContext::default();
        assert!(ctx.channel.is_none());
        assert!(ctx.chat_id.is_none());
        assert!(ctx.workspace.is_none());
    }

    #[test]
    fn test_tool_context_with_channel() {
        let ctx = ToolContext::new().with_channel("telegram", "123456");
        assert_eq!(ctx.channel.as_deref(), Some("telegram"));
        assert_eq!(ctx.chat_id.as_deref(), Some("123456"));
        assert!(ctx.workspace.is_none());
    }

    #[test]
    fn test_tool_context_with_workspace() {
        let ctx = ToolContext::new().with_workspace("/home/user/project");
        assert!(ctx.channel.is_none());
        assert!(ctx.chat_id.is_none());
        assert_eq!(ctx.workspace.as_deref(), Some("/home/user/project"));
    }

    #[test]
    fn test_tool_context_builder_chain() {
        let ctx = ToolContext::new()
            .with_channel("discord", "abc123")
            .with_workspace("/tmp/workspace");

        assert_eq!(ctx.channel.as_deref(), Some("discord"));
        assert_eq!(ctx.chat_id.as_deref(), Some("abc123"));
        assert_eq!(ctx.workspace.as_deref(), Some("/tmp/workspace"));
    }

    #[test]
    fn test_tool_context_debug() {
        let ctx = ToolContext::new().with_channel("cli", "test");
        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("ToolContext"));
        assert!(debug_str.contains("cli"));
    }

    #[test]
    fn test_tool_context_clone() {
        let ctx1 = ToolContext::new()
            .with_channel("telegram", "123")
            .with_workspace("/test");
        let ctx2 = ctx1.clone();

        assert_eq!(ctx1.channel, ctx2.channel);
        assert_eq!(ctx1.chat_id, ctx2.chat_id);
        assert_eq!(ctx1.workspace, ctx2.workspace);
    }
}
