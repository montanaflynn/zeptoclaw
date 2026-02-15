//! Channel trait and types for ZeptoClaw
//!
//! This module defines the `Channel` trait that all communication channels
//! (Telegram, Discord, Slack, etc.) must implement, along with supporting types.

use async_trait::async_trait;

use crate::bus::OutboundMessage;
use crate::error::Result;

/// The `Channel` trait defines the interface for all communication channels.
///
/// Channels are responsible for:
/// - Receiving messages from users and publishing them to the message bus
/// - Sending outbound messages from agents back to users
/// - Managing their connection lifecycle (start/stop)
/// - Enforcing access control via allowlists
///
/// # Example Implementation
///
/// ```ignore
/// use async_trait::async_trait;
/// use zeptoclaw::channels::{Channel, BaseChannelConfig};
/// use zeptoclaw::bus::OutboundMessage;
/// use zeptoclaw::error::Result;
///
/// struct MyChannel {
///     config: BaseChannelConfig,
///     running: bool,
/// }
///
/// #[async_trait]
/// impl Channel for MyChannel {
///     fn name(&self) -> &str {
///         &self.config.name
///     }
///
///     async fn start(&mut self) -> Result<()> {
///         self.running = true;
///         Ok(())
///     }
///
///     async fn stop(&mut self) -> Result<()> {
///         self.running = false;
///         Ok(())
///     }
///
///     async fn send(&self, msg: OutboundMessage) -> Result<()> {
///         println!("Sending: {}", msg.content);
///         Ok(())
///     }
///
///     fn is_running(&self) -> bool {
///         self.running
///     }
///
///     fn is_allowed(&self, user_id: &str) -> bool {
///         self.config.is_allowed(user_id)
///     }
/// }
/// ```
#[async_trait]
pub trait Channel: Send + Sync {
    /// Returns the unique name of this channel (e.g., "telegram", "discord").
    ///
    /// This name is used for routing messages and logging purposes.
    fn name(&self) -> &str;

    /// Starts the channel, establishing connections and beginning to listen
    /// for incoming messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel fails to start (e.g., invalid token,
    /// network failure, etc.).
    async fn start(&mut self) -> Result<()>;

    /// Stops the channel, cleaning up resources and closing connections.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel fails to stop cleanly.
    async fn stop(&mut self) -> Result<()>;

    /// Sends an outbound message through this channel.
    ///
    /// # Arguments
    ///
    /// * `msg` - The outbound message to send
    ///
    /// # Errors
    ///
    /// Returns an error if the message fails to send (e.g., network failure,
    /// invalid chat ID, rate limiting, etc.).
    async fn send(&self, msg: OutboundMessage) -> Result<()>;

    /// Returns whether the channel is currently running and accepting messages.
    fn is_running(&self) -> bool;

    /// Checks if a user is allowed to use this channel.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier of the user
    ///
    /// # Returns
    ///
    /// `true` if the user is allowed, `false` otherwise.
    fn is_allowed(&self, user_id: &str) -> bool;
}

/// Base configuration shared by all channels.
///
/// This struct provides common configuration options that most channels need,
/// including the channel name and an allowlist for access control.
///
/// # Access Control Modes
///
/// - **Open mode** (`deny_by_default: false`, the default): An empty allowlist
///   means all senders are permitted.
/// - **Strict mode** (`deny_by_default: true`): An empty allowlist means
///   *no* senders are permitted — every sender must be explicitly listed.
///
/// # Example
///
/// ```
/// use zeptoclaw::channels::BaseChannelConfig;
///
/// let config = BaseChannelConfig {
///     name: "telegram".to_string(),
///     allowlist: vec!["user123".to_string(), "user456".to_string()],
///     ..Default::default()
/// };
///
/// assert!(config.is_allowed("user123"));
/// assert!(!config.is_allowed("user789"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct BaseChannelConfig {
    /// The unique name of this channel
    pub name: String,
    /// List of allowed user IDs. If empty, behaviour depends on `deny_by_default`.
    pub allowlist: Vec<String>,
    /// When `true`, an empty allowlist rejects all senders (strict mode).
    /// When `false` (the default), an empty allowlist allows all senders.
    pub deny_by_default: bool,
}

impl BaseChannelConfig {
    /// Creates a new `BaseChannelConfig` with the given name and an empty allowlist.
    ///
    /// An empty allowlist means all users are allowed (`deny_by_default` is `false`).
    ///
    /// # Arguments
    ///
    /// * `name` - The unique name for this channel
    ///
    /// # Example
    ///
    /// ```
    /// use zeptoclaw::channels::BaseChannelConfig;
    ///
    /// let config = BaseChannelConfig::new("telegram");
    /// assert!(config.is_allowed("anyone")); // Empty allowlist = allow all
    /// ```
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            allowlist: Vec::new(),
            deny_by_default: false,
        }
    }

    /// Creates a new `BaseChannelConfig` with the given name and allowlist.
    ///
    /// # Arguments
    ///
    /// * `name` - The unique name for this channel
    /// * `allowlist` - List of allowed user IDs
    ///
    /// # Example
    ///
    /// ```
    /// use zeptoclaw::channels::BaseChannelConfig;
    ///
    /// let config = BaseChannelConfig::with_allowlist("telegram", vec!["user1".to_string()]);
    /// assert!(config.is_allowed("user1"));
    /// assert!(!config.is_allowed("user2"));
    /// ```
    pub fn with_allowlist(name: &str, allowlist: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            allowlist,
            deny_by_default: false,
        }
    }

    /// Checks if a user is allowed based on the allowlist and `deny_by_default`.
    ///
    /// | `deny_by_default` | Allowlist empty | Behaviour            |
    /// |-------------------|-----------------|----------------------|
    /// | `false` (default) | yes             | Allow all senders    |
    /// | `false`           | no              | Check allowlist      |
    /// | `true`            | yes             | **Reject all**       |
    /// | `true`            | no              | Check allowlist      |
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier of the user to check
    ///
    /// # Example
    ///
    /// ```
    /// use zeptoclaw::channels::BaseChannelConfig;
    ///
    /// // With allowlist
    /// let config = BaseChannelConfig {
    ///     name: "test".to_string(),
    ///     allowlist: vec!["user1".to_string()],
    ///     ..Default::default()
    /// };
    /// assert!(config.is_allowed("user1"));
    /// assert!(!config.is_allowed("user2"));
    ///
    /// // Empty allowlist = allow all (default mode)
    /// let open_config = BaseChannelConfig::new("test");
    /// assert!(open_config.is_allowed("anyone"));
    ///
    /// // Strict mode: empty allowlist = reject all
    /// let strict = BaseChannelConfig {
    ///     name: "test".to_string(),
    ///     deny_by_default: true,
    ///     ..Default::default()
    /// };
    /// assert!(!strict.is_allowed("anyone"));
    /// ```
    pub fn is_allowed(&self, user_id: &str) -> bool {
        if self.allowlist.is_empty() {
            // Empty allowlist: allow all unless deny_by_default is on
            !self.deny_by_default
        } else {
            self.allowlist.contains(&user_id.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_channel_config_new() {
        let config = BaseChannelConfig::new("telegram");
        assert_eq!(config.name, "telegram");
        assert!(config.allowlist.is_empty());
    }

    #[test]
    fn test_base_channel_config_with_allowlist() {
        let config = BaseChannelConfig::with_allowlist(
            "discord",
            vec!["user1".to_string(), "user2".to_string()],
        );
        assert_eq!(config.name, "discord");
        assert_eq!(config.allowlist.len(), 2);
    }

    #[test]
    fn test_base_channel_config() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec!["user1".to_string()],
            ..Default::default()
        };
        assert!(config.is_allowed("user1"));
        assert!(!config.is_allowed("user2"));
    }

    #[test]
    fn test_empty_allowlist() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec![],
            ..Default::default()
        };
        assert!(config.is_allowed("anyone")); // empty allowlist = allow all
    }

    #[test]
    fn test_allowlist_with_multiple_users() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec![
                "user1".to_string(),
                "user2".to_string(),
                "user3".to_string(),
            ],
            ..Default::default()
        };
        assert!(config.is_allowed("user1"));
        assert!(config.is_allowed("user2"));
        assert!(config.is_allowed("user3"));
        assert!(!config.is_allowed("user4"));
    }

    #[test]
    fn test_base_channel_config_default() {
        let config = BaseChannelConfig::default();
        assert!(config.name.is_empty());
        assert!(config.allowlist.is_empty());
        assert!(!config.deny_by_default);
        assert!(config.is_allowed("anyone"));
    }

    #[test]
    fn test_base_channel_config_clone() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec!["user1".to_string()],
            ..Default::default()
        };
        let cloned = config.clone();
        assert_eq!(cloned.name, "test");
        assert_eq!(cloned.allowlist, vec!["user1"]);
    }

    // ---- deny_by_default tests ----

    #[test]
    fn test_deny_by_default_empty_allowlist_rejects() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec![],
            deny_by_default: true,
        };
        assert!(!config.is_allowed("anyone"));
    }

    #[test]
    fn test_deny_by_default_with_allowlist_checks() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec!["user1".to_string()],
            deny_by_default: true,
        };
        assert!(config.is_allowed("user1"));
        assert!(!config.is_allowed("user2"));
    }

    #[test]
    fn test_deny_by_default_false_allows_all() {
        let config = BaseChannelConfig {
            name: "test".to_string(),
            allowlist: vec![],
            deny_by_default: false,
        };
        assert!(config.is_allowed("anyone"));
    }

    #[test]
    fn test_deny_by_default_defaults_to_false() {
        let config = BaseChannelConfig::new("test");
        assert!(!config.deny_by_default);
        assert!(config.is_allowed("anyone"));
    }
}
