//! Configuration management for ZeptoClaw
//!
//! This module provides configuration loading, saving, and global state management.
//! Configuration is loaded from `~/.zeptoclaw/config.json` with environment variable overrides.

mod types;

pub use types::*;

use crate::error::{PicoError, Result};
use once_cell::sync::OnceCell;
use std::path::PathBuf;
use std::sync::RwLock;

/// Global configuration instance
static CONFIG: OnceCell<RwLock<Config>> = OnceCell::new();

impl Config {
    /// Returns the ZeptoClaw configuration directory path (~/.zeptoclaw)
    pub fn dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zeptoclaw")
    }

    /// Returns the path to the config file (~/.zeptoclaw/config.json)
    pub fn path() -> PathBuf {
        Self::dir().join("config.json")
    }

    /// Load configuration from the default path with environment overrides.
    ///
    /// If the config file doesn't exist, returns default configuration.
    /// Environment variables can override config values using the pattern:
    /// `ZEPTOCLAW_SECTION_SUBSECTION_KEY`
    pub fn load() -> Result<Self> {
        Self::load_from_path(&Self::path())
    }

    /// Load configuration from a specific path with environment overrides.
    pub fn load_from_path(path: &PathBuf) -> Result<Self> {
        let mut config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            serde_json::from_str(&content)?
        } else {
            Config::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides to the configuration.
    ///
    /// Environment variables follow the pattern: ZEPTOCLAW_SECTION_SUBSECTION_KEY
    fn apply_env_overrides(&mut self) {
        // Agent defaults
        if let Ok(val) = std::env::var("ZEPTOCLAW_AGENTS_DEFAULTS_WORKSPACE") {
            self.agents.defaults.workspace = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_AGENTS_DEFAULTS_MODEL") {
            self.agents.defaults.model = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_AGENTS_DEFAULTS_MAX_TOKENS") {
            if let Ok(v) = val.parse() {
                self.agents.defaults.max_tokens = v;
            }
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_AGENTS_DEFAULTS_TEMPERATURE") {
            if let Ok(v) = val.parse() {
                self.agents.defaults.temperature = v;
            }
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_AGENTS_DEFAULTS_MAX_TOOL_ITERATIONS") {
            if let Ok(v) = val.parse() {
                self.agents.defaults.max_tool_iterations = v;
            }
        }

        // Gateway
        if let Ok(val) = std::env::var("ZEPTOCLAW_GATEWAY_HOST") {
            self.gateway.host = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_GATEWAY_PORT") {
            if let Ok(v) = val.parse() {
                self.gateway.port = v;
            }
        }

        // Provider API keys
        self.apply_provider_env_overrides();

        // Channel overrides
        self.apply_channel_env_overrides();

        // Tool-specific overrides
        self.apply_tool_env_overrides();
    }

    /// Apply provider-specific environment variable overrides
    fn apply_provider_env_overrides(&mut self) {
        // Anthropic
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY") {
            let provider = self
                .providers
                .anthropic
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_BASE") {
            let provider = self
                .providers
                .anthropic
                .get_or_insert_with(ProviderConfig::default);
            provider.api_base = Some(val);
        }

        // OpenAI
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_OPENAI_API_KEY") {
            let provider = self
                .providers
                .openai
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_OPENAI_API_BASE") {
            let provider = self
                .providers
                .openai
                .get_or_insert_with(ProviderConfig::default);
            provider.api_base = Some(val);
        }

        // OpenRouter
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_OPENROUTER_API_KEY") {
            let provider = self
                .providers
                .openrouter
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_OPENROUTER_API_BASE") {
            let provider = self
                .providers
                .openrouter
                .get_or_insert_with(ProviderConfig::default);
            provider.api_base = Some(val);
        }

        // Groq
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_GROQ_API_KEY") {
            let provider = self
                .providers
                .groq
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }

        // Zhipu
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_ZHIPU_API_KEY") {
            let provider = self
                .providers
                .zhipu
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_ZHIPU_API_BASE") {
            let provider = self
                .providers
                .zhipu
                .get_or_insert_with(ProviderConfig::default);
            provider.api_base = Some(val);
        }

        // Gemini
        if let Ok(val) = std::env::var("ZEPTOCLAW_PROVIDERS_GEMINI_API_KEY") {
            let provider = self
                .providers
                .gemini
                .get_or_insert_with(ProviderConfig::default);
            provider.api_key = Some(val);
        }
    }

    /// Apply channel-specific environment variable overrides
    fn apply_channel_env_overrides(&mut self) {
        // Telegram
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_TELEGRAM_TOKEN") {
            let channel = self
                .channels
                .telegram
                .get_or_insert_with(TelegramConfig::default);
            channel.token = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_TELEGRAM_ENABLED") {
            if let Ok(enabled) = val.parse() {
                let channel = self
                    .channels
                    .telegram
                    .get_or_insert_with(TelegramConfig::default);
                channel.enabled = enabled;
            }
        }

        // Discord
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_DISCORD_TOKEN") {
            let channel = self
                .channels
                .discord
                .get_or_insert_with(DiscordConfig::default);
            channel.token = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_DISCORD_ENABLED") {
            if let Ok(enabled) = val.parse() {
                let channel = self
                    .channels
                    .discord
                    .get_or_insert_with(DiscordConfig::default);
                channel.enabled = enabled;
            }
        }

        // Slack
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_SLACK_BOT_TOKEN") {
            let channel = self.channels.slack.get_or_insert_with(SlackConfig::default);
            channel.bot_token = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_SLACK_APP_TOKEN") {
            let channel = self.channels.slack.get_or_insert_with(SlackConfig::default);
            channel.app_token = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_SLACK_ENABLED") {
            if let Ok(enabled) = val.parse() {
                let channel = self.channels.slack.get_or_insert_with(SlackConfig::default);
                channel.enabled = enabled;
            }
        }

        // WhatsApp
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_WHATSAPP_BRIDGE_URL") {
            let channel = self
                .channels
                .whatsapp
                .get_or_insert_with(WhatsAppConfig::default);
            channel.bridge_url = val;
        }
        if let Ok(val) = std::env::var("ZEPTOCLAW_CHANNELS_WHATSAPP_ENABLED") {
            if let Ok(enabled) = val.parse() {
                let channel = self
                    .channels
                    .whatsapp
                    .get_or_insert_with(WhatsAppConfig::default);
                channel.enabled = enabled;
            }
        }
    }

    /// Apply tool-specific environment variable overrides
    fn apply_tool_env_overrides(&mut self) {
        // Web search API key (prefer explicit tool-scoped variable).
        if let Ok(val) = std::env::var("ZEPTOCLAW_TOOLS_WEB_SEARCH_API_KEY") {
            self.tools.web.search.api_key = Some(val);
        } else if let Ok(val) = std::env::var("ZEPTOCLAW_INTEGRATIONS_BRAVE_API_KEY") {
            self.tools.web.search.api_key = Some(val);
        } else if let Ok(val) = std::env::var("BRAVE_API_KEY") {
            self.tools.web.search.api_key = Some(val);
        }

        if let Ok(val) = std::env::var("ZEPTOCLAW_TOOLS_WEB_SEARCH_MAX_RESULTS") {
            if let Ok(v) = val.parse::<u32>() {
                self.tools.web.search.max_results = v.clamp(1, 10);
            }
        }
    }

    /// Save configuration to the default path
    pub fn save(&self) -> Result<()> {
        self.save_to_path(&Self::path())
    }

    /// Save configuration to a specific path
    pub fn save_to_path(&self, path: &PathBuf) -> Result<()> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Initialize the global configuration.
    ///
    /// This should be called once at startup. Subsequent calls will return
    /// an error if the config is already initialized.
    pub fn init() -> Result<()> {
        let config = Self::load()?;
        CONFIG
            .set(RwLock::new(config))
            .map_err(|_| PicoError::Config("Configuration already initialized".to_string()))
    }

    /// Initialize the global configuration with a specific config.
    ///
    /// Useful for testing or custom initialization.
    pub fn init_with(config: Config) -> Result<()> {
        CONFIG
            .set(RwLock::new(config))
            .map_err(|_| PicoError::Config("Configuration already initialized".to_string()))
    }

    /// Get a clone of the current global configuration.
    ///
    /// Returns default configuration if not yet initialized.
    pub fn get() -> Config {
        CONFIG
            .get()
            .and_then(|lock| lock.read().ok())
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Update the global configuration.
    ///
    /// Returns an error if the config hasn't been initialized yet.
    pub fn update<F>(f: F) -> Result<()>
    where
        F: FnOnce(&mut Config),
    {
        let lock = CONFIG
            .get()
            .ok_or_else(|| PicoError::Config("Configuration not initialized".to_string()))?;
        let mut guard = lock
            .write()
            .map_err(|_| PicoError::Config("Failed to acquire config write lock".to_string()))?;
        f(&mut guard);
        Ok(())
    }

    /// Returns the expanded workspace path (resolves ~ to home directory)
    pub fn workspace_path(&self) -> PathBuf {
        expand_home(&self.agents.defaults.workspace)
    }

    /// Get the first available API key from configured providers.
    ///
    /// Checks providers in order: OpenRouter, Anthropic, OpenAI, Gemini, Zhipu, Groq
    pub fn get_api_key(&self) -> Option<String> {
        // Check providers in priority order
        let providers = [
            &self.providers.openrouter,
            &self.providers.anthropic,
            &self.providers.openai,
            &self.providers.gemini,
            &self.providers.zhipu,
            &self.providers.groq,
        ];

        for config in providers.into_iter().flatten() {
            if let Some(ref key) = config.api_key {
                if !key.is_empty() {
                    return Some(key.clone());
                }
            }
        }
        None
    }

    /// Get the API base URL for the first configured provider.
    pub fn get_api_base(&self) -> Option<String> {
        // OpenRouter
        if let Some(ref config) = self.providers.openrouter {
            if config
                .api_key
                .as_ref()
                .map(|k| !k.is_empty())
                .unwrap_or(false)
            {
                return config
                    .api_base
                    .clone()
                    .or_else(|| Some("https://openrouter.ai/api/v1".to_string()));
            }
        }

        // Zhipu
        if let Some(ref config) = self.providers.zhipu {
            if config
                .api_key
                .as_ref()
                .map(|k| !k.is_empty())
                .unwrap_or(false)
            {
                return config.api_base.clone();
            }
        }

        // VLLM
        if let Some(ref config) = self.providers.vllm {
            if config
                .api_key
                .as_ref()
                .map(|k| !k.is_empty())
                .unwrap_or(false)
            {
                return config.api_base.clone();
            }
        }

        None
    }
}

/// Expand ~ to home directory in a path string
fn expand_home(path: &str) -> PathBuf {
    if path.is_empty() {
        return PathBuf::from(path);
    }

    if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            if path.len() > 1 && path.chars().nth(1) == Some('/') {
                return home.join(&path[2..]);
            }
            return home;
        }
    }

    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.agents.defaults.model, "claude-sonnet-4-5-20250929");
        assert_eq!(config.agents.defaults.max_tokens, 8096);
        assert_eq!(config.agents.defaults.temperature, 0.7);
        assert_eq!(config.agents.defaults.max_tool_iterations, 20);
        assert_eq!(config.agents.defaults.workspace, "~/.zeptoclaw/workspace");
        assert_eq!(config.gateway.host, "0.0.0.0");
        assert_eq!(config.gateway.port, 8080);
        assert_eq!(config.runtime.runtime_type, RuntimeType::Native);
        assert!(!config.runtime.allow_fallback_to_native);
    }

    #[test]
    fn test_config_from_json() {
        let json = r#"{"agents": {"defaults": {"model": "gpt-4", "max_tokens": 4096}}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.agents.defaults.model, "gpt-4");
        assert_eq!(config.agents.defaults.max_tokens, 4096);
        // Defaults should apply to unspecified fields
        assert_eq!(config.agents.defaults.temperature, 0.7);
        assert_eq!(config.gateway.port, 8080);
    }

    #[test]
    fn test_config_to_json() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("claude-sonnet-4-5-20250929"));
        assert!(json.contains("8096"));
    }

    #[test]
    fn test_config_partial_json() {
        // Test that partial JSON works with defaults
        let json = r#"{"gateway": {"port": 9090}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.gateway.port, 9090);
        assert_eq!(config.gateway.host, "0.0.0.0"); // Default
        assert_eq!(config.agents.defaults.model, "claude-sonnet-4-5-20250929"); // Default
    }

    #[test]
    fn test_expand_home() {
        let home = dirs::home_dir().unwrap();

        // Test ~ expansion
        let expanded = expand_home("~/.zeptoclaw");
        assert_eq!(expanded, home.join(".zeptoclaw"));

        // Test ~/path expansion
        let expanded = expand_home("~/some/path");
        assert_eq!(expanded, home.join("some/path"));

        // Test absolute path (no expansion)
        let expanded = expand_home("/absolute/path");
        assert_eq!(expanded, PathBuf::from("/absolute/path"));

        // Test relative path (no expansion)
        let expanded = expand_home("relative/path");
        assert_eq!(expanded, PathBuf::from("relative/path"));

        // Test empty path
        let expanded = expand_home("");
        assert_eq!(expanded, PathBuf::from(""));
    }

    #[test]
    fn test_workspace_path() {
        let config = Config::default();
        let workspace = config.workspace_path();
        let home = dirs::home_dir().unwrap();
        assert_eq!(workspace, home.join(".zeptoclaw/workspace"));
    }

    #[test]
    fn test_config_dir() {
        let dir = Config::dir();
        let home = dirs::home_dir().unwrap();
        assert_eq!(dir, home.join(".zeptoclaw"));
    }

    #[test]
    fn test_config_path() {
        let path = Config::path();
        let home = dirs::home_dir().unwrap();
        assert_eq!(path, home.join(".zeptoclaw/config.json"));
    }

    #[test]
    fn test_channel_configs() {
        let json = r#"{
            "channels": {
                "telegram": {
                    "enabled": true,
                    "token": "bot123:ABC",
                    "allow_from": ["user1", "user2"]
                },
                "discord": {
                    "enabled": false,
                    "token": "discord-token"
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();

        let telegram = config.channels.telegram.unwrap();
        assert!(telegram.enabled);
        assert_eq!(telegram.token, "bot123:ABC");
        assert_eq!(telegram.allow_from, vec!["user1", "user2"]);

        let discord = config.channels.discord.unwrap();
        assert!(!discord.enabled);
        assert_eq!(discord.token, "discord-token");
    }

    #[test]
    fn test_provider_configs() {
        let json = r#"{
            "providers": {
                "anthropic": {
                    "api_key": "sk-ant-xxx"
                },
                "openai": {
                    "api_key": "sk-xxx",
                    "api_base": "https://api.openai.com/v1"
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();

        let anthropic = config.providers.anthropic.unwrap();
        assert_eq!(anthropic.api_key, Some("sk-ant-xxx".to_string()));

        let openai = config.providers.openai.unwrap();
        assert_eq!(openai.api_key, Some("sk-xxx".to_string()));
        assert_eq!(
            openai.api_base,
            Some("https://api.openai.com/v1".to_string())
        );
    }

    #[test]
    fn test_get_api_key() {
        let mut config = Config::default();

        // No API keys configured
        assert!(config.get_api_key().is_none());

        // Add OpenAI key
        config.providers.openai = Some(ProviderConfig {
            api_key: Some("openai-key".to_string()),
            ..Default::default()
        });
        assert_eq!(config.get_api_key(), Some("openai-key".to_string()));

        // OpenRouter has higher priority
        config.providers.openrouter = Some(ProviderConfig {
            api_key: Some("openrouter-key".to_string()),
            ..Default::default()
        });
        assert_eq!(config.get_api_key(), Some("openrouter-key".to_string()));
    }

    #[test]
    fn test_env_override() {
        // Set env var
        env::set_var("ZEPTOCLAW_AGENTS_DEFAULTS_MODEL", "test-model");
        env::set_var("ZEPTOCLAW_AGENTS_DEFAULTS_MAX_TOKENS", "1000");
        env::set_var("BRAVE_API_KEY", "test-brave-key");
        env::set_var("ZEPTOCLAW_TOOLS_WEB_SEARCH_MAX_RESULTS", "9");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.agents.defaults.model, "test-model");
        assert_eq!(config.agents.defaults.max_tokens, 1000);
        assert_eq!(
            config.tools.web.search.api_key,
            Some("test-brave-key".to_string())
        );
        assert_eq!(config.tools.web.search.max_results, 9);

        // Clean up
        env::remove_var("ZEPTOCLAW_AGENTS_DEFAULTS_MODEL");
        env::remove_var("ZEPTOCLAW_AGENTS_DEFAULTS_MAX_TOKENS");
        env::remove_var("BRAVE_API_KEY");
        env::remove_var("ZEPTOCLAW_TOOLS_WEB_SEARCH_MAX_RESULTS");
    }

    #[test]
    fn test_tools_config() {
        let json = r#"{
            "tools": {
                "web": {
                    "search": {
                        "api_key": "search-key",
                        "max_results": 10
                    }
                }
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();

        assert_eq!(
            config.tools.web.search.api_key,
            Some("search-key".to_string())
        );
        assert_eq!(config.tools.web.search.max_results, 10);
    }

    #[test]
    fn test_tools_config_defaults() {
        let config = Config::default();
        assert!(config.tools.web.search.api_key.is_none());
        assert_eq!(config.tools.web.search.max_results, 5);
    }

    #[test]
    fn test_save_and_load() {
        use std::fs;

        // Create a temp directory
        let temp_dir = std::env::temp_dir().join("zeptoclaw_test");
        fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("config.json");

        // Create and save config
        let mut config = Config::default();
        config.agents.defaults.model = "test-model".to_string();
        config.gateway.port = 9999;
        config.save_to_path(&config_path).unwrap();

        // Load and verify
        let loaded = Config::load_from_path(&config_path).unwrap();
        assert_eq!(loaded.agents.defaults.model, "test-model");
        assert_eq!(loaded.gateway.port, 9999);

        // Clean up
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_load_nonexistent() {
        let path = PathBuf::from("/nonexistent/path/config.json");
        let config = Config::load_from_path(&path).unwrap();

        // Should return defaults
        assert_eq!(config.agents.defaults.model, "claude-sonnet-4-5-20250929");
    }
}
