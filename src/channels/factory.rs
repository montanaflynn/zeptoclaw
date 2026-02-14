//! Channel factory/registration helpers.

use std::sync::Arc;

use tracing::{info, warn};

use crate::bus::MessageBus;
use crate::config::Config;

use super::webhook::{WebhookChannel, WebhookChannelConfig};
use super::WhatsAppChannel;
use super::{BaseChannelConfig, ChannelManager, DiscordChannel, SlackChannel, TelegramChannel};

/// Register all configured channels that currently have implementations.
///
/// Returns the number of registered channels.
pub async fn register_configured_channels(
    manager: &ChannelManager,
    bus: Arc<MessageBus>,
    config: &Config,
) -> usize {
    // Telegram
    if let Some(ref telegram_config) = config.channels.telegram {
        if telegram_config.enabled {
            if telegram_config.token.is_empty() {
                warn!("Telegram channel enabled but token is empty");
            } else {
                manager
                    .register(Box::new(TelegramChannel::new(
                        telegram_config.clone(),
                        bus.clone(),
                    )))
                    .await;
                info!("Registered Telegram channel");
            }
        }
    }

    // Slack
    if let Some(ref slack_config) = config.channels.slack {
        if slack_config.enabled {
            if slack_config.bot_token.is_empty() {
                warn!("Slack channel enabled but bot token is empty");
            } else {
                manager
                    .register(Box::new(SlackChannel::new(
                        slack_config.clone(),
                        bus.clone(),
                    )))
                    .await;
                info!("Registered Slack channel");
            }
        }
    }

    // Discord
    if let Some(ref discord_config) = config.channels.discord {
        if discord_config.enabled {
            if discord_config.token.is_empty() {
                warn!("Discord channel enabled but token is empty");
            } else {
                manager
                    .register(Box::new(DiscordChannel::new(
                        discord_config.clone(),
                        bus.clone(),
                    )))
                    .await;
                info!("Registered Discord channel");
            }
        }
    }
    // Webhook
    if let Some(ref webhook_config) = config.channels.webhook {
        if webhook_config.enabled {
            let runtime_config = WebhookChannelConfig {
                bind_address: webhook_config.bind_address.clone(),
                port: webhook_config.port,
                path: webhook_config.path.clone(),
                auth_token: webhook_config.auth_token.clone(),
            };
            let base_config = BaseChannelConfig {
                name: "webhook".to_string(),
                allowlist: webhook_config.allow_from.clone(),
            };
            manager
                .register(Box::new(WebhookChannel::new(
                    runtime_config,
                    base_config,
                    bus.clone(),
                )))
                .await;
            info!(
                "Registered Webhook channel on {}:{}",
                webhook_config.bind_address, webhook_config.port
            );
        }
    }

    // WhatsApp (via bridge)
    if let Some(ref whatsapp_config) = config.channels.whatsapp {
        if whatsapp_config.enabled {
            if whatsapp_config.bridge_url.is_empty() {
                warn!("WhatsApp channel enabled but bridge_url is empty");
            } else {
                manager
                    .register(Box::new(WhatsAppChannel::new(
                        whatsapp_config.clone(),
                        bus.clone(),
                    )))
                    .await;
                info!("Registered WhatsApp channel");
            }
        }
    }
    if config
        .channels
        .feishu
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false)
    {
        warn!("Feishu channel is enabled but not implemented");
    }
    if config
        .channels
        .maixcam
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false)
    {
        warn!("MaixCam channel is enabled but not implemented");
    }
    if config
        .channels
        .qq
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false)
    {
        warn!("QQ channel is enabled but not implemented");
    }
    if config
        .channels
        .dingtalk
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false)
    {
        warn!("DingTalk channel is enabled but not implemented");
    }

    manager.channel_count().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::MessageBus;
    use crate::config::{Config, SlackConfig, TelegramConfig, WhatsAppConfig};

    #[tokio::test]
    async fn test_register_configured_channels_registers_telegram() {
        let bus = Arc::new(MessageBus::new());
        let mut config = Config::default();
        config.channels.telegram = Some(TelegramConfig {
            enabled: true,
            token: "test-token".to_string(),
            allow_from: Vec::new(),
        });

        let manager = ChannelManager::new(bus.clone(), config.clone());
        let count = register_configured_channels(&manager, bus, &config).await;

        assert_eq!(count, 1);
        assert!(manager.has_channel("telegram").await);
    }

    #[tokio::test]
    async fn test_register_configured_channels_registers_whatsapp() {
        let bus = Arc::new(MessageBus::new());
        let mut config = Config::default();
        config.channels.whatsapp = Some(WhatsAppConfig {
            enabled: true,
            bridge_url: "ws://localhost:3001".to_string(),
            allow_from: Vec::new(),
        });

        let manager = ChannelManager::new(bus.clone(), config.clone());
        let count = register_configured_channels(&manager, bus, &config).await;

        assert_eq!(count, 1);
        assert!(manager.has_channel("whatsapp").await);
    }

    #[tokio::test]
    async fn test_register_configured_channels_registers_slack() {
        let bus = Arc::new(MessageBus::new());
        let mut config = Config::default();
        config.channels.slack = Some(SlackConfig {
            enabled: true,
            bot_token: "xoxb-test-token".to_string(),
            app_token: String::new(),
            allow_from: Vec::new(),
        });

        let manager = ChannelManager::new(bus.clone(), config.clone());
        let count = register_configured_channels(&manager, bus, &config).await;

        assert_eq!(count, 1);
        assert!(manager.has_channel("slack").await);
    }
}
