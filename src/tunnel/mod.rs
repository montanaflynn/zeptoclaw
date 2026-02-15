//! Tunnel module for exposing local ports via public URLs.
//!
//! Supports three providers:
//! - **Cloudflare** (`cloudflared`) — free quick tunnels or named tunnels with token
//! - **ngrok** — free or paid tunnels with optional custom domains
//! - **Tailscale** (`tailscale funnel/serve`) — Tailscale Funnel (public) or Serve (tailnet-only)
//!
//! # Usage
//!
//! ```rust,no_run
//! use zeptoclaw::tunnel::{create_tunnel, TunnelProvider};
//! use zeptoclaw::config::TunnelConfig;
//!
//! # async fn example() -> zeptoclaw::error::Result<()> {
//! let config = TunnelConfig::default();
//! let mut tunnel = create_tunnel(&config)?;
//! let url = tunnel.start(8080).await?;
//! println!("Public URL: {}", url);
//! tunnel.stop().await?;
//! # Ok(())
//! # }
//! ```

pub mod cloudflare;
pub mod ngrok;
pub mod tailscale;
pub mod types;

pub use cloudflare::CloudflareTunnel;
pub use ngrok::NgrokTunnel;
pub use tailscale::TailscaleTunnel;
pub use types::TunnelProvider;

use crate::config::TunnelConfig;
use crate::error::{Result, ZeptoError};

use tracing::info;

/// Create a tunnel provider based on the configuration.
///
/// If `provider` is set to `"auto"` or `None`, attempts to auto-detect
/// which tunnel binary is available on `PATH`.
pub fn create_tunnel(config: &TunnelConfig) -> Result<Box<dyn TunnelProvider>> {
    let provider_name = config.provider.as_deref().unwrap_or("auto");

    match provider_name {
        "cloudflare" => {
            info!("Using Cloudflare tunnel provider");
            Ok(Box::new(CloudflareTunnel::new(config.cloudflare.clone())))
        }
        "ngrok" => {
            info!("Using ngrok tunnel provider");
            Ok(Box::new(NgrokTunnel::new(config.ngrok.clone())))
        }
        "tailscale" => {
            info!("Using Tailscale tunnel provider");
            Ok(Box::new(TailscaleTunnel::new(config.tailscale.clone())))
        }
        "auto" => {
            info!("Auto-detecting tunnel provider");
            auto_detect(config)
        }
        other => Err(ZeptoError::Config(format!(
            "Unknown tunnel provider '{}'. Supported: cloudflare, ngrok, tailscale, auto",
            other
        ))),
    }
}

/// Auto-detect the best available tunnel provider by checking which
/// binary is on `PATH`.
///
/// Priority order: cloudflared > ngrok > tailscale
fn auto_detect(config: &TunnelConfig) -> Result<Box<dyn TunnelProvider>> {
    if which("cloudflared") {
        info!("Auto-detected cloudflared on PATH");
        return Ok(Box::new(CloudflareTunnel::new(config.cloudflare.clone())));
    }
    if which("ngrok") {
        info!("Auto-detected ngrok on PATH");
        return Ok(Box::new(NgrokTunnel::new(config.ngrok.clone())));
    }
    if which("tailscale") {
        info!("Auto-detected tailscale on PATH");
        return Ok(Box::new(TailscaleTunnel::new(config.tailscale.clone())));
    }

    Err(ZeptoError::Config(
        "No tunnel provider found on PATH. Install one of: cloudflared, ngrok, tailscale".into(),
    ))
}

/// Check if a binary is available on `PATH` using `which` / `where`.
fn which(binary: &str) -> bool {
    std::process::Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tunnel_cloudflare() {
        let config = TunnelConfig {
            provider: Some("cloudflare".into()),
            ..Default::default()
        };
        let tunnel = create_tunnel(&config).unwrap();
        assert_eq!(tunnel.name(), "cloudflare");
    }

    #[test]
    fn test_create_tunnel_ngrok() {
        let config = TunnelConfig {
            provider: Some("ngrok".into()),
            ..Default::default()
        };
        let tunnel = create_tunnel(&config).unwrap();
        assert_eq!(tunnel.name(), "ngrok");
    }

    #[test]
    fn test_create_tunnel_tailscale() {
        let config = TunnelConfig {
            provider: Some("tailscale".into()),
            ..Default::default()
        };
        let tunnel = create_tunnel(&config).unwrap();
        assert_eq!(tunnel.name(), "tailscale");
    }

    #[test]
    fn test_create_tunnel_unknown_provider() {
        let config = TunnelConfig {
            provider: Some("teleport".into()),
            ..Default::default()
        };
        let result = create_tunnel(&config);
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("Unknown tunnel provider"), "got: {}", msg);
                assert!(msg.contains("teleport"), "got: {}", msg);
            }
            Ok(_) => panic!("expected error for unknown provider"),
        }
    }

    #[test]
    fn test_create_tunnel_auto_fallback() {
        // Auto-detect might or might not find a binary depending on the
        // test environment. We just verify it doesn't panic.
        let config = TunnelConfig {
            provider: Some("auto".into()),
            ..Default::default()
        };
        let result = create_tunnel(&config);
        // Either succeeds (binary found) or returns a config error (none found)
        match result {
            Ok(tunnel) => {
                assert!(["cloudflare", "ngrok", "tailscale"].contains(&tunnel.name()));
            }
            Err(e) => {
                assert!(e.to_string().contains("No tunnel provider found"));
            }
        }
    }

    #[test]
    fn test_create_tunnel_none_provider_uses_auto() {
        let config = TunnelConfig::default();
        assert!(config.provider.is_none());
        // Should use auto-detect path
        let result = create_tunnel(&config);
        match result {
            Ok(tunnel) => {
                assert!(["cloudflare", "ngrok", "tailscale"].contains(&tunnel.name()));
            }
            Err(e) => {
                assert!(e.to_string().contains("No tunnel provider found"));
            }
        }
    }

    #[test]
    fn test_which_nonexistent_binary() {
        assert!(!which("zeptoclaw_nonexistent_binary_12345"));
    }

    #[test]
    fn test_which_existing_binary() {
        // `ls` or `echo` should exist on all Unix systems
        if cfg!(unix) {
            assert!(which("ls"));
        }
    }
}
