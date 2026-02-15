//! Tailscale Funnel/Serve tunnel provider.
//!
//! Uses `tailscale funnel` (public) or `tailscale serve` (tailnet-only)
//! to expose a local port. Discovers the hostname via `tailscale status --json`.

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::TailscaleTunnelConfig;
use crate::error::{Result, ZeptoError};
use crate::tunnel::types::TunnelProvider;

/// Tailscale Funnel/Serve tunnel provider.
pub struct TailscaleTunnel {
    config: TailscaleTunnelConfig,
    child: Option<Child>,
    url: Option<String>,
}

impl TailscaleTunnel {
    /// Create a new Tailscale tunnel provider.
    pub fn new(config: Option<TailscaleTunnelConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
            child: None,
            url: None,
        }
    }
}

/// Get the Tailscale hostname from `tailscale status --json`.
async fn get_tailscale_hostname() -> Result<String> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .await
        .map_err(|e| {
            ZeptoError::Config(format!(
                "Failed to run 'tailscale status --json' (is Tailscale installed?): {}",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ZeptoError::Config(format!(
            "tailscale status failed: {}",
            stderr.trim()
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| ZeptoError::Config(format!("Failed to parse tailscale status JSON: {}", e)))?;

    // Try Self.DNSName first, then Self.TailscaleIPs
    if let Some(self_node) = json.get("Self") {
        if let Some(dns_name) = self_node.get("DNSName").and_then(|d| d.as_str()) {
            // DNSName ends with a trailing dot, remove it
            let hostname = dns_name.trim_end_matches('.');
            if !hostname.is_empty() {
                return Ok(hostname.to_string());
            }
        }
    }

    Err(ZeptoError::Config(
        "Could not determine Tailscale hostname from status output".into(),
    ))
}

#[async_trait]
impl TunnelProvider for TailscaleTunnel {
    fn name(&self) -> &str {
        "tailscale"
    }

    async fn start(&mut self, local_port: u16) -> Result<String> {
        if self.child.is_some() {
            return Err(ZeptoError::Config(
                "Tailscale tunnel already running".into(),
            ));
        }

        let subcommand = if self.config.funnel {
            "funnel"
        } else {
            "serve"
        };

        info!("Starting tailscale {} on port {}", subcommand, local_port);

        let mut cmd = Command::new("tailscale");
        cmd.arg(subcommand).arg(local_port.to_string());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());

        let child = cmd.spawn().map_err(|e| {
            ZeptoError::Config(format!(
                "Failed to start 'tailscale {}' (is Tailscale installed?): {}",
                subcommand, e
            ))
        })?;

        self.child = Some(child);

        // Get the hostname to construct the URL
        let hostname = get_tailscale_hostname().await?;

        let url = format!("https://{}:{}", hostname, local_port);
        info!("Tailscale {} active: {}", subcommand, url);
        self.url = Some(url.clone());
        Ok(url)
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            info!("Stopping tailscale tunnel");
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        // Also turn off funnel/serve explicitly
        if self.config.funnel {
            let _ = Command::new("tailscale")
                .args(["funnel", "off"])
                .output()
                .await;
        } else {
            let _ = Command::new("tailscale")
                .args(["serve", "off"])
                .output()
                .await;
        }

        self.child = None;
        self.url = None;
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        match &self.child {
            Some(child) => Ok(child.id().is_some()),
            None => Ok(false),
        }
    }
}

impl Drop for TailscaleTunnel {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            warn!("TailscaleTunnel dropped while still running, killing child process");
            let _ = child.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default() {
        let tunnel = TailscaleTunnel::new(None);
        assert!(tunnel.config.funnel); // default is true
        assert!(tunnel.child.is_none());
        assert!(tunnel.url.is_none());
        assert_eq!(tunnel.name(), "tailscale");
    }

    #[test]
    fn test_new_with_config_funnel_false() {
        let config = TailscaleTunnelConfig { funnel: false };
        let tunnel = TailscaleTunnel::new(Some(config));
        assert!(!tunnel.config.funnel);
    }

    #[test]
    fn test_new_with_config_funnel_true() {
        let config = TailscaleTunnelConfig { funnel: true };
        let tunnel = TailscaleTunnel::new(Some(config));
        assert!(tunnel.config.funnel);
    }

    #[tokio::test]
    async fn test_health_check_no_child() {
        let tunnel = TailscaleTunnel::new(None);
        let result = tunnel.health_check().await.unwrap();
        assert!(!result);
    }
}
