//! ngrok tunnel provider.
//!
//! Uses the `ngrok` CLI to expose a local port and polls the local
//! ngrok API (`http://127.0.0.1:4040/api/tunnels`) to discover the
//! public URL.

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::NgrokTunnelConfig;
use crate::error::{Result, ZeptoError};
use crate::tunnel::types::TunnelProvider;

/// ngrok tunnel provider backed by the `ngrok` binary.
pub struct NgrokTunnel {
    config: Option<NgrokTunnelConfig>,
    child: Option<Child>,
    url: Option<String>,
}

impl NgrokTunnel {
    /// Create a new ngrok tunnel provider.
    pub fn new(config: Option<NgrokTunnelConfig>) -> Self {
        Self {
            config,
            child: None,
            url: None,
        }
    }
}

/// Fetch the public tunnel URL from the ngrok local API.
///
/// Polls `http://127.0.0.1:4040/api/tunnels` and extracts the first
/// tunnel's `public_url` field.
async fn fetch_ngrok_url(client: &reqwest::Client) -> Result<Option<String>> {
    let resp = client.get("http://127.0.0.1:4040/api/tunnels").send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.map_err(|e| {
                ZeptoError::Config(format!("Failed to parse ngrok API response: {}", e))
            })?;
            if let Some(tunnels) = body.get("tunnels").and_then(|t| t.as_array()) {
                for tunnel in tunnels {
                    if let Some(url) = tunnel.get("public_url").and_then(|u| u.as_str()) {
                        // Prefer https tunnel over http
                        if url.starts_with("https://") {
                            return Ok(Some(url.to_string()));
                        }
                    }
                }
                // Fall back to first tunnel URL (might be http)
                if let Some(first) = tunnels.first() {
                    if let Some(url) = first.get("public_url").and_then(|u| u.as_str()) {
                        return Ok(Some(url.to_string()));
                    }
                }
            }
            Ok(None)
        }
        Ok(_) => Ok(None),
        Err(_) => Ok(None), // API not ready yet
    }
}

#[async_trait]
impl TunnelProvider for NgrokTunnel {
    fn name(&self) -> &str {
        "ngrok"
    }

    async fn start(&mut self, local_port: u16) -> Result<String> {
        if self.child.is_some() {
            return Err(ZeptoError::Config("ngrok tunnel already running".into()));
        }

        let mut cmd = Command::new("ngrok");
        cmd.arg("http").arg(local_port.to_string());

        if let Some(ref cfg) = self.config {
            if let Some(ref authtoken) = cfg.authtoken {
                cmd.arg("--authtoken").arg(authtoken);
            }
            if let Some(ref domain) = cfg.domain {
                cmd.arg("--domain").arg(domain);
            }
        }

        // ngrok runs in the foreground, so we need to background it
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        cmd.stdin(std::process::Stdio::null());

        info!("Starting ngrok http tunnel on port {}", local_port);

        let child = cmd.spawn().map_err(|e| {
            ZeptoError::Config(format!("Failed to start ngrok (is it installed?): {}", e))
        })?;

        self.child = Some(child);

        // Poll the ngrok API for the tunnel URL
        let client = reqwest::Client::new();
        let url = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                match fetch_ngrok_url(&client).await? {
                    Some(url) => return Ok::<String, ZeptoError>(url),
                    None => continue,
                }
            }
        })
        .await
        .map_err(|_| ZeptoError::Config("Timed out waiting for ngrok tunnel URL (15s)".into()))??;

        info!("ngrok tunnel active: {}", url);
        self.url = Some(url.clone());
        Ok(url)
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            info!("Stopping ngrok tunnel");
            let _ = child.kill().await;
            let _ = child.wait().await;
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

impl Drop for NgrokTunnel {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            warn!("NgrokTunnel dropped while still running, killing child process");
            let _ = child.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default() {
        let tunnel = NgrokTunnel::new(None);
        assert!(tunnel.config.is_none());
        assert!(tunnel.child.is_none());
        assert!(tunnel.url.is_none());
        assert_eq!(tunnel.name(), "ngrok");
    }

    #[test]
    fn test_new_with_config() {
        let config = NgrokTunnelConfig {
            authtoken: Some("tok_abc".into()),
            domain: Some("my.ngrok.io".into()),
        };
        let tunnel = NgrokTunnel::new(Some(config));
        assert!(tunnel.config.is_some());
        let cfg = tunnel.config.as_ref().unwrap();
        assert_eq!(cfg.authtoken.as_deref(), Some("tok_abc"));
        assert_eq!(cfg.domain.as_deref(), Some("my.ngrok.io"));
    }

    #[tokio::test]
    async fn test_health_check_no_child() {
        let tunnel = NgrokTunnel::new(None);
        let result = tunnel.health_check().await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_fetch_ngrok_url_no_server() {
        // When ngrok is not running, the fetch should return None (not error)
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let result = fetch_ngrok_url(&client).await.unwrap();
        assert!(result.is_none());
    }
}
