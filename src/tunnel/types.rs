//! Tunnel provider trait and types.
//!
//! Defines the `TunnelProvider` async trait for exposing local ports
//! via public tunnel URLs (Cloudflare, ngrok, Tailscale, etc.).

use async_trait::async_trait;

use crate::error::Result;

/// Trait implemented by all tunnel providers.
///
/// Each provider manages a child process that creates a public URL
/// pointing to a local port. The lifecycle is: `start()` -> use URL -> `stop()`.
#[async_trait]
pub trait TunnelProvider: Send + Sync {
    /// Human-readable provider name (e.g., "cloudflare", "ngrok", "tailscale").
    fn name(&self) -> &str;

    /// Start the tunnel and return the public URL.
    ///
    /// Spawns the provider binary, waits for it to output a URL,
    /// and returns the public endpoint.
    async fn start(&mut self, local_port: u16) -> Result<String>;

    /// Stop the tunnel and clean up resources.
    ///
    /// Kills the child process and performs any provider-specific teardown.
    async fn stop(&mut self) -> Result<()>;

    /// Check whether the tunnel process is still alive and healthy.
    async fn health_check(&self) -> Result<bool>;
}
