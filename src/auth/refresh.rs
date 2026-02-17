//! Token refresh logic for OAuth access tokens.
//!
//! Handles automatic refresh of expired access tokens using stored
//! refresh tokens, with fallback behavior when refresh fails.

use tracing::{info, warn};

use std::future::Future;
use std::pin::Pin;

use crate::error::{Result, ZeptoError};

use super::store::TokenStore;
use super::OAuthTokenSet;

/// Seconds before expiry to trigger a proactive refresh.
pub const REFRESH_BUFFER_SECS: i64 = 300; // 5 minutes

/// Ensure the stored token for a provider is fresh.
///
/// Returns the access token if valid, or attempts to refresh it.
/// Updates the store with new tokens if refresh succeeds.
///
/// # Errors
///
/// Returns `Err` if the token is expired and cannot be refreshed.
pub async fn ensure_fresh_token(store: &TokenStore, provider: &str) -> Result<String> {
    ensure_fresh_token_with(store, provider, |token_url, refresh_token, client_id| {
        Box::pin(refresh_access_token(token_url, refresh_token, client_id))
    })
    .await
}

async fn ensure_fresh_token_with<F>(
    store: &TokenStore,
    provider: &str,
    refresh_fn: F,
) -> Result<String>
where
    F: for<'a> Fn(
        &'a str,
        &'a str,
        &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RefreshedTokens>> + 'a>>,
{
    let token = store
        .load(provider)?
        .ok_or_else(|| ZeptoError::Config(format!("No OAuth token stored for '{}'", provider)))?;

    // Token is still valid (not expiring soon)
    if !token.expires_within(REFRESH_BUFFER_SECS) {
        return Ok(token.access_token);
    }

    // Token is expired or expiring soon — try refresh
    info!(
        provider = provider,
        "OAuth token expiring soon, attempting refresh"
    );

    let refresh_token = match token.refresh_token.as_deref() {
        Some(v) => v,
        None => {
            if token.is_expired() {
                return Err(ZeptoError::Config(format!(
                    "OAuth token for '{}' is expired and no refresh token is available",
                    provider
                )));
            }
            warn!(
                provider = provider,
                "OAuth token is expiring soon but no refresh token is available; using existing token"
            );
            return Ok(token.access_token);
        }
    };

    let client_id = match token.client_id.as_deref() {
        Some(v) => v,
        None => {
            if token.is_expired() {
                return Err(ZeptoError::Config(format!(
                    "OAuth token for '{}' is expired and missing client_id; re-authenticate to store a valid client id",
                    provider
                )));
            }
            warn!(
                provider = provider,
                "OAuth token is expiring soon but client_id is missing; using existing token"
            );
            return Ok(token.access_token);
        }
    };

    let token_url = super::provider_oauth_config(provider)
        .map(|c| c.token_url)
        .unwrap_or_else(|| {
            warn!(
                provider = provider,
                "No OAuth config for provider, using default token URL"
            );
            String::new()
        });

    if token_url.is_empty() {
        if token.is_expired() {
            return Err(ZeptoError::Config(format!(
                "Cannot refresh OAuth token for '{}': unknown token endpoint",
                provider
            )));
        }
        warn!(
            provider = provider,
            "OAuth token is expiring soon but token endpoint is unknown; using existing token"
        );
        return Ok(token.access_token);
    }

    match refresh_fn(&token_url, refresh_token, client_id).await {
        Ok(new_tokens) => {
            // Build updated token set
            let updated = OAuthTokenSet {
                provider: provider.to_string(),
                access_token: new_tokens.access_token.clone(),
                refresh_token: new_tokens.refresh_token.or(token.refresh_token),
                expires_at: new_tokens.expires_at,
                token_type: new_tokens.token_type,
                scope: new_tokens.scope.or(token.scope),
                obtained_at: chrono::Utc::now().timestamp(),
                client_id: token.client_id,
            };

            store.save(&updated)?;
            info!(provider = provider, "OAuth token refreshed successfully");

            Ok(updated.access_token)
        }
        Err(e) => {
            warn!(
                provider = provider,
                error = %e,
                "OAuth token refresh failed"
            );

            // If the old token hasn't actually expired yet, use it anyway
            if !token.is_expired() {
                warn!("Using existing token despite refresh failure (not yet expired)");
                Ok(token.access_token)
            } else {
                Err(ZeptoError::Config(format!(
                    "OAuth token for '{}' expired and refresh failed: {}",
                    provider, e
                )))
            }
        }
    }
}

/// Partial token response from a refresh grant.
struct RefreshedTokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
    token_type: String,
    scope: Option<String>,
}

/// Perform a token refresh grant against the provider's token endpoint.
async fn refresh_access_token(
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
) -> Result<RefreshedTokens> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ZeptoError::Config(format!("Failed to create HTTP client: {}", e)))?;

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];

    let resp = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| ZeptoError::Config(format!("Token refresh request failed: {}", e)))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(ZeptoError::Config(format!(
            "Token refresh failed (HTTP {}): {}",
            status, body
        )));
    }

    #[derive(serde::Deserialize)]
    struct RefreshResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<i64>,
        token_type: Option<String>,
        scope: Option<String>,
    }

    let parsed: RefreshResponse = serde_json::from_str(&body)
        .map_err(|e| ZeptoError::Config(format!("Failed to parse refresh response: {}", e)))?;

    let now = chrono::Utc::now().timestamp();

    Ok(RefreshedTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at: parsed.expires_in.map(|secs| now + secs),
        token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
        scope: parsed.scope,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::encryption::SecretEncryption;
    use tempfile::TempDir;

    fn test_store() -> (TokenStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("tokens.json.enc");
        (
            TokenStore::with_path(path, SecretEncryption::from_raw_key(&[0x42u8; 32])),
            tmp,
        )
    }

    fn token_set(provider: &str, expires_at: i64) -> OAuthTokenSet {
        OAuthTokenSet {
            provider: provider.to_string(),
            access_token: "old-access-token".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            expires_at: Some(expires_at),
            token_type: "Bearer".to_string(),
            scope: None,
            obtained_at: chrono::Utc::now().timestamp(),
            client_id: Some("registered-client-id".to_string()),
        }
    }

    #[test]
    fn test_refresh_buffer_secs() {
        // Ensure the refresh buffer is reasonable (5 minutes)
        assert_eq!(REFRESH_BUFFER_SECS, 300);
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_skips_refresh_when_valid() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        store.save(&token_set("anthropic", now + 3600)).unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);

        let token = ensure_fresh_token_with(&store, "anthropic", move |_, _, _| {
            calls2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ZeptoError::Config("should not be called".into())) })
        })
        .await
        .unwrap();

        assert_eq!(token, "old-access-token");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_refresh_failure_uses_old_when_not_expired() {
        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        store.save(&token_set("anthropic", now + 10)).unwrap(); // expiring soon, not expired

        let token = ensure_fresh_token_with(&store, "anthropic", |_, _, _| {
            Box::pin(async { Err(ZeptoError::Config("refresh failed".into())) })
        })
        .await
        .unwrap();

        assert_eq!(token, "old-access-token");
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_refresh_failure_errors_when_expired() {
        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        store.save(&token_set("anthropic", now - 10)).unwrap(); // expired

        let err = ensure_fresh_token_with(&store, "anthropic", |_, _, _| {
            Box::pin(async { Err(ZeptoError::Config("refresh failed".into())) })
        })
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("expired"));
        assert!(err.contains("refresh failed"));
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_refresh_success_updates_store() {
        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        store.save(&token_set("anthropic", now + 10)).unwrap();

        let token = ensure_fresh_token_with(&store, "anthropic", |_, _, _| {
            Box::pin(async move {
                Ok(RefreshedTokens {
                    access_token: "new-access-token".to_string(),
                    refresh_token: None,
                    expires_at: Some(now + 7200),
                    token_type: "Bearer".to_string(),
                    scope: None,
                })
            })
        })
        .await
        .unwrap();

        assert_eq!(token, "new-access-token");

        let stored = store.load("anthropic").unwrap().unwrap();
        assert_eq!(stored.access_token, "new-access-token");
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_missing_refresh_token_errors() {
        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        let mut token = token_set("anthropic", now + 10);
        token.refresh_token = None;
        store.save(&token).unwrap();

        let err = ensure_fresh_token_with(&store, "anthropic", |_, _, _| {
            Box::pin(async {
                Ok(RefreshedTokens {
                    access_token: "new".to_string(),
                    refresh_token: None,
                    expires_at: None,
                    token_type: "Bearer".to_string(),
                    scope: None,
                })
            })
        })
        .await
        .unwrap();

        assert_eq!(err, "old-access-token");
    }

    #[tokio::test]
    async fn test_ensure_fresh_token_expired_missing_refresh_token_errors() {
        let (store, _tmp) = test_store();
        let now = chrono::Utc::now().timestamp();
        let mut token = token_set("anthropic", now - 10);
        token.refresh_token = None;
        store.save(&token).unwrap();

        let err = ensure_fresh_token_with(&store, "anthropic", |_, _, _| {
            Box::pin(async { unreachable!("refresh_fn should not be called") })
        })
        .await
        .unwrap_err()
        .to_string();

        assert!(err.contains("expired"));
        assert!(err.contains("no refresh token"));
    }
}
