//! Secret encryption CLI commands.
//!
//! Provides `zeptoclaw secrets encrypt|decrypt|rotate` to manage
//! encrypted secrets in `~/.zeptoclaw/config.json`.

use anyhow::Result;
use serde_json::Value;

use super::SecretsAction;
use zeptoclaw::config::Config;
use zeptoclaw::security::encryption::{is_secret_field, resolve_master_key, SecretEncryption};

/// Dispatch secrets subcommands.
pub(crate) async fn cmd_secrets(action: SecretsAction) -> Result<()> {
    match action {
        SecretsAction::Encrypt => cmd_encrypt().await,
        SecretsAction::Decrypt => cmd_decrypt().await,
        SecretsAction::Rotate => cmd_rotate().await,
    }
}

// ============================================================================
// encrypt
// ============================================================================

/// Read config.json, encrypt all plaintext secret fields, and write back.
async fn cmd_encrypt() -> Result<()> {
    let path = Config::path();
    if !path.exists() {
        anyhow::bail!("config file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(&path)?;
    let mut root: Value = serde_json::from_str(&content)?;

    let enc = resolve_master_key(true).map_err(|e| anyhow::anyhow!("{e}"))?;

    let count = encrypt_value(&enc, &mut root)?;

    let pretty = serde_json::to_string_pretty(&root)?;
    std::fs::write(&path, pretty)?;

    println!("Encrypted {count} secret(s) in {}", path.display());
    Ok(())
}

/// Recursively walk JSON and encrypt plaintext values for secret fields.
/// Returns the number of values encrypted.
fn encrypt_value(enc: &SecretEncryption, value: &mut Value) -> Result<u64> {
    let mut count = 0u64;
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_secret_field(key) {
                    if let Value::String(s) = val {
                        if !s.is_empty() && !SecretEncryption::is_encrypted(s) {
                            let encrypted = enc.encrypt(s).map_err(|e| anyhow::anyhow!("{e}"))?;
                            *s = encrypted;
                            count += 1;
                        }
                    }
                } else {
                    count += encrypt_value(enc, val)?;
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                count += encrypt_value(enc, item)?;
            }
        }
        _ => {}
    }
    Ok(count)
}

// ============================================================================
// decrypt
// ============================================================================

/// Read config.json, decrypt all ENC[...] values, and write back.
async fn cmd_decrypt() -> Result<()> {
    let path = Config::path();
    if !path.exists() {
        anyhow::bail!("config file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(&path)?;
    let mut root: Value = serde_json::from_str(&content)?;

    let enc = resolve_master_key(true).map_err(|e| anyhow::anyhow!("{e}"))?;

    let count = decrypt_value(&enc, &mut root)?;

    let pretty = serde_json::to_string_pretty(&root)?;
    std::fs::write(&path, pretty)?;

    println!("Decrypted {count} secret(s) in {}", path.display());
    Ok(())
}

/// Recursively walk JSON and decrypt ENC[...] values.
/// Returns the number of values decrypted.
fn decrypt_value(enc: &SecretEncryption, value: &mut Value) -> Result<u64> {
    let mut count = 0u64;
    match value {
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                if let Value::String(s) = val {
                    if SecretEncryption::is_encrypted(s) {
                        let decrypted = enc.decrypt(s).map_err(|e| anyhow::anyhow!("{e}"))?;
                        *s = decrypted;
                        count += 1;
                    }
                } else {
                    count += decrypt_value(enc, val)?;
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                count += decrypt_value(enc, item)?;
            }
        }
        _ => {}
    }
    Ok(count)
}

// ============================================================================
// rotate
// ============================================================================

/// Decrypt all secrets with the current key, then re-encrypt with a new key.
async fn cmd_rotate() -> Result<()> {
    let path = Config::path();
    if !path.exists() {
        anyhow::bail!("config file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(&path)?;
    let mut root: Value = serde_json::from_str(&content)?;

    // Step 1: Decrypt with current key
    println!("Step 1/2: Decrypt with current key");
    let old_enc = resolve_master_key(true).map_err(|e| anyhow::anyhow!("{e}"))?;
    let dec_count = decrypt_value(&old_enc, &mut root)?;
    println!("  Decrypted {dec_count} secret(s)");

    // Step 2: Prompt for new passphrase and re-encrypt
    println!("Step 2/2: Re-encrypt with new key");
    let new_passphrase = rpassword::prompt_password("Enter NEW master passphrase: ")
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {e}"))?;
    if new_passphrase.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm NEW master passphrase: ")
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {e}"))?;
    if new_passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let new_enc =
        SecretEncryption::from_passphrase(&new_passphrase).map_err(|e| anyhow::anyhow!("{e}"))?;
    let enc_count = encrypt_value(&new_enc, &mut root)?;

    let pretty = serde_json::to_string_pretty(&root)?;
    std::fs::write(&path, pretty)?;

    println!("  Re-encrypted {enc_count} secret(s) in {}", path.display());
    println!("Key rotated successfully.");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_enc() -> SecretEncryption {
        SecretEncryption::from_raw_key(&[0xABu8; 32])
    }

    #[test]
    fn test_encrypt_value_simple() {
        let enc = test_enc();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": "sk-ant-abc123"
                }
            }
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 1);

        let encrypted = val["providers"]["anthropic"]["api_key"].as_str().unwrap();
        assert!(SecretEncryption::is_encrypted(encrypted));
    }

    #[test]
    fn test_encrypt_value_skips_already_encrypted() {
        let enc = test_enc();
        let already = enc.encrypt("secret").unwrap();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": already
                }
            }
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_encrypt_value_skips_empty() {
        let enc = test_enc();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": ""
                }
            }
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_encrypt_value_skips_non_secret_fields() {
        let enc = test_enc();
        let mut val = json!({
            "agents": {
                "defaults": {
                    "model": "gpt-4",
                    "workspace": "~/.zeptoclaw/workspace"
                }
            }
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 0);

        // Non-secret fields should remain unchanged
        assert_eq!(val["agents"]["defaults"]["model"], "gpt-4");
    }

    #[test]
    fn test_decrypt_value_simple() {
        let enc = test_enc();
        let encrypted = enc.encrypt("sk-ant-abc123").unwrap();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": encrypted
                }
            }
        });

        let count = decrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            val["providers"]["anthropic"]["api_key"].as_str().unwrap(),
            "sk-ant-abc123"
        );
    }

    #[test]
    fn test_decrypt_value_skips_plaintext() {
        let enc = test_enc();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": "sk-plain-text"
                }
            }
        });

        let count = decrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 0);
        assert_eq!(
            val["providers"]["anthropic"]["api_key"].as_str().unwrap(),
            "sk-plain-text"
        );
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let enc = test_enc();
        let mut val = json!({
            "providers": {
                "anthropic": {
                    "api_key": "sk-ant-secret"
                },
                "openai": {
                    "api_key": "sk-openai-key",
                    "api_base": "https://api.openai.com/v1"
                }
            },
            "channels": {
                "telegram": {
                    "token": "bot123:ABC",
                    "enabled": true
                }
            }
        });

        // Encrypt
        let enc_count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(enc_count, 3); // api_key x2 + token

        // All secret fields should be encrypted
        assert!(SecretEncryption::is_encrypted(
            val["providers"]["anthropic"]["api_key"].as_str().unwrap()
        ));
        assert!(SecretEncryption::is_encrypted(
            val["providers"]["openai"]["api_key"].as_str().unwrap()
        ));
        assert!(SecretEncryption::is_encrypted(
            val["channels"]["telegram"]["token"].as_str().unwrap()
        ));

        // Non-secret fields should be unchanged
        assert_eq!(
            val["providers"]["openai"]["api_base"].as_str().unwrap(),
            "https://api.openai.com/v1"
        );
        assert_eq!(val["channels"]["telegram"]["enabled"], true);

        // Decrypt
        let dec_count = decrypt_value(&enc, &mut val).unwrap();
        assert_eq!(dec_count, 3);

        // Values should be restored
        assert_eq!(
            val["providers"]["anthropic"]["api_key"].as_str().unwrap(),
            "sk-ant-secret"
        );
        assert_eq!(
            val["providers"]["openai"]["api_key"].as_str().unwrap(),
            "sk-openai-key"
        );
        assert_eq!(
            val["channels"]["telegram"]["token"].as_str().unwrap(),
            "bot123:ABC"
        );
    }

    #[test]
    fn test_encrypt_value_in_array() {
        let enc = test_enc();
        let mut val = json!({
            "list": [
                {
                    "api_key": "secret-in-array"
                }
            ]
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 1);
        assert!(SecretEncryption::is_encrypted(
            val["list"][0]["api_key"].as_str().unwrap()
        ));
    }

    #[test]
    fn test_decrypt_value_in_array() {
        let enc = test_enc();
        let encrypted = enc.encrypt("array-secret").unwrap();
        let mut val = json!({
            "list": [
                {
                    "api_key": encrypted
                }
            ]
        });

        let count = decrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 1);
        assert_eq!(val["list"][0]["api_key"].as_str().unwrap(), "array-secret");
    }

    #[test]
    fn test_encrypt_multiple_secret_field_types() {
        let enc = test_enc();
        let mut val = json!({
            "channels": {
                "slack": {
                    "bot_token": "xoxb-slack-token",
                    "app_token": "xapp-slack-app"
                },
                "webhook": {
                    "webhook_verify_token": "verify-me"
                }
            },
            "tools": {
                "whatsapp": {
                    "access_token": "wa-token-123"
                },
                "google_sheets": {
                    "service_account_base64": "base64data"
                }
            }
        });

        let count = encrypt_value(&enc, &mut val).unwrap();
        assert_eq!(count, 5);
    }
}
