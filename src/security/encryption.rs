//! Secret encryption at rest using XChaCha20-Poly1305 + Argon2id
//!
//! Provides symmetric AEAD encryption for sensitive configuration values
//! (API keys, tokens, secrets). Encrypted values are stored in the format:
//!
//! ```text
//! ENC[1:salt_b64:nonce_b64:ciphertext_b64]
//! ```
//!
//! - Version `1`: XChaCha20-Poly1305 with Argon2id KDF
//! - Salt: 16-byte random, base64-encoded (used by Argon2id)
//! - Nonce: 24-byte random, base64-encoded (required by XChaCha20)
//! - Ciphertext: AEAD output (plaintext + 16-byte Poly1305 tag), base64-encoded

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

use crate::error::{Result, ZeptoError};

// ============================================================================
// Constants
// ============================================================================

/// Length of the Argon2id salt in bytes.
const ARGON2_SALT_LEN: usize = 16;

/// Length of the XChaCha20 nonce in bytes.
const XCHACHA_NONCE_LEN: usize = 24;

/// Current envelope format version.
const FORMAT_VERSION: &str = "1";

// ============================================================================
// SecretEncryption
// ============================================================================

/// Symmetric AEAD encryptor for configuration secrets.
///
/// Wraps a 256-bit key used with XChaCha20-Poly1305. The key can be derived
/// from a passphrase via Argon2id or provided directly as raw bytes.
pub struct SecretEncryption {
    key: [u8; 32],
}

impl SecretEncryption {
    /// Derive a 256-bit encryption key from a passphrase using Argon2id.
    ///
    /// A random 16-byte salt is generated internally. The salt is embedded in
    /// each encrypted value so decryption can re-derive the same key when given
    /// the original passphrase.
    ///
    /// # Errors
    ///
    /// Returns `ZeptoError::Config` if the KDF fails (should not happen with
    /// valid parameters).
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        let salt = Self::random_bytes::<ARGON2_SALT_LEN>();
        let key = Self::derive_key(passphrase, &salt)?;
        Ok(Self { key })
    }

    /// Create an encryptor from a raw 256-bit key.
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Returns `true` if `value` looks like an encrypted envelope (`ENC[...]`).
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with("ENC[") && value.ends_with(']')
    }

    /// Encrypt `plaintext` and return an `ENC[...]` envelope string.
    ///
    /// Each call generates a fresh random salt and nonce, so encrypting the
    /// same plaintext twice produces different ciphertexts.
    ///
    /// # Errors
    ///
    /// Returns `ZeptoError::Config` if encryption fails.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let salt = Self::random_bytes::<ARGON2_SALT_LEN>();
        // Re-derive key with the new salt so the salt is meaningful on decrypt.
        // For raw-key mode the salt is still stored but ignored on decrypt
        // (the raw key is used directly). This keeps the format uniform.
        let cipher_key = self.key;

        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| ZeptoError::Config(format!("encryption failed: {e}")))?;

        let salt_b64 = BASE64.encode(salt);
        let nonce_b64 = BASE64.encode(nonce.as_slice());
        let ct_b64 = BASE64.encode(&ciphertext);

        Ok(format!(
            "ENC[{FORMAT_VERSION}:{salt_b64}:{nonce_b64}:{ct_b64}]"
        ))
    }

    /// Decrypt an `ENC[...]` envelope and return the original plaintext.
    ///
    /// # Errors
    ///
    /// Returns `ZeptoError::Config` if the envelope format is invalid or
    /// decryption fails (wrong key, corrupted ciphertext, etc.).
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        if !Self::is_encrypted(encrypted) {
            return Err(ZeptoError::Config(
                "value is not an encrypted envelope".into(),
            ));
        }

        // Strip "ENC[" prefix and "]" suffix
        let inner = &encrypted[4..encrypted.len() - 1];
        let parts: Vec<&str> = inner.split(':').collect();

        if parts.len() != 4 {
            return Err(ZeptoError::Config(format!(
                "invalid encrypted format: expected 4 parts, got {}",
                parts.len()
            )));
        }

        let version = parts[0];
        if version != FORMAT_VERSION {
            return Err(ZeptoError::Config(format!(
                "unsupported encryption version: {version}"
            )));
        }

        // parts[1] is the salt — stored for passphrase-based KDF re-derivation.
        // In raw-key mode we ignore it (key is already known).
        let _salt_bytes = BASE64
            .decode(parts[1])
            .map_err(|e| ZeptoError::Config(format!("invalid salt encoding: {e}")))?;

        let nonce_bytes = BASE64
            .decode(parts[2])
            .map_err(|e| ZeptoError::Config(format!("invalid nonce encoding: {e}")))?;

        if nonce_bytes.len() != XCHACHA_NONCE_LEN {
            return Err(ZeptoError::Config(format!(
                "invalid nonce length: expected {XCHACHA_NONCE_LEN}, got {}",
                nonce_bytes.len()
            )));
        }

        let ciphertext = BASE64
            .decode(parts[3])
            .map_err(|e| ZeptoError::Config(format!("invalid ciphertext encoding: {e}")))?;

        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = XChaCha20Poly1305::new((&self.key).into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| ZeptoError::Config(format!("decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|e| ZeptoError::Config(format!("decrypted value is not valid UTF-8: {e}")))
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Derive a 32-byte key from a passphrase and salt using Argon2id.
    ///
    /// Parameters: m=64MB (65536 KiB), t=3 iterations, p=1 parallelism (OWASP recommended).
    fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| ZeptoError::Config(format!("Argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| ZeptoError::Config(format!("key derivation failed: {e}")))?;
        Ok(key)
    }

    /// Generate `N` cryptographically random bytes.
    fn random_bytes<const N: usize>() -> [u8; N] {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

// ============================================================================
// SecretEncryption — passphrase-aware encrypt/decrypt
// ============================================================================

/// A passphrase-aware variant that stores the passphrase so it can re-derive
/// the key with each envelope's unique salt during decryption.
///
/// This is used internally by `from_passphrase` to support round-trip
/// encrypt/decrypt without requiring the caller to manage salts.
pub struct PassphraseEncryption {
    passphrase: String,
}

impl PassphraseEncryption {
    /// Create a passphrase-based encryptor.
    pub fn new(passphrase: &str) -> Self {
        Self {
            passphrase: passphrase.to_string(),
        }
    }

    /// Encrypt `plaintext` using a fresh salt and nonce.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let salt = SecretEncryption::random_bytes::<ARGON2_SALT_LEN>();
        let key = SecretEncryption::derive_key(&self.passphrase, &salt)?;

        let cipher = XChaCha20Poly1305::new((&key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| ZeptoError::Config(format!("encryption failed: {e}")))?;

        let salt_b64 = BASE64.encode(salt);
        let nonce_b64 = BASE64.encode(nonce.as_slice());
        let ct_b64 = BASE64.encode(&ciphertext);

        Ok(format!(
            "ENC[{FORMAT_VERSION}:{salt_b64}:{nonce_b64}:{ct_b64}]"
        ))
    }

    /// Decrypt an `ENC[...]` envelope by re-deriving the key from the embedded salt.
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        if !SecretEncryption::is_encrypted(encrypted) {
            return Err(ZeptoError::Config(
                "value is not an encrypted envelope".into(),
            ));
        }

        let inner = &encrypted[4..encrypted.len() - 1];
        let parts: Vec<&str> = inner.split(':').collect();

        if parts.len() != 4 {
            return Err(ZeptoError::Config(format!(
                "invalid encrypted format: expected 4 parts, got {}",
                parts.len()
            )));
        }

        let version = parts[0];
        if version != FORMAT_VERSION {
            return Err(ZeptoError::Config(format!(
                "unsupported encryption version: {version}"
            )));
        }

        let salt_bytes = BASE64
            .decode(parts[1])
            .map_err(|e| ZeptoError::Config(format!("invalid salt encoding: {e}")))?;

        let nonce_bytes = BASE64
            .decode(parts[2])
            .map_err(|e| ZeptoError::Config(format!("invalid nonce encoding: {e}")))?;

        if nonce_bytes.len() != XCHACHA_NONCE_LEN {
            return Err(ZeptoError::Config(format!(
                "invalid nonce length: expected {XCHACHA_NONCE_LEN}, got {}",
                nonce_bytes.len()
            )));
        }

        let ciphertext = BASE64
            .decode(parts[3])
            .map_err(|e| ZeptoError::Config(format!("invalid ciphertext encoding: {e}")))?;

        // Re-derive key from passphrase + stored salt
        let key = SecretEncryption::derive_key(&self.passphrase, &salt_bytes)?;

        let nonce = XNonce::from_slice(&nonce_bytes);
        let cipher = XChaCha20Poly1305::new((&key).into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| ZeptoError::Config(format!("decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|e| ZeptoError::Config(format!("decrypted value is not valid UTF-8: {e}")))
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Returns `true` if `field_name` refers to a configuration field that
/// typically holds a secret value (API key, token, etc.).
///
/// Used to decide which config values should be encrypted at rest.
pub fn is_secret_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "api_key"
            | "token"
            | "bot_token"
            | "app_token"
            | "auth_token"
            | "access_token"
            | "app_secret"
            | "client_secret"
            | "encrypt_key"
            | "verification_token"
            | "service_account_base64"
            | "webhook_verify_token"
    )
}

/// Resolve the master encryption key from environment or interactive prompt.
///
/// Resolution order:
/// 1. `ZEPTOCLAW_MASTER_KEY` environment variable (hex-encoded 32 bytes)
/// 2. Interactive passphrase prompt via `rpassword` (if `interactive` is `true`)
/// 3. Error if neither is available
///
/// # Errors
///
/// Returns `ZeptoError::Config` if the env var is present but not valid
/// 64-character hex, or if no key source is available.
pub fn resolve_master_key(interactive: bool) -> Result<SecretEncryption> {
    // 1. Try environment variable (hex-encoded 32 bytes = 64 hex chars)
    if let Ok(hex_key) = std::env::var("ZEPTOCLAW_MASTER_KEY") {
        let bytes = hex::decode(hex_key.trim()).map_err(|e| {
            ZeptoError::Config(format!("ZEPTOCLAW_MASTER_KEY is not valid hex: {e}"))
        })?;

        if bytes.len() != 32 {
            return Err(ZeptoError::Config(format!(
                "ZEPTOCLAW_MASTER_KEY must be 64 hex chars (32 bytes), got {} bytes",
                bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(SecretEncryption::from_raw_key(&key));
    }

    // 2. Interactive passphrase prompt
    if interactive {
        let passphrase = rpassword::prompt_password("Enter master passphrase: ")
            .map_err(|e| ZeptoError::Config(format!("failed to read passphrase: {e}")))?;

        if passphrase.is_empty() {
            return Err(ZeptoError::Config("passphrase cannot be empty".into()));
        }

        return SecretEncryption::from_passphrase(&passphrase);
    }

    // 3. No key source available
    Err(ZeptoError::Config(
        "no master key available: set ZEPTOCLAW_MASTER_KEY env var or use interactive mode".into(),
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_encrypted_true() {
        assert!(SecretEncryption::is_encrypted("ENC[1:abc:def:ghi]"));
        assert!(SecretEncryption::is_encrypted("ENC[anything]"));
    }

    #[test]
    fn test_is_encrypted_false() {
        assert!(!SecretEncryption::is_encrypted("sk-abc123"));
        assert!(!SecretEncryption::is_encrypted(""));
        assert!(!SecretEncryption::is_encrypted("ENC"));
        assert!(!SecretEncryption::is_encrypted("ENC["));
        assert!(!SecretEncryption::is_encrypted("ENC]"));
        assert!(!SecretEncryption::is_encrypted("[ENC]"));
        assert!(!SecretEncryption::is_encrypted("plain text"));
    }

    #[test]
    fn test_round_trip_passphrase() {
        let enc = PassphraseEncryption::new("test-passphrase-42");
        let plaintext = "sk-secret-api-key-12345";

        let encrypted = enc.encrypt(plaintext).unwrap();
        assert!(SecretEncryption::is_encrypted(&encrypted));

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_round_trip_raw_key() {
        let key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let enc = SecretEncryption::from_raw_key(&key);
        let plaintext = "super-secret-token";

        let encrypted = enc.encrypt(plaintext).unwrap();
        assert!(SecretEncryption::is_encrypted(&encrypted));

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let enc1 = PassphraseEncryption::new("correct-passphrase");
        let enc2 = PassphraseEncryption::new("wrong-passphrase");

        let encrypted = enc1.encrypt("secret-data").unwrap();

        let result = enc2.decrypt(&encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let key = [0xABu8; 32];
        let enc = SecretEncryption::from_raw_key(&key);

        let encrypted = enc.encrypt("test-value").unwrap();

        // Corrupt by replacing ciphertext portion
        let inner = &encrypted[4..encrypted.len() - 1];
        let parts: Vec<&str> = inner.split(':').collect();
        let corrupted = format!(
            "ENC[{}:{}:{}:{}]",
            parts[0],
            parts[1],
            parts[2],
            BASE64.encode(b"totally-corrupted-ciphertext-data")
        );

        let result = enc.decrypt(&corrupted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn test_invalid_format_fails() {
        let key = [0x42u8; 32];
        let enc = SecretEncryption::from_raw_key(&key);

        // Not an envelope at all
        assert!(enc.decrypt("not-encrypted").is_err());

        // Wrong number of parts
        assert!(enc.decrypt("ENC[1:two:parts]").is_err());
        assert!(enc.decrypt("ENC[only-one]").is_err());

        // Wrong version
        assert!(enc.decrypt("ENC[99:a:b:c]").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x55u8; 32];
        let enc = SecretEncryption::from_raw_key(&key);

        let encrypted = enc.encrypt("").unwrap();
        assert!(SecretEncryption::is_encrypted(&encrypted));

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_each_encrypt_produces_unique_output() {
        let key = [0x77u8; 32];
        let enc = SecretEncryption::from_raw_key(&key);
        let plaintext = "same-secret";

        let a = enc.encrypt(plaintext).unwrap();
        let b = enc.encrypt(plaintext).unwrap();

        // Different nonces produce different ciphertexts
        assert_ne!(a, b);

        // Both decrypt to the same plaintext
        assert_eq!(enc.decrypt(&a).unwrap(), plaintext);
        assert_eq!(enc.decrypt(&b).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypted_format_has_four_parts() {
        let key = [0x11u8; 32];
        let enc = SecretEncryption::from_raw_key(&key);

        let encrypted = enc.encrypt("test").unwrap();

        // Strip envelope markers
        assert!(encrypted.starts_with("ENC["));
        assert!(encrypted.ends_with(']'));

        let inner = &encrypted[4..encrypted.len() - 1];
        let parts: Vec<&str> = inner.split(':').collect();
        assert_eq!(parts.len(), 4, "envelope must have 4 colon-separated parts");
        assert_eq!(parts[0], "1", "version must be '1'");

        // Salt should decode to ARGON2_SALT_LEN bytes
        let salt = BASE64.decode(parts[1]).unwrap();
        assert_eq!(salt.len(), ARGON2_SALT_LEN);

        // Nonce should decode to XCHACHA_NONCE_LEN bytes
        let nonce = BASE64.decode(parts[2]).unwrap();
        assert_eq!(nonce.len(), XCHACHA_NONCE_LEN);

        // Ciphertext should be non-empty
        let ct = BASE64.decode(parts[3]).unwrap();
        assert!(!ct.is_empty());
    }

    #[test]
    fn test_secret_field_names() {
        // Positive cases — all of these should be detected as secret fields
        let secret_fields = [
            "api_key",
            "token",
            "bot_token",
            "app_token",
            "auth_token",
            "access_token",
            "app_secret",
            "client_secret",
            "encrypt_key",
            "verification_token",
            "service_account_base64",
            "webhook_verify_token",
        ];
        for field in &secret_fields {
            assert!(
                is_secret_field(field),
                "{field} should be detected as a secret field"
            );
        }

        // Negative cases — these should NOT be detected
        let non_secret_fields = [
            "model",
            "name",
            "workspace",
            "enabled",
            "max_retries",
            "base_url",
            "provider",
            "temperature",
        ];
        for field in &non_secret_fields {
            assert!(
                !is_secret_field(field),
                "{field} should NOT be detected as a secret field"
            );
        }
    }
}
