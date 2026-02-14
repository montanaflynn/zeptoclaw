//! JSON-based registry tracking installed dependency state.
//!
//! Persists to `~/.zeptoclaw/deps/registry.json`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Result, ZeptoError};

/// An entry in the dependency registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Dependency kind (e.g. "binary", "docker_image", "npm_package", "pip_package").
    pub kind: String,
    /// Installed version.
    pub version: String,
    /// When it was installed (ISO 8601).
    pub installed_at: String,
    /// Path to the installed artifact.
    pub path: String,
    /// Whether a managed process is currently believed to be running.
    #[serde(default)]
    pub running: bool,
    /// PID of the managed process (if running).
    #[serde(default)]
    pub pid: Option<u32>,
}

/// In-memory registry backed by a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Registry {
    #[serde(flatten)]
    entries: HashMap<String, RegistryEntry>,
}

impl Registry {
    /// Load from a JSON file. Returns empty registry if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        if content.trim().is_empty() {
            return Ok(Self::default());
        }
        let registry: Self =
            serde_json::from_str(&content).map_err(|e| ZeptoError::Config(e.to_string()))?;
        Ok(registry)
    }

    /// Save to a JSON file. Creates parent directories if needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get an entry by dependency name.
    pub fn get(&self, name: &str) -> Option<&RegistryEntry> {
        self.entries.get(name)
    }

    /// Insert or update an entry.
    pub fn set(&mut self, name: String, entry: RegistryEntry) {
        self.entries.insert(name, entry);
    }

    /// Remove an entry.
    pub fn remove(&mut self, name: &str) -> Option<RegistryEntry> {
        self.entries.remove(name)
    }

    /// Check if a dependency is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// List all entry names.
    pub fn names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Mark a dependency as running with a PID.
    pub fn mark_running(&mut self, name: &str, pid: u32) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.running = true;
            entry.pid = Some(pid);
        }
    }

    /// Mark a dependency as stopped.
    pub fn mark_stopped(&mut self, name: &str) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.running = false;
            entry.pid = None;
        }
    }

    /// Find entries that claim to be running (for stale process cleanup).
    pub fn stale_running(&self) -> Vec<(String, &RegistryEntry)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.running)
            .map(|(k, v)| (k.clone(), v))
            .collect()
    }

    /// Default registry file path.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zeptoclaw/deps/registry.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_entry(name: &str) -> RegistryEntry {
        RegistryEntry {
            kind: "binary".to_string(),
            version: "v0.1.0".to_string(),
            installed_at: "2026-02-14T10:00:00Z".to_string(),
            path: format!("~/.zeptoclaw/deps/bin/{}", name),
            running: false,
            pid: None,
        }
    }

    #[test]
    fn test_registry_empty_default() {
        let reg = Registry::default();
        assert!(reg.names().is_empty());
    }

    #[test]
    fn test_registry_set_and_get() {
        let mut reg = Registry::default();
        reg.set("test-dep".to_string(), test_entry("test-dep"));
        assert!(reg.contains("test-dep"));
        let entry = reg.get("test-dep").unwrap();
        assert_eq!(entry.version, "v0.1.0");
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = Registry::default();
        reg.set("test-dep".to_string(), test_entry("test-dep"));
        let removed = reg.remove("test-dep");
        assert!(removed.is_some());
        assert!(!reg.contains("test-dep"));
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let mut reg = Registry::default();
        assert!(reg.remove("nope").is_none());
    }

    #[test]
    fn test_registry_names() {
        let mut reg = Registry::default();
        reg.set("a".to_string(), test_entry("a"));
        reg.set("b".to_string(), test_entry("b"));
        let mut names = reg.names();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_registry_mark_running() {
        let mut reg = Registry::default();
        reg.set("dep".to_string(), test_entry("dep"));
        reg.mark_running("dep", 12345);
        let entry = reg.get("dep").unwrap();
        assert!(entry.running);
        assert_eq!(entry.pid, Some(12345));
    }

    #[test]
    fn test_registry_mark_stopped() {
        let mut reg = Registry::default();
        reg.set("dep".to_string(), test_entry("dep"));
        reg.mark_running("dep", 12345);
        reg.mark_stopped("dep");
        let entry = reg.get("dep").unwrap();
        assert!(!entry.running);
        assert!(entry.pid.is_none());
    }

    #[test]
    fn test_registry_stale_running() {
        let mut reg = Registry::default();
        reg.set("a".to_string(), test_entry("a"));
        reg.set("b".to_string(), test_entry("b"));
        reg.mark_running("a", 111);
        let stale = reg.stale_running();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, "a");
    }

    #[test]
    fn test_registry_serde_roundtrip() {
        let mut reg = Registry::default();
        reg.set("dep1".to_string(), test_entry("dep1"));
        reg.mark_running("dep1", 999);

        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert!(loaded.contains("dep1"));
        assert_eq!(loaded.get("dep1").unwrap().pid, Some(999));
    }

    #[test]
    fn test_registry_save_and_load() {
        let dir = std::env::temp_dir().join("zeptoclaw_test_registry");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");

        let mut reg = Registry::default();
        reg.set("test".to_string(), test_entry("test"));
        reg.save(&path).unwrap();

        let loaded = Registry::load(&path).unwrap();
        assert!(loaded.contains("test"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_registry_load_nonexistent() {
        let path = PathBuf::from("/tmp/nonexistent_zeptoclaw_registry.json");
        let reg = Registry::load(&path).unwrap();
        assert!(reg.names().is_empty());
    }

    #[test]
    fn test_registry_load_empty_file() {
        let dir = std::env::temp_dir().join("zeptoclaw_test_registry_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        fs::write(&path, "").unwrap();

        let reg = Registry::load(&path).unwrap();
        assert!(reg.names().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_registry_default_path() {
        let path = Registry::default_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".zeptoclaw/deps/registry.json"));
    }
}
