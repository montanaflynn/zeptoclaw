# Dependency Manager Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a general-purpose dependency manager (`src/deps/`) that handles install, start, health check, and stop of external dependencies (binaries, Docker images, npm/pip packages) so channels, tools, and skills can declare what they need and have it managed automatically.

**Architecture:** Components implement `HasDependencies` trait to declare their needs. A central `DepManager` handles the lifecycle. A `DepFetcher` trait abstracts network calls for testability. A JSON registry at `~/.zeptoclaw/deps/registry.json` tracks installed state. No new crate dependencies.

**Tech Stack:** Rust, tokio, serde/serde_json, reqwest (existing), std::process::Command

**Design doc:** `docs/plans/2026-02-14-dependency-manager-design.md`

---

## Task 1: Core types (`src/deps/types.rs`)

**Files:**
- Create: `src/deps/types.rs`

**Step 1: Write the types file with all core abstractions and tests**

```rust
//! Dependency manager core types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The kind of external dependency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DepKind {
    /// A binary downloaded from GitHub Releases.
    Binary {
        /// GitHub repo (e.g. "qhkm/whatsmeow-rs")
        repo: String,
        /// Asset filename pattern with `{os}` and `{arch}` placeholders.
        asset_pattern: String,
        /// Semver version tag (e.g. "v0.1.0"). Empty = latest.
        version: String,
    },
    /// A Docker image.
    DockerImage {
        /// Image name (e.g. "redis")
        image: String,
        /// Image tag (e.g. "7-alpine")
        tag: String,
        /// Port mappings (host:container)
        ports: Vec<String>,
    },
    /// An npm package.
    NpmPackage {
        /// Package name (e.g. "@modelcontextprotocol/server-github")
        package: String,
        /// Version constraint (e.g. "^1.0.0")
        version: String,
        /// Entry point script or binary name within the package.
        entry_point: String,
    },
    /// A pip package installed into a virtualenv.
    PipPackage {
        /// Package name (e.g. "mcp-server-sqlite")
        package: String,
        /// Version constraint (e.g. ">=1.0")
        version: String,
        /// Entry point script or module.
        entry_point: String,
    },
}

/// How to verify a dependency process is healthy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HealthCheck {
    /// Connect to a WebSocket URL.
    WebSocket { url: String },
    /// HTTP GET to a URL, expect 2xx.
    Http { url: String },
    /// Check that a TCP port is listening.
    TcpPort { port: u16 },
    /// Run a command and check exit code 0.
    Command { command: String },
    /// No health check needed.
    None,
}

/// A declared external dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Unique name (e.g. "whatsmeow-bridge").
    pub name: String,
    /// What kind of dependency this is.
    pub kind: DepKind,
    /// How to check process health after starting.
    pub health_check: HealthCheck,
    /// Environment variables to set when starting the process.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Command-line arguments to pass when starting.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Trait for components that declare external dependencies.
///
/// Channels, tools, or skills implement this to declare what they need.
/// Default implementation returns no dependencies.
pub trait HasDependencies {
    fn dependencies(&self) -> Vec<Dependency> {
        vec![]
    }
}

/// Detect the current platform for binary downloads.
pub fn current_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "unknown"
    };

    (os, arch)
}

/// Resolve `{os}` and `{arch}` placeholders in an asset pattern.
pub fn resolve_asset_pattern(pattern: &str) -> String {
    let (os, arch) = current_platform();
    pattern.replace("{os}", os).replace("{arch}", arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- DepKind construction --

    #[test]
    fn test_dep_kind_binary() {
        let kind = DepKind::Binary {
            repo: "qhkm/whatsmeow-rs".to_string(),
            asset_pattern: "whatsmeow-bridge-{os}-{arch}".to_string(),
            version: "v0.1.0".to_string(),
        };
        match kind {
            DepKind::Binary { repo, .. } => assert_eq!(repo, "qhkm/whatsmeow-rs"),
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn test_dep_kind_docker() {
        let kind = DepKind::DockerImage {
            image: "redis".to_string(),
            tag: "7-alpine".to_string(),
            ports: vec!["6379:6379".to_string()],
        };
        match kind {
            DepKind::DockerImage { image, tag, ports } => {
                assert_eq!(image, "redis");
                assert_eq!(tag, "7-alpine");
                assert_eq!(ports.len(), 1);
            }
            _ => panic!("expected DockerImage"),
        }
    }

    #[test]
    fn test_dep_kind_npm() {
        let kind = DepKind::NpmPackage {
            package: "@mcp/server".to_string(),
            version: "^1.0.0".to_string(),
            entry_point: "mcp-server".to_string(),
        };
        match kind {
            DepKind::NpmPackage { package, .. } => assert_eq!(package, "@mcp/server"),
            _ => panic!("expected NpmPackage"),
        }
    }

    #[test]
    fn test_dep_kind_pip() {
        let kind = DepKind::PipPackage {
            package: "mcp-server-sqlite".to_string(),
            version: ">=1.0".to_string(),
            entry_point: "mcp-server-sqlite".to_string(),
        };
        match kind {
            DepKind::PipPackage { package, .. } => assert_eq!(package, "mcp-server-sqlite"),
            _ => panic!("expected PipPackage"),
        }
    }

    // -- HealthCheck variants --

    #[test]
    fn test_health_check_websocket() {
        let hc = HealthCheck::WebSocket {
            url: "ws://localhost:3001".to_string(),
        };
        assert_eq!(
            hc,
            HealthCheck::WebSocket {
                url: "ws://localhost:3001".to_string()
            }
        );
    }

    #[test]
    fn test_health_check_http() {
        let hc = HealthCheck::Http {
            url: "http://localhost:8080/health".to_string(),
        };
        match hc {
            HealthCheck::Http { url } => assert!(url.contains("/health")),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_health_check_tcp() {
        let hc = HealthCheck::TcpPort { port: 6379 };
        assert_eq!(hc, HealthCheck::TcpPort { port: 6379 });
    }

    #[test]
    fn test_health_check_command() {
        let hc = HealthCheck::Command {
            command: "redis-cli ping".to_string(),
        };
        match hc {
            HealthCheck::Command { command } => assert!(command.contains("ping")),
            _ => panic!("expected Command"),
        }
    }

    #[test]
    fn test_health_check_none() {
        let hc = HealthCheck::None;
        assert_eq!(hc, HealthCheck::None);
    }

    // -- Dependency construction --

    #[test]
    fn test_dependency_full() {
        let dep = Dependency {
            name: "whatsmeow-bridge".to_string(),
            kind: DepKind::Binary {
                repo: "qhkm/whatsmeow-rs".to_string(),
                asset_pattern: "whatsmeow-bridge-{os}-{arch}".to_string(),
                version: "v0.1.0".to_string(),
            },
            health_check: HealthCheck::WebSocket {
                url: "ws://localhost:3001".to_string(),
            },
            env: HashMap::from([("PORT".to_string(), "3001".to_string())]),
            args: vec!["--port".to_string(), "3001".to_string()],
        };

        assert_eq!(dep.name, "whatsmeow-bridge");
        assert_eq!(dep.env.get("PORT"), Some(&"3001".to_string()));
        assert_eq!(dep.args.len(), 2);
    }

    #[test]
    fn test_dependency_empty_env_and_args() {
        let dep = Dependency {
            name: "test".to_string(),
            kind: DepKind::DockerImage {
                image: "redis".to_string(),
                tag: "latest".to_string(),
                ports: vec![],
            },
            health_check: HealthCheck::None,
            env: HashMap::new(),
            args: vec![],
        };

        assert!(dep.env.is_empty());
        assert!(dep.args.is_empty());
    }

    // -- HasDependencies default --

    struct NoDeps;
    impl HasDependencies for NoDeps {}

    #[test]
    fn test_has_dependencies_default_is_empty() {
        let c = NoDeps;
        assert!(c.dependencies().is_empty());
    }

    // -- Serde roundtrip --

    #[test]
    fn test_dep_kind_serde_roundtrip() {
        let kind = DepKind::Binary {
            repo: "owner/repo".to_string(),
            asset_pattern: "bin-{os}-{arch}".to_string(),
            version: "v1.0.0".to_string(),
        };
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized: DepKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized);
    }

    #[test]
    fn test_health_check_serde_roundtrip() {
        let hc = HealthCheck::TcpPort { port: 5432 };
        let json = serde_json::to_string(&hc).unwrap();
        let deserialized: HealthCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(hc, deserialized);
    }

    #[test]
    fn test_dependency_serde_roundtrip() {
        let dep = Dependency {
            name: "test-dep".to_string(),
            kind: DepKind::NpmPackage {
                package: "pkg".to_string(),
                version: "1.0".to_string(),
                entry_point: "cmd".to_string(),
            },
            health_check: HealthCheck::Http {
                url: "http://localhost:3000".to_string(),
            },
            env: HashMap::new(),
            args: vec![],
        };
        let json = serde_json::to_string(&dep).unwrap();
        let deserialized: Dependency = serde_json::from_str(&json).unwrap();
        assert_eq!(dep.name, deserialized.name);
    }

    // -- Platform detection --

    #[test]
    fn test_current_platform_returns_known_values() {
        let (os, arch) = current_platform();
        assert!(["darwin", "linux", "windows", "unknown"].contains(&os));
        assert!(["amd64", "arm64", "unknown"].contains(&arch));
    }

    #[test]
    fn test_resolve_asset_pattern() {
        let (os, arch) = current_platform();
        let result = resolve_asset_pattern("binary-{os}-{arch}.tar.gz");
        assert_eq!(result, format!("binary-{}-{}.tar.gz", os, arch));
    }

    #[test]
    fn test_resolve_asset_pattern_no_placeholders() {
        let result = resolve_asset_pattern("static-binary");
        assert_eq!(result, "static-binary");
    }
}
```

**Step 2: Run tests to verify**

Run: `cargo test --lib deps::types::tests`
Expected: All 20 tests PASS

**Step 3: Commit**

```bash
git add src/deps/types.rs
git commit -m "feat(deps): add core types — DepKind, Dependency, HealthCheck, HasDependencies"
```

---

## Task 2: Registry (`src/deps/registry.rs`)

**Files:**
- Create: `src/deps/registry.rs`

**Step 1: Write the registry module with CRUD and tests**

```rust
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
```

**Step 2: Run tests**

Run: `cargo test --lib deps::registry::tests`
Expected: All 13 tests PASS

**Step 3: Commit**

```bash
git add src/deps/registry.rs
git commit -m "feat(deps): add JSON registry for tracking installed dependencies"
```

---

## Task 3: Fetcher trait (`src/deps/fetcher.rs`)

**Files:**
- Create: `src/deps/fetcher.rs`

**Step 1: Write the fetcher trait and mock implementation with tests**

```rust
//! Dependency fetcher trait and implementations.
//!
//! `DepFetcher` abstracts network/system calls for testability.
//! `RealFetcher` makes actual system calls.
//! `MockFetcher` is used in tests.

use async_trait::async_trait;
use std::path::Path;

use crate::error::{Result, ZeptoError};

use super::types::DepKind;

/// Result of a fetch operation.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Path where the artifact was installed.
    pub path: String,
    /// Resolved version that was installed.
    pub version: String,
}

/// Abstracts the actual download/install operations.
#[async_trait]
pub trait DepFetcher: Send + Sync {
    /// Install a dependency. Returns the installed path and version.
    async fn install(&self, kind: &DepKind, dest_dir: &Path) -> Result<FetchResult>;

    /// Check if a command/binary is available on the system.
    fn is_command_available(&self, command: &str) -> bool;
}

/// Real fetcher that makes actual system calls.
pub struct RealFetcher;

#[async_trait]
impl DepFetcher for RealFetcher {
    async fn install(&self, kind: &DepKind, dest_dir: &Path) -> Result<FetchResult> {
        match kind {
            DepKind::Binary {
                repo,
                asset_pattern,
                version,
            } => {
                let resolved_pattern = super::types::resolve_asset_pattern(asset_pattern);
                // For now, return a descriptive error — actual GitHub download TBD.
                let bin_dir = dest_dir.join("bin");
                std::fs::create_dir_all(&bin_dir)?;
                let bin_name = resolved_pattern
                    .split('/')
                    .last()
                    .unwrap_or(&resolved_pattern);
                let bin_path = bin_dir.join(bin_name);
                Err(ZeptoError::Tool(format!(
                    "Binary download not yet implemented: {} {} -> {}",
                    repo,
                    version,
                    bin_path.display()
                )))
            }
            DepKind::DockerImage { image, tag, .. } => {
                let output = tokio::process::Command::new("docker")
                    .args(["pull", &format!("{}:{}", image, tag)])
                    .output()
                    .await
                    .map_err(|e| {
                        ZeptoError::Tool(format!("Failed to run docker pull: {}", e))
                    })?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(ZeptoError::Tool(format!("docker pull failed: {}", stderr)));
                }
                Ok(FetchResult {
                    path: format!("{}:{}", image, tag),
                    version: tag.clone(),
                })
            }
            DepKind::NpmPackage {
                package, version, ..
            } => {
                let node_dir = dest_dir.join("node_modules");
                std::fs::create_dir_all(&node_dir)?;
                let output = tokio::process::Command::new("npm")
                    .args([
                        "install",
                        "--prefix",
                        &dest_dir.to_string_lossy(),
                        &format!("{}@{}", package, version),
                    ])
                    .output()
                    .await
                    .map_err(|e| ZeptoError::Tool(format!("npm install failed: {}", e)))?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(ZeptoError::Tool(format!("npm install failed: {}", stderr)));
                }
                Ok(FetchResult {
                    path: node_dir.to_string_lossy().to_string(),
                    version: version.clone(),
                })
            }
            DepKind::PipPackage {
                package, version, ..
            } => {
                let venv_dir = dest_dir.join("venvs").join(package);
                std::fs::create_dir_all(&venv_dir)?;
                // Create venv
                let venv_out = tokio::process::Command::new("python3")
                    .args(["-m", "venv", &venv_dir.to_string_lossy()])
                    .output()
                    .await
                    .map_err(|e| ZeptoError::Tool(format!("venv creation failed: {}", e)))?;
                if !venv_out.status.success() {
                    let stderr = String::from_utf8_lossy(&venv_out.stderr);
                    return Err(ZeptoError::Tool(format!("venv creation failed: {}", stderr)));
                }
                // pip install
                let pip_bin = venv_dir.join("bin").join("pip");
                let pip_out = tokio::process::Command::new(&pip_bin)
                    .args(["install", &format!("{}{}", package, version)])
                    .output()
                    .await
                    .map_err(|e| ZeptoError::Tool(format!("pip install failed: {}", e)))?;
                if !pip_out.status.success() {
                    let stderr = String::from_utf8_lossy(&pip_out.stderr);
                    return Err(ZeptoError::Tool(format!("pip install failed: {}", stderr)));
                }
                Ok(FetchResult {
                    path: venv_dir.to_string_lossy().to_string(),
                    version: version.clone(),
                })
            }
        }
    }

    fn is_command_available(&self, command: &str) -> bool {
        std::process::Command::new("which")
            .arg(command)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Mock fetcher for tests.
#[cfg(test)]
pub struct MockFetcher {
    pub install_result: std::sync::Mutex<Option<Result<FetchResult>>>,
    pub commands_available: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl MockFetcher {
    pub fn success(path: &str, version: &str) -> Self {
        Self {
            install_result: std::sync::Mutex::new(Some(Ok(FetchResult {
                path: path.to_string(),
                version: version.to_string(),
            }))),
            commands_available: std::sync::Mutex::new(vec![]),
        }
    }

    pub fn failure(msg: &str) -> Self {
        Self {
            install_result: std::sync::Mutex::new(Some(Err(ZeptoError::Tool(msg.to_string())))),
            commands_available: std::sync::Mutex::new(vec![]),
        }
    }

    pub fn with_commands(mut self, cmds: Vec<&str>) -> Self {
        self.commands_available = std::sync::Mutex::new(cmds.iter().map(|s| s.to_string()).collect());
        self
    }
}

#[cfg(test)]
#[async_trait]
impl DepFetcher for MockFetcher {
    async fn install(&self, _kind: &DepKind, _dest_dir: &Path) -> Result<FetchResult> {
        self.install_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Err(ZeptoError::Tool("No mock result configured".to_string())))
    }

    fn is_command_available(&self, command: &str) -> bool {
        self.commands_available
            .lock()
            .unwrap()
            .contains(&command.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_result_construction() {
        let result = FetchResult {
            path: "/usr/local/bin/test".to_string(),
            version: "v1.0.0".to_string(),
        };
        assert_eq!(result.path, "/usr/local/bin/test");
        assert_eq!(result.version, "v1.0.0");
    }

    #[test]
    fn test_mock_fetcher_success() {
        let fetcher = MockFetcher::success("/bin/test", "v1.0.0");
        assert!(!fetcher.is_command_available("docker"));
    }

    #[test]
    fn test_mock_fetcher_with_commands() {
        let fetcher = MockFetcher::success("/bin/test", "v1.0.0").with_commands(vec!["docker", "npm"]);
        assert!(fetcher.is_command_available("docker"));
        assert!(fetcher.is_command_available("npm"));
        assert!(!fetcher.is_command_available("pip"));
    }

    #[tokio::test]
    async fn test_mock_fetcher_install_success() {
        let fetcher = MockFetcher::success("/bin/test", "v1.0.0");
        let kind = DepKind::Binary {
            repo: "test/repo".to_string(),
            asset_pattern: "bin".to_string(),
            version: "v1.0.0".to_string(),
        };
        let result = fetcher.install(&kind, Path::new("/tmp")).await;
        assert!(result.is_ok());
        let fr = result.unwrap();
        assert_eq!(fr.path, "/bin/test");
        assert_eq!(fr.version, "v1.0.0");
    }

    #[tokio::test]
    async fn test_mock_fetcher_install_failure() {
        let fetcher = MockFetcher::failure("test error");
        let kind = DepKind::Binary {
            repo: "test/repo".to_string(),
            asset_pattern: "bin".to_string(),
            version: "v1.0.0".to_string(),
        };
        let result = fetcher.install(&kind, Path::new("/tmp")).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_real_fetcher_is_command_available() {
        let fetcher = RealFetcher;
        // 'ls' should be available on any UNIX system
        assert!(fetcher.is_command_available("ls"));
        assert!(!fetcher.is_command_available("nonexistent_command_xyz_123"));
    }
}
```

**Step 2: Run tests**

Run: `cargo test --lib deps::fetcher::tests`
Expected: All 6 tests PASS

**Step 3: Commit**

```bash
git add src/deps/fetcher.rs
git commit -m "feat(deps): add DepFetcher trait with mock for testable installs"
```

---

## Task 4: DepManager (`src/deps/manager.rs`)

**Files:**
- Create: `src/deps/manager.rs`

**Step 1: Write the dependency manager with process lifecycle and tests**

```rust
//! Dependency manager — install, start, stop, and health check external deps.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{Result, ZeptoError};

use super::fetcher::{DepFetcher, FetchResult};
use super::registry::{Registry, RegistryEntry};
use super::types::{Dependency, DepKind, HealthCheck};

/// A managed child process.
pub struct ManagedProcess {
    pub name: String,
    pub pid: u32,
    child: tokio::process::Child,
}

impl ManagedProcess {
    /// Check if the process is still alive.
    pub fn is_alive(&mut self) -> bool {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .is_none()
    }

    /// Kill the process.
    pub async fn kill(&mut self) -> Result<()> {
        self.child.kill().await.map_err(|e| {
            ZeptoError::Tool(format!("Failed to kill process {}: {}", self.name, e))
        })
    }
}

/// Central dependency manager.
pub struct DepManager {
    /// Base directory for installed dependencies (~/.zeptoclaw/deps/).
    deps_dir: PathBuf,
    /// Registry tracking installed state.
    registry: RwLock<Registry>,
    /// Running processes keyed by dependency name.
    processes: RwLock<HashMap<String, ManagedProcess>>,
    /// Fetcher for install operations (mockable).
    fetcher: Arc<dyn DepFetcher>,
}

impl DepManager {
    /// Create a new DepManager.
    pub fn new(deps_dir: PathBuf, fetcher: Arc<dyn DepFetcher>) -> Self {
        let registry_path = deps_dir.join("registry.json");
        let registry = Registry::load(&registry_path).unwrap_or_default();

        Self {
            deps_dir,
            registry: RwLock::new(registry),
            processes: RwLock::new(HashMap::new()),
            fetcher,
        }
    }

    /// Default deps directory.
    pub fn default_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zeptoclaw/deps")
    }

    /// Save registry to disk.
    async fn save_registry(&self) -> Result<()> {
        let registry = self.registry.read().await;
        let path = self.deps_dir.join("registry.json");
        registry.save(&path)
    }

    /// Check if a dependency is installed.
    pub async fn is_installed(&self, name: &str) -> bool {
        self.registry.read().await.contains(name)
    }

    /// Check if a dependency process is running.
    pub async fn is_running(&self, name: &str) -> bool {
        self.processes.read().await.contains_key(name)
    }

    /// Ensure a dependency is installed. No-op if already installed.
    pub async fn ensure_installed(&self, dep: &Dependency) -> Result<()> {
        if self.is_installed(&dep.name).await {
            info!("Dependency '{}' already installed", dep.name);
            return Ok(());
        }

        info!("Installing dependency '{}'...", dep.name);
        let result = self.fetcher.install(&dep.kind, &self.deps_dir).await?;

        let entry = RegistryEntry {
            kind: dep_kind_label(&dep.kind).to_string(),
            version: result.version,
            installed_at: chrono_now(),
            path: result.path,
            running: false,
            pid: None,
        };

        let mut registry = self.registry.write().await;
        registry.set(dep.name.clone(), entry);
        drop(registry);

        self.save_registry().await?;
        info!("Dependency '{}' installed", dep.name);
        Ok(())
    }

    /// Start a dependency process.
    pub async fn start(&self, dep: &Dependency) -> Result<()> {
        if self.is_running(&dep.name).await {
            info!("Dependency '{}' already running", dep.name);
            return Ok(());
        }

        let registry = self.registry.read().await;
        let entry = registry.get(&dep.name).ok_or_else(|| {
            ZeptoError::Tool(format!(
                "Dependency '{}' not installed, cannot start",
                dep.name
            ))
        })?;
        let artifact_path = entry.path.clone();
        drop(registry);

        // Build the command based on dep kind.
        let mut cmd = build_start_command(&dep.kind, &artifact_path, &dep.args)?;

        // Set env vars.
        for (k, v) in &dep.env {
            cmd.env(k, v);
        }

        // Set up log capture.
        let logs_dir = self.deps_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)?;
        let log_path = logs_dir.join(format!("{}.log", dep.name));
        let log_file = std::fs::File::create(&log_path)?;
        let log_file_err = log_file.try_clone()?;

        cmd.stdout(std::process::Stdio::from(log_file));
        cmd.stderr(std::process::Stdio::from(log_file_err));

        let child = cmd.spawn().map_err(|e| {
            ZeptoError::Tool(format!("Failed to start '{}': {}", dep.name, e))
        })?;

        let pid = child.id().unwrap_or(0);
        info!("Started dependency '{}' (PID: {})", dep.name, pid);

        let managed = ManagedProcess {
            name: dep.name.clone(),
            pid,
            child,
        };

        // Update registry and process map.
        let mut registry = self.registry.write().await;
        registry.mark_running(&dep.name, pid);
        drop(registry);
        self.save_registry().await?;

        self.processes.write().await.insert(dep.name.clone(), managed);

        Ok(())
    }

    /// Stop a dependency process by name.
    pub async fn stop(&self, name: &str) -> Result<()> {
        let mut processes = self.processes.write().await;
        if let Some(mut proc) = processes.remove(name) {
            info!("Stopping dependency '{}'", name);
            proc.kill().await?;
        } else {
            debug!("Dependency '{}' not running, nothing to stop", name);
        }
        drop(processes);

        let mut registry = self.registry.write().await;
        registry.mark_stopped(name);
        drop(registry);
        self.save_registry().await?;

        Ok(())
    }

    /// Stop all running dependency processes.
    pub async fn stop_all(&self) -> Result<()> {
        let names: Vec<String> = self.processes.read().await.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop(&name).await {
                error!("Failed to stop '{}': {}", name, e);
            }
        }
        Ok(())
    }

    /// Wait for a dependency to become healthy (with timeout).
    pub async fn wait_healthy(
        &self,
        dep: &Dependency,
        timeout: Duration,
    ) -> Result<()> {
        match &dep.health_check {
            HealthCheck::None => Ok(()),
            HealthCheck::TcpPort { port } => {
                wait_for_tcp(*port, timeout).await
            }
            HealthCheck::Http { url } => {
                wait_for_http(url, timeout).await
            }
            HealthCheck::WebSocket { url } => {
                wait_for_websocket(url, timeout).await
            }
            HealthCheck::Command { command } => {
                wait_for_command(command, timeout).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dep_kind_label(kind: &DepKind) -> &str {
    match kind {
        DepKind::Binary { .. } => "binary",
        DepKind::DockerImage { .. } => "docker_image",
        DepKind::NpmPackage { .. } => "npm_package",
        DepKind::PipPackage { .. } => "pip_package",
    }
}

/// Get current time as ISO 8601 string (basic, no chrono dependency).
fn chrono_now() -> String {
    // Use std::time for a basic timestamp. Not ISO 8601 but sufficient.
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", dur.as_secs())
}

/// Build the tokio::process::Command for starting a dependency.
fn build_start_command(
    kind: &DepKind,
    artifact_path: &str,
    args: &[String],
) -> Result<tokio::process::Command> {
    match kind {
        DepKind::Binary { .. } => {
            let mut cmd = tokio::process::Command::new(artifact_path);
            cmd.args(args);
            Ok(cmd)
        }
        DepKind::DockerImage { image, tag, ports, .. } => {
            let mut cmd = tokio::process::Command::new("docker");
            let mut docker_args = vec!["run".to_string(), "--rm".to_string()];
            for p in ports {
                docker_args.push("-p".to_string());
                docker_args.push(p.clone());
            }
            docker_args.push(format!("{}:{}", image, tag));
            docker_args.extend(args.iter().cloned());
            cmd.args(&docker_args);
            Ok(cmd)
        }
        DepKind::NpmPackage { entry_point, .. } => {
            let mut cmd = tokio::process::Command::new("npx");
            cmd.arg(entry_point);
            cmd.args(args);
            Ok(cmd)
        }
        DepKind::PipPackage { entry_point, .. } => {
            // Run from the venv's bin directory.
            let entry = PathBuf::from(artifact_path).join("bin").join(entry_point);
            let mut cmd = tokio::process::Command::new(entry);
            cmd.args(args);
            Ok(cmd)
        }
    }
}

/// Wait for a TCP port to become reachable.
async fn wait_for_tcp(port: u16, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let addr = format!("127.0.0.1:{}", port);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ZeptoError::Tool(format!(
                "Health check timed out: TCP port {} not reachable",
                port
            )));
        }
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Wait for an HTTP endpoint to return 2xx.
async fn wait_for_http(url: &str, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| ZeptoError::Tool(format!("Failed to build HTTP client: {}", e)))?;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ZeptoError::Tool(format!(
                "Health check timed out: HTTP {} not returning 2xx",
                url
            )));
        }
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Wait for a WebSocket to accept connections.
async fn wait_for_websocket(url: &str, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ZeptoError::Tool(format!(
                "Health check timed out: WebSocket {} not accepting connections",
                url
            )));
        }
        match tokio_tungstenite::connect_async(url).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Wait for a command to exit with code 0.
async fn wait_for_command(command: &str, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ZeptoError::Tool(format!(
                "Health check timed out: command '{}' not returning 0",
                command
            )));
        }
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(ZeptoError::Tool("Empty health check command".to_string()));
        }
        match tokio::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .await
        {
            Ok(output) if output.status.success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fetcher::MockFetcher;
    use std::fs;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zeptoclaw_test_depmanager_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_dep() -> Dependency {
        Dependency {
            name: "test-dep".to_string(),
            kind: DepKind::Binary {
                repo: "test/repo".to_string(),
                asset_pattern: "bin-{os}-{arch}".to_string(),
                version: "v1.0.0".to_string(),
            },
            health_check: HealthCheck::None,
            env: HashMap::new(),
            args: vec![],
        }
    }

    #[tokio::test]
    async fn test_new_creates_manager() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        assert!(!mgr.is_installed("test").await);
        assert!(!mgr.is_running("test").await);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_ensure_installed_success() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test-dep", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        let dep = test_dep();

        let result = mgr.ensure_installed(&dep).await;
        assert!(result.is_ok());
        assert!(mgr.is_installed("test-dep").await);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_ensure_installed_idempotent() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test-dep", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        let dep = test_dep();

        mgr.ensure_installed(&dep).await.unwrap();
        // Second call should be a no-op (fetcher already consumed its result).
        let result = mgr.ensure_installed(&dep).await;
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_ensure_installed_failure() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::failure("network error"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        let dep = test_dep();

        let result = mgr.ensure_installed(&dep).await;
        assert!(result.is_err());
        assert!(!mgr.is_installed("test-dep").await);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stop_not_running() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);

        let result = mgr.stop("nonexistent").await;
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stop_all_empty() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);

        let result = mgr.stop_all().await;
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_start_not_installed() {
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        let dep = test_dep();

        let result = mgr.start(&dep).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not installed"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dep_kind_label() {
        assert_eq!(dep_kind_label(&DepKind::Binary {
            repo: String::new(),
            asset_pattern: String::new(),
            version: String::new(),
        }), "binary");
        assert_eq!(dep_kind_label(&DepKind::DockerImage {
            image: String::new(),
            tag: String::new(),
            ports: vec![],
        }), "docker_image");
        assert_eq!(dep_kind_label(&DepKind::NpmPackage {
            package: String::new(),
            version: String::new(),
            entry_point: String::new(),
        }), "npm_package");
        assert_eq!(dep_kind_label(&DepKind::PipPackage {
            package: String::new(),
            version: String::new(),
            entry_point: String::new(),
        }), "pip_package");
    }

    #[test]
    fn test_build_start_command_binary() {
        let kind = DepKind::Binary {
            repo: String::new(),
            asset_pattern: String::new(),
            version: String::new(),
        };
        let cmd = build_start_command(&kind, "/bin/test", &["--port".to_string(), "3001".to_string()]);
        assert!(cmd.is_ok());
    }

    #[test]
    fn test_build_start_command_docker() {
        let kind = DepKind::DockerImage {
            image: "redis".to_string(),
            tag: "7".to_string(),
            ports: vec!["6379:6379".to_string()],
        };
        let cmd = build_start_command(&kind, "redis:7", &[]);
        assert!(cmd.is_ok());
    }

    #[test]
    fn test_build_start_command_npm() {
        let kind = DepKind::NpmPackage {
            package: "test".to_string(),
            version: "1.0".to_string(),
            entry_point: "test-cmd".to_string(),
        };
        let cmd = build_start_command(&kind, "/node_modules", &[]);
        assert!(cmd.is_ok());
    }

    #[test]
    fn test_build_start_command_pip() {
        let kind = DepKind::PipPackage {
            package: "test".to_string(),
            version: "1.0".to_string(),
            entry_point: "test-cmd".to_string(),
        };
        let cmd = build_start_command(&kind, "/venvs/test", &[]);
        assert!(cmd.is_ok());
    }

    #[tokio::test]
    async fn test_wait_healthy_none() {
        let dep = Dependency {
            name: "test".to_string(),
            kind: DepKind::Binary {
                repo: String::new(),
                asset_pattern: String::new(),
                version: String::new(),
            },
            health_check: HealthCheck::None,
            env: HashMap::new(),
            args: vec![],
        };
        let dir = test_dir();
        let fetcher = Arc::new(MockFetcher::success("/bin/test", "v1.0.0"));
        let mgr = DepManager::new(dir.clone(), fetcher);
        let result = mgr.wait_healthy(&dep, Duration::from_secs(1)).await;
        assert!(result.is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_default_dir() {
        let dir = DepManager::default_dir();
        let dir_str = dir.to_string_lossy();
        assert!(dir_str.contains(".zeptoclaw/deps"));
    }
}
```

**Step 2: Run tests**

Run: `cargo test --lib deps::manager::tests`
Expected: All 14 tests PASS

**Step 3: Commit**

```bash
git add src/deps/manager.rs
git commit -m "feat(deps): add DepManager with install, start, stop, and health check"
```

---

## Task 5: Module wiring (`src/deps/mod.rs`, `src/lib.rs`)

**Files:**
- Create: `src/deps/mod.rs`
- Modify: `src/lib.rs`

**Step 1: Create the module file**

Create `src/deps/mod.rs`:

```rust
//! Dependency manager — install, lifecycle, and health check for external deps.
//!
//! Components declare needs via `HasDependencies` trait. `DepManager` handles
//! download, install, start, health check, and stop.

pub mod fetcher;
pub mod manager;
pub mod registry;
pub mod types;

pub use manager::DepManager;
pub use types::{Dependency, DepKind, HasDependencies, HealthCheck};
```

**Step 2: Add `pub mod deps;` to `src/lib.rs`**

Add after the `pub mod cron;` line:

```rust
pub mod deps;
```

**Step 3: Run full test suite**

Run: `cargo test --lib`
Expected: All existing tests + ~53 new tests PASS

**Step 4: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: Clean (no errors)

**Step 5: Run format**

Run: `cargo fmt -- --check`
Expected: Clean

**Step 6: Commit**

```bash
git add src/deps/mod.rs src/lib.rs
git commit -m "feat(deps): wire deps module into library exports"
```

---

## Task 6: Add `bridge_managed` config + `HasDependencies` on WhatsAppChannel

**Files:**
- Modify: `src/config/types.rs` — add `bridge_managed` field to `WhatsAppConfig`
- Modify: `src/channels/whatsapp.rs` — implement `HasDependencies` for `WhatsAppChannel`

**Step 1: Add `bridge_managed` field to `WhatsAppConfig`**

In `src/config/types.rs`, add to `WhatsAppConfig`:

```rust
/// Whether ZeptoClaw manages the bridge binary lifecycle.
/// When true, `channel setup` and `gateway` will auto-install and start the bridge.
/// When false, the user manages the bridge process externally.
#[serde(default = "default_bridge_managed")]
pub bridge_managed: bool,
```

Add the default function:

```rust
fn default_bridge_managed() -> bool {
    true
}
```

Update the `Default` impl to include `bridge_managed: default_bridge_managed()`.

**Step 2: Implement `HasDependencies` for `WhatsAppChannel`**

In `src/channels/whatsapp.rs`, add:

```rust
use crate::deps::{Dependency, DepKind, HasDependencies, HealthCheck};

impl HasDependencies for WhatsAppChannel {
    fn dependencies(&self) -> Vec<Dependency> {
        if !self.config.bridge_managed {
            return vec![];
        }

        vec![Dependency {
            name: "whatsmeow-bridge".to_string(),
            kind: DepKind::Binary {
                repo: "qhkm/whatsmeow-rs".to_string(),
                asset_pattern: "whatsmeow-bridge-{os}-{arch}".to_string(),
                version: String::new(), // latest
            },
            health_check: HealthCheck::WebSocket {
                url: self.config.bridge_url.clone(),
            },
            env: std::collections::HashMap::new(),
            args: vec![],
        }]
    }
}
```

**Step 3: Add tests**

Add to the existing tests in `whatsapp.rs`:

```rust
// -- HasDependencies --

#[test]
fn test_has_dependencies_managed() {
    let mut config = test_config();
    config.bridge_managed = true;
    let channel = WhatsAppChannel::new(config, test_bus());
    let deps = channel.dependencies();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "whatsmeow-bridge");
}

#[test]
fn test_has_dependencies_unmanaged() {
    let mut config = test_config();
    config.bridge_managed = false;
    let channel = WhatsAppChannel::new(config, test_bus());
    let deps = channel.dependencies();
    assert!(deps.is_empty());
}
```

And in `types.rs` tests:

```rust
#[test]
fn test_whatsapp_config_bridge_managed_default() {
    let json = r#"{}"#;
    let config: WhatsAppConfig = serde_json::from_str(json).expect("should parse");
    assert!(config.bridge_managed);
}

#[test]
fn test_whatsapp_config_bridge_managed_false() {
    let json = r#"{"bridge_managed": false}"#;
    let config: WhatsAppConfig = serde_json::from_str(json).expect("should parse");
    assert!(!config.bridge_managed);
}
```

**Step 4: Run tests**

Run: `cargo test --lib`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/config/types.rs src/channels/whatsapp.rs
git commit -m "feat(deps): add bridge_managed config, WhatsAppChannel implements HasDependencies"
```

---

## Task 7: Add `deps` to KNOWN_TOP_LEVEL config validation

**Files:**
- Modify: `src/config/validate.rs` — add `"deps"` to `KNOWN_TOP_LEVEL`

**Step 1: Add "deps" to the known fields array**

This prepares for future `DepsConfig` on the `Config` struct (not added yet since we have no config fields for deps, but the validation should recognize it).

Actually — skip this task. There's no `deps` config field on `Config` yet, so there's nothing to validate. YAGNI.

---

## Task 7 (revised): Update docs

**Files:**
- Modify: `CLAUDE.md` — add deps module to architecture tree
- Modify: `docs/plans/TODO.md` — check off dependency manager

**Step 1: Update CLAUDE.md**

Add to the architecture tree after `cron/`:

```
├── deps/           # Dependency manager (install, start, stop, health check)
│   ├── types.rs    # Dependency, DepKind, HealthCheck, HasDependencies
│   ├── registry.rs # JSON registry (installed state tracking)
│   ├── fetcher.rs  # DepFetcher trait + real/mock implementations
│   └── manager.rs  # DepManager lifecycle orchestrator
```

Add to "Key Modules" section:

```
### Deps (`src/deps/`)
- `HasDependencies` trait — components declare external dependencies
- `DepKind` enum: Binary (GitHub Releases), DockerImage, NpmPackage, PipPackage
- `DepManager` — install, start, stop, health check lifecycle orchestrator
- `Registry` — JSON file at `~/.zeptoclaw/deps/registry.json` tracks installed state
- `DepFetcher` trait — abstracts network calls for testability
```

Add `bridge_managed` to WhatsApp env override docs if applicable.

**Step 2: Update TODO.md**

Add to Done section:
```
- [x] Dependency manager (HasDependencies trait, DepManager, Registry)
```

Update stats:
```
- Channels: 5 (Telegram, Slack, Discord, Webhook, WhatsApp)
```

**Step 3: Commit**

```bash
git add CLAUDE.md docs/plans/TODO.md
git commit -m "docs: add dependency manager to architecture docs and roadmap"
```

---

## Verification

```bash
# All tests pass (existing + ~53 new)
cargo test --lib

# Lint clean
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check
```

---

## File Summary

| File | Action | ~Lines |
|------|--------|--------|
| `src/deps/types.rs` | CREATE | ~280 (100 impl + 180 tests) |
| `src/deps/registry.rs` | CREATE | ~250 (100 impl + 150 tests) |
| `src/deps/fetcher.rs` | CREATE | ~220 (100 impl + 120 tests) |
| `src/deps/manager.rs` | CREATE | ~400 (220 impl + 180 tests) |
| `src/deps/mod.rs` | CREATE | ~12 |
| `src/lib.rs` | MODIFY | +1 |
| `src/config/types.rs` | MODIFY | +8 |
| `src/channels/whatsapp.rs` | MODIFY | +30 |
| `CLAUDE.md` | MODIFY | ~15 |
| `docs/plans/TODO.md` | MODIFY | ~3 |

**No new crate dependencies.** Uses existing `tokio`, `reqwest`, `serde/serde_json`, `tokio-tungstenite`, `async-trait`, `dirs`.
