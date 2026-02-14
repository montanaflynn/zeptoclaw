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
                let bin_dir = dest_dir.join("bin");
                std::fs::create_dir_all(&bin_dir)?;
                let bin_name = resolved_pattern
                    .split('/')
                    .next_back()
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
                    .map_err(|e| ZeptoError::Tool(format!("Failed to run docker pull: {}", e)))?;
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
                let venv_out = tokio::process::Command::new("python3")
                    .args(["-m", "venv", &venv_dir.to_string_lossy()])
                    .output()
                    .await
                    .map_err(|e| ZeptoError::Tool(format!("venv creation failed: {}", e)))?;
                if !venv_out.status.success() {
                    let stderr = String::from_utf8_lossy(&venv_out.stderr);
                    return Err(ZeptoError::Tool(format!(
                        "venv creation failed: {}",
                        stderr
                    )));
                }
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
        self.commands_available =
            std::sync::Mutex::new(cmds.iter().map(|s| s.to_string()).collect());
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
        let fetcher =
            MockFetcher::success("/bin/test", "v1.0.0").with_commands(vec!["docker", "npm"]);
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
        assert!(fetcher.is_command_available("ls"));
        assert!(!fetcher.is_command_available("nonexistent_command_xyz_123"));
    }
}
