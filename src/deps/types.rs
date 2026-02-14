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
