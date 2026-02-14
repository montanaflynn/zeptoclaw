//! Dependency manager — install, start, stop, and health check external deps.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::error::{Result, ZeptoError};

use super::fetcher::DepFetcher;
use super::registry::{Registry, RegistryEntry};
use super::types::{DepKind, Dependency, HealthCheck};

/// A managed child process.
pub struct ManagedProcess {
    pub name: String,
    pub pid: u32,
    child: tokio::process::Child,
}

impl ManagedProcess {
    /// Check if the process is still alive.
    pub fn is_alive(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none()
    }

    /// Kill the process.
    pub async fn kill(&mut self) -> Result<()> {
        self.child
            .kill()
            .await
            .map_err(|e| ZeptoError::Tool(format!("Failed to kill process {}: {}", self.name, e)))
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

        let child = cmd
            .spawn()
            .map_err(|e| ZeptoError::Tool(format!("Failed to start '{}': {}", dep.name, e)))?;

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

        self.processes
            .write()
            .await
            .insert(dep.name.clone(), managed);

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
    pub async fn wait_healthy(&self, dep: &Dependency, timeout: Duration) -> Result<()> {
        match &dep.health_check {
            HealthCheck::None => Ok(()),
            HealthCheck::TcpPort { port } => wait_for_tcp(*port, timeout).await,
            HealthCheck::Http { url } => wait_for_http(url, timeout).await,
            HealthCheck::WebSocket { url } => wait_for_websocket(url, timeout).await,
            HealthCheck::Command { command } => wait_for_command(command, timeout).await,
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

/// Get current time as a basic timestamp string (no chrono dependency).
fn chrono_now() -> String {
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
        DepKind::DockerImage {
            image, tag, ports, ..
        } => {
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
    use super::super::fetcher::MockFetcher;
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zeptoclaw_test_depmanager_{}_{}",
            std::process::id(),
            id
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
        assert_eq!(
            dep_kind_label(&DepKind::Binary {
                repo: String::new(),
                asset_pattern: String::new(),
                version: String::new(),
            }),
            "binary"
        );
        assert_eq!(
            dep_kind_label(&DepKind::DockerImage {
                image: String::new(),
                tag: String::new(),
                ports: vec![],
            }),
            "docker_image"
        );
        assert_eq!(
            dep_kind_label(&DepKind::NpmPackage {
                package: String::new(),
                version: String::new(),
                entry_point: String::new(),
            }),
            "npm_package"
        );
        assert_eq!(
            dep_kind_label(&DepKind::PipPackage {
                package: String::new(),
                version: String::new(),
                entry_point: String::new(),
            }),
            "pip_package"
        );
    }

    #[test]
    fn test_build_start_command_binary() {
        let kind = DepKind::Binary {
            repo: String::new(),
            asset_pattern: String::new(),
            version: String::new(),
        };
        let cmd = build_start_command(
            &kind,
            "/bin/test",
            &["--port".to_string(), "3001".to_string()],
        );
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
