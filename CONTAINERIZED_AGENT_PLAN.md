# Containerized Agent Mode Implementation Plan

> **For Claude:** Use this plan to implement containerized agent mode task-by-task.

**Goal:** Add `--containerized` flag to gateway that spawns agent inside Docker container instead of running in-process, providing isolation for multi-user scenarios.

**Architecture:** Gateway runs on host, spawns Docker container per request via stdin/stdout JSON IPC. Container runs `zeptoclaw agent-stdin` which processes one message and exits.

**Tech Stack:** Rust, tokio, Docker, serde_json

---

## Architecture Overview

```
┌────────────────── Gateway (Host) ──────────────────┐
│  Telegram ─┐                                       │
│  Discord ──┼──► MessageBus ──► ContainerAgentProxy │
│  WhatsApp ─┘                          │            │
└───────────────────────────────────────┼────────────┘
                                        │ stdin/stdout JSON
                        ┌───────────────▼───────────────┐
                        │      Docker Container         │
                        │  zeptoclaw agent-stdin        │
                        │  ┌─────────────────────────┐  │
                        │  │ AgentLoop (processes 1  │  │
                        │  │ message, then exits)    │  │
                        │  └─────────────────────────┘  │
                        │  Mounts: /workspace, /sessions│
                        └───────────────────────────────┘
```

---

## Remaining Tasks

### Task 1: Create Gateway Module with IPC Types (PARTIALLY STARTED)
**Status:** In Progress - `src/gateway/mod.rs` created, need `src/gateway/ipc.rs`

**Files:**
- ✅ Created: `src/gateway/mod.rs`
- ❌ Create: `src/gateway/ipc.rs`

**Step: Create IPC protocol types**

```rust
// src/gateway/ipc.rs
//! IPC protocol for containerized agent communication

use serde::{Deserialize, Serialize};
use crate::bus::InboundMessage;
use crate::config::AgentDefaults;
use crate::session::Session;
use crate::providers::ToolDefinition;

pub const RESPONSE_START_MARKER: &str = "<<<AGENT_RESPONSE_START>>>";
pub const RESPONSE_END_MARKER: &str = "<<<AGENT_RESPONSE_END>>>";

/// Request sent to containerized agent via stdin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub request_id: String,
    pub message: InboundMessage,
    pub agent_config: AgentDefaults,
    pub tools: Vec<ToolDefinition>,
    pub session: Option<Session>,
}

/// Response from containerized agent via stdout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub request_id: String,
    pub result: AgentResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResult {
    Success {
        content: String,
        session: Option<Session>,
    },
    Error {
        message: String,
        code: String,
    },
}

impl AgentResponse {
    pub fn success(request_id: &str, content: &str, session: Option<Session>) -> Self {
        Self {
            request_id: request_id.to_string(),
            result: AgentResult::Success {
                content: content.to_string(),
                session,
            },
        }
    }

    pub fn error(request_id: &str, message: &str, code: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            result: AgentResult::Error {
                message: message.to_string(),
                code: code.to_string(),
            },
        }
    }

    /// Format response with markers for reliable parsing
    pub fn to_marked_json(&self) -> String {
        format!(
            "{}\n{}\n{}",
            RESPONSE_START_MARKER,
            serde_json::to_string(self).unwrap_or_default(),
            RESPONSE_END_MARKER
        )
    }
}

/// Parse response from marked stdout
pub fn parse_marked_response(stdout: &str) -> Option<AgentResponse> {
    let start = stdout.find(RESPONSE_START_MARKER)?;
    let end = stdout.find(RESPONSE_END_MARKER)?;
    let json = stdout[start + RESPONSE_START_MARKER.len()..end].trim();
    serde_json::from_str(json).ok()
}
```

---

### Task 2: Add Container Agent Configuration
**Status:** Not Started

**Files:**
- Modify: `src/config/types.rs`

**Add ContainerAgentConfig struct:**

```rust
/// Configuration for containerized agent mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerAgentConfig {
    /// Docker image for containerized agent
    pub image: String,
    /// Memory limit (e.g., "1g")
    pub memory_limit: Option<String>,
    /// CPU limit (e.g., "2.0")
    pub cpu_limit: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Network mode
    pub network: String,
    /// Extra volume mounts
    pub extra_mounts: Vec<String>,
}

impl Default for ContainerAgentConfig {
    fn default() -> Self {
        Self {
            image: "zeptoclaw:latest".to_string(),
            memory_limit: Some("1g".to_string()),
            cpu_limit: Some("2.0".to_string()),
            timeout_secs: 300,
            network: "none".to_string(),
            extra_mounts: Vec::new(),
        }
    }
}
```

**Add to Config struct:**

```rust
pub struct Config {
    // ... existing fields ...
    #[serde(default)]
    pub container_agent: ContainerAgentConfig,
}
```

---

### Task 3: Implement agent-stdin Subcommand
**Status:** Not Started

**Files:**
- Modify: `src/main.rs`

**Step 1: Add subcommand to CLI**

```rust
#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...

    /// Run agent in stdin/stdout mode (for containerized execution)
    AgentStdin,
}
```

**Step 2: Implement cmd_agent_stdin()**

```rust
async fn cmd_agent_stdin(config: Config) -> Result<()> {
    use std::io::{self, BufRead, Write};
    use zeptoclaw::gateway::{AgentRequest, AgentResponse, RESPONSE_START_MARKER, RESPONSE_END_MARKER};

    // Read JSON request from stdin
    let stdin = io::stdin();
    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;

    let request: AgentRequest = serde_json::from_str(&input)
        .map_err(|e| anyhow::anyhow!("Invalid request JSON: {}", e))?;

    // Create agent with provided config
    let session_manager = SessionManager::new_memory();
    let bus = Arc::new(MessageBus::new());
    let agent = create_agent(config.clone(), bus.clone()).await?;

    // Process the message
    let response = match agent.process_message(&request.message).await {
        Ok(content) => {
            AgentResponse::success(&request.request_id, &content, None)
        }
        Err(e) => AgentResponse::error(&request.request_id, &e.to_string(), "PROCESS_ERROR"),
    };

    // Write response with markers
    println!("{}", response.to_marked_json());
    io::stdout().flush()?;

    Ok(())
}
```

**Step 3: Wire up in main()**

```rust
Some(Commands::AgentStdin) => {
    let config = Config::load().with_context(|| "Failed to load configuration")?;
    cmd_agent_stdin(config).await?;
}
```

---

### Task 4: Implement ContainerAgentProxy
**Status:** Not Started

**Files:**
- Create: `src/gateway/container_agent.rs`

```rust
// src/gateway/container_agent.rs
//! Container-based agent proxy that spawns Docker for each request

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::bus::{InboundMessage, MessageBus, OutboundMessage};
use crate::config::{Config, ContainerAgentConfig};
use crate::error::{PicoError, Result};

use super::ipc::{parse_marked_response, AgentRequest, AgentResponse, AgentResult};

pub struct ContainerAgentProxy {
    config: Config,
    container_config: ContainerAgentConfig,
    bus: Arc<MessageBus>,
    running: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ContainerAgentProxy {
    pub fn new(config: Config, bus: Arc<MessageBus>) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let container_config = config.container_agent.clone();

        Self {
            config,
            container_config,
            bus,
            running: AtomicBool::new(false),
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(PicoError::Config("Container agent proxy already running".into()));
        }

        info!("Starting containerized agent proxy");

        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Container agent proxy shutting down");
                        break;
                    }
                }
                msg = self.bus.consume_inbound() => {
                    match msg {
                        Some(inbound) => {
                            let response = self.process_in_container(&inbound).await;
                            if let Err(e) = self.bus.publish_outbound(response).await {
                                error!("Failed to publish response: {}", e);
                            }
                        }
                        None => {
                            error!("Inbound channel closed");
                            break;
                        }
                    }
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    async fn process_in_container(&self, message: &InboundMessage) -> OutboundMessage {
        let request_id = Uuid::new_v4().to_string();

        let request = AgentRequest {
            request_id: request_id.clone(),
            message: message.clone(),
            agent_config: self.config.agents.defaults.clone(),
            tools: Vec::new(),
            session: None,
        };

        match self.spawn_container(&request).await {
            Ok(response) => {
                match response.result {
                    AgentResult::Success { content, .. } => {
                        OutboundMessage::new(&message.channel, &message.chat_id, &content)
                    }
                    AgentResult::Error { message: err, .. } => {
                        OutboundMessage::new(&message.channel, &message.chat_id, &format!("Error: {}", err))
                    }
                }
            }
            Err(e) => {
                error!("Container execution failed: {}", e);
                OutboundMessage::new(&message.channel, &message.chat_id, &format!("Container error: {}", e))
            }
        }
    }

    async fn spawn_container(&self, request: &AgentRequest) -> Result<AgentResponse> {
        let workspace = dirs::home_dir()
            .unwrap_or_default()
            .join(".zeptoclaw/workspace");

        let sessions_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".zeptoclaw/sessions");

        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "-i".to_string(),
            "--network".to_string(),
            self.container_config.network.clone(),
        ];

        // Resource limits
        if let Some(ref mem) = self.container_config.memory_limit {
            args.push("--memory".to_string());
            args.push(mem.clone());
        }
        if let Some(ref cpu) = self.container_config.cpu_limit {
            args.push("--cpus".to_string());
            args.push(cpu.clone());
        }

        // Volume mounts
        args.push("-v".to_string());
        args.push(format!("{}:/workspace", workspace.display()));
        args.push("-v".to_string());
        args.push(format!("{}:/sessions", sessions_dir.display()));

        // Environment variables for API keys
        if let Some(ref anthropic) = self.config.providers.anthropic {
            if let Some(ref key) = anthropic.api_key {
                args.push("-e".to_string());
                args.push(format!("ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY={}", key));
            }
        }

        // Extra mounts from config
        for mount in &self.container_config.extra_mounts {
            args.push("-v".to_string());
            args.push(mount.clone());
        }

        // Image and command
        args.push(self.container_config.image.clone());
        args.push("zeptoclaw".to_string());
        args.push("agent-stdin".to_string());

        debug!("Spawning container with args: {:?}", args);

        let mut child = Command::new("docker")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PicoError::Config(format!("Failed to spawn container: {}", e)))?;

        // Write request to stdin
        let request_json = serde_json::to_string(request)
            .map_err(|e| PicoError::Config(format!("Failed to serialize request: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(request_json.as_bytes()).await
                .map_err(|e| PicoError::Config(format!("Failed to write to stdin: {}", e)))?;
            stdin.write_all(b"\n").await?;
            stdin.shutdown().await?;
        }

        // Wait for output with timeout
        let timeout = Duration::from_secs(self.container_config.timeout_secs);
        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| PicoError::Config("Container timeout".into()))?
            .map_err(|e| PicoError::Config(format!("Container failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PicoError::Config(format!(
                "Container exited with code {:?}: {}",
                output.status.code(),
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_marked_response(&stdout)
            .ok_or_else(|| PicoError::Config("Failed to parse container response".into()))
    }
}
```

---

### Task 5: Wire Up Gateway with --containerized Flag
**Status:** Not Started

**Files:**
- Modify: `src/main.rs`

**Step 1: Add flag to Gateway command**

```rust
/// Start multi-channel gateway
Gateway {
    /// Run agent in Docker container for isolation
    #[arg(long)]
    containerized: bool,
},
```

**Step 2: Modify cmd_gateway() signature and add container logic**

```rust
async fn cmd_gateway(containerized: bool) -> Result<()> {
    let config = Config::load().with_context(|| "Failed to load configuration")?;

    // ... existing provider validation ...

    let bus = Arc::new(MessageBus::new());

    if containerized {
        info!("Starting gateway with containerized agent mode");

        // Check Docker is available
        let docker_check = tokio::process::Command::new("docker")
            .args(["info"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        if !docker_check.map(|s| s.success()).unwrap_or(false) {
            return Err(anyhow::anyhow!("Docker is not available"));
        }

        // Check image exists
        let image = &config.container_agent.image;
        let image_check = tokio::process::Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        if !image_check.map(|s| s.success()).unwrap_or(false) {
            eprintln!("Warning: Docker image '{}' not found.", image);
            eprintln!("Build it with: docker build -t {} .", image);
            return Err(anyhow::anyhow!("Image '{}' not found", image));
        }

        let proxy = ContainerAgentProxy::new(config.clone(), bus.clone());

        // Start proxy in background
        let proxy_handle = tokio::spawn(async move {
            if let Err(e) = proxy.start().await {
                error!("Container agent proxy error: {}", e);
            }
        });

        // ... rest of channel setup same as before, but use proxy instead of agent ...
    } else {
        // Existing in-process agent code
        let agent = create_agent(config.clone(), bus.clone()).await?;
        // ... existing code ...
    }
}
```

**Step 3: Update main() match arm**

```rust
Some(Commands::Gateway { containerized }) => {
    cmd_gateway(containerized).await?;
}
```

---

### Task 6: Export Gateway Module from Library
**Status:** Not Started

**Files:**
- Modify: `src/lib.rs`

```rust
pub mod gateway;

pub use gateway::{ContainerAgentProxy, AgentRequest, AgentResponse};
```

---

### Task 7: Add Tests
**Status:** Not Started

**Files:**
- Modify or create: `tests/integration.rs`

```rust
#[test]
fn test_container_agent_config() {
    use zeptoclaw::config::Config;

    let json = r#"{
        "container_agent": {
            "image": "zeptoclaw:custom",
            "memory_limit": "2g",
            "timeout_secs": 600
        }
    }"#;

    let config: Config = serde_json::from_str(json).unwrap();
    assert_eq!(config.container_agent.image, "zeptoclaw:custom");
    assert_eq!(config.container_agent.memory_limit, Some("2g".to_string()));
    assert_eq!(config.container_agent.timeout_secs, 600);
}

#[test]
fn test_ipc_response_markers() {
    use zeptoclaw::gateway::{AgentResponse, parse_marked_response};

    let response = AgentResponse::success("req-123", "Hello!", None);
    let marked = response.to_marked_json();

    assert!(marked.contains("<<<AGENT_RESPONSE_START>>>"));
    assert!(marked.contains("<<<AGENT_RESPONSE_END>>>"));

    let parsed = parse_marked_response(&marked).unwrap();
    assert_eq!(parsed.request_id, "req-123");
}
```

---

## Dependencies to Add

Add `uuid` and `dirs` to `Cargo.toml` if not present:

```toml
[dependencies]
uuid = { version = "1", features = ["v4"] }
dirs = "5"
```

---

## Verification Commands

```bash
# Build
cargo build --release

# Build Docker image (must be done first)
docker build -t zeptoclaw:latest .

# Test agent-stdin directly
echo '{"request_id":"test","message":{"channel":"test","chat_id":"1","sender_id":"u1","content":"Hello","session_key":"test:1","metadata":{}},"agent_config":{},"tools":[],"session":null}' | \
  docker run -i -e ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY zeptoclaw:latest zeptoclaw agent-stdin

# Run gateway with containerized mode
ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY=your-key cargo run -- gateway --containerized

# Run tests
cargo test
```

---

## Usage

```bash
# Standard mode (agent in-process)
zeptoclaw gateway

# Containerized mode (agent in Docker)
zeptoclaw gateway --containerized

# With custom image
ZEPTOCLAW_CONTAINER_AGENT_IMAGE=myregistry/zeptoclaw:v1 zeptoclaw gateway --containerized
```

---

## Notes

- The `src/gateway/mod.rs` file was partially created but references `container_agent` module which doesn't exist yet
- AgentDefaults in config needs to derive Clone and Serialize/Deserialize (check if already done)
- May need to add a `Runtime` error variant to `PicoError` enum for container-specific errors
