# ZeptoClaw

Rust-based AI agent framework with container isolation. The smallest, fastest, safest member of the Claw family.

## Quick Reference

```bash
# Build
cargo build --release

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Run agent
./target/release/zeptoclaw agent -m "Hello"

# Run gateway (Telegram bot)
./target/release/zeptoclaw gateway

# Run gateway with container isolation
./target/release/zeptoclaw gateway --containerized          # auto-detect
./target/release/zeptoclaw gateway --containerized docker   # force Docker
./target/release/zeptoclaw gateway --containerized apple    # force Apple Container (macOS)

# Validate configuration
./target/release/zeptoclaw config check

# Heartbeat and skills
./target/release/zeptoclaw heartbeat --show
./target/release/zeptoclaw skills list

# Onboard (interactive setup)
./target/release/zeptoclaw onboard
```

## Architecture

```
src/
├── agent/          # Agent loop and context builder
├── bus/            # Async message bus (pub/sub)
├── channels/       # Input channels (Telegram, Slack, CLI)
│   ├── factory.rs  # Channel factory/registry
│   ├── manager.rs  # Channel lifecycle management
│   ├── telegram.rs # Telegram bot channel
│   └── slack.rs    # Slack outbound channel
├── config/         # Configuration types and loading
├── cron/           # Persistent cron scheduler service
├── gateway/        # Containerized agent proxy (Docker/Apple)
├── heartbeat/      # Periodic background task service
├── memory/         # Workspace memory (markdown search)
├── providers/      # LLM providers (Claude, OpenAI)
├── runtime/        # Container runtimes (Native, Docker, Apple)
├── security/       # Shell blocklist, path validation, mount policy
├── session/        # Session and message persistence
├── skills/         # Markdown-based skill system (loader, types)
├── tools/          # Agent tools (14 tools)
│   ├── shell.rs       # Shell execution with runtime isolation
│   ├── filesystem.rs  # Read, write, list, edit files
│   ├── web.rs         # Web search (Brave) and fetch with SSRF protection
│   ├── whatsapp.rs    # WhatsApp Cloud API messaging
│   ├── gsheets.rs     # Google Sheets read/write
│   ├── message.rs     # Proactive channel messaging
│   ├── memory.rs      # Workspace memory get/search
│   ├── cron.rs        # Cron job scheduling
│   ├── spawn.rs       # Background task delegation
│   ├── delegate.rs    # Agent swarm delegation (DelegateTool)
│   └── r8r.rs         # R8r workflow integration
├── utils/          # Utility functions (sanitize tool results)
├── error.rs        # Error types (ZeptoError)
├── lib.rs          # Library exports
└── main.rs         # CLI entry point (~1900 lines)
```

## Key Modules

### Runtime (`src/runtime/`)
Selectable container isolation for shell commands:
- `NativeRuntime` - Direct execution (default)
- `DockerRuntime` - Docker container isolation
- `AppleContainerRuntime` - macOS 15+ native containers

### Gateway (`src/gateway/`)
Containerized agent proxy for full request isolation:
- Stdin/stdout IPC with containerized agent
- Semaphore-based concurrency limiting (`max_concurrent` config)
- Mount allowlist validation, docker binary verification

### Providers (`src/providers/`)
LLM provider abstraction via `LLMProvider` trait:
- `ClaudeProvider` - Anthropic Claude API (120s timeout)
- `OpenAIProvider` - OpenAI Chat Completions API (120s timeout)

### Channels (`src/channels/`)
Message input channels via `Channel` trait:
- `TelegramChannel` - Telegram bot integration
- `SlackChannel` - Slack outbound messaging
- CLI mode via direct agent invocation

### Tools (`src/tools/`)
14 tools via `Tool` async trait. All filesystem tools require workspace.

### Security (`src/security/`)
- `shell.rs` - Regex-based command blocklist
- `path.rs` - Workspace path validation, symlink escape detection
- `mount.rs` - Mount allowlist validation, docker binary verification

## Configuration

Config file: `~/.zeptoclaw/config.json`

Environment variables override config:
- `ZEPTOCLAW_PROVIDERS_ANTHROPIC_API_KEY`
- `ZEPTOCLAW_PROVIDERS_OPENAI_API_KEY`
- `ZEPTOCLAW_CHANNELS_TELEGRAM_BOT_TOKEN`
- `ZEPTOCLAW_AGENTS_DEFAULTS_AGENT_TIMEOUT_SECS` — wall-clock timeout for agent runs (default: 300)
- `ZEPTOCLAW_AGENTS_DEFAULTS_MESSAGE_QUEUE_MODE` — "collect" (default) or "followup"

### Compile-time Configuration

Default models can be set at compile time using environment variables:
- `ZEPTOCLAW_DEFAULT_MODEL` - Default model for agent (default: claude-sonnet-4-5-20250929)
- `ZEPTOCLAW_CLAUDE_DEFAULT_MODEL` - Default Claude model (default: claude-sonnet-4-5-20250929)
- `ZEPTOCLAW_OPENAI_DEFAULT_MODEL` - Default OpenAI model (default: gpt-4o)

Example:
```bash
export ZEPTOCLAW_DEFAULT_MODEL=gpt-4o
cargo build --release
```

## Design Patterns

- **Async-first**: All I/O uses Tokio async runtime
- **Trait-based abstraction**: `LLMProvider`, `Channel`, `Tool`, `ContainerRuntime`
- **Arc for shared state**: `Arc<dyn LLMProvider>`, `Arc<dyn ContainerRuntime>`
- **Parallel tool execution**: `futures::future::join_all` for concurrent tool calls
- **Tool result sanitization**: Strip base64 URIs, hex blobs, truncate to 50KB before LLM
- **Agent-level timeout**: Wall-clock timeout wrapping entire agent runs (default 300s)
- **Message queue modes**: Collect (concatenate) or Followup (replay) for busy sessions
- **Per-session mutex map**: Prevents concurrent message race conditions
- **Semaphore concurrency**: Container gateway limits concurrent requests
- **spawn_blocking**: Wraps sync I/O (memory, filesystem) in async context
- **Conditional compilation**: `#[cfg(target_os = "macos")]` for Apple-specific code

## Testing

```bash
# Unit tests (483 tests)
cargo test --lib

# Integration tests (60 tests)
cargo test --test integration

# All tests (543 total)
cargo test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

## Benchmarks

Verified on Apple Silicon (release build):
- Binary size: ~4MB
- Startup time: ~50ms
- Memory (RSS): ~6MB

## Common Tasks

### Add a new LLM provider
1. Create `src/providers/newprovider.rs`
2. Implement `LLMProvider` trait
3. Export from `src/providers/mod.rs`
4. Wire up in `main.rs` create_agent()

### Add a new tool
1. Create tool in `src/tools/`
2. Implement `Tool` trait with `async fn execute()`
3. Register in `src/tools/mod.rs` and `src/lib.rs`
4. Register in agent setup in `main.rs`

### Add a new channel
1. Create `src/channels/newchannel.rs`
2. Implement `Channel` trait
3. Export from `src/channels/mod.rs`
4. Add to gateway mode in `main.rs`

### Add a new skill
1. Create `~/.zeptoclaw/skills/<name>/SKILL.md`
2. Add YAML frontmatter (name, description, metadata)
3. Add markdown instructions for the agent
4. Or use: `zeptoclaw skills create <name>`

## Dependencies

Key crates:
- `tokio` - Async runtime
- `reqwest` - HTTP client (with 120s timeout)
- `serde` / `serde_json` - Serialization
- `async-trait` - Async trait support
- `tracing` - Structured logging
- `clap` - CLI argument parsing
- `scraper` - HTML parsing for web_fetch
