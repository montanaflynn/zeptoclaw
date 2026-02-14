<p align="center">
  <img src="assets/mascot-no-bg.png" width="200" alt="Zippy — ZeptoClaw mascot">
</p>
<h1 align="center">ZeptoClaw</h1>
<p align="center">
  <strong>AI assistant framework that fits in 5 megabytes.</strong>
</p>
<p align="center">
  <a href="https://zeptoclaw.com/docs/"><img src="https://img.shields.io/badge/docs-zeptoclaw.com-3b82f6?style=for-the-badge&logo=bookstack&logoColor=white" alt="Documentation"></a>
</p>
<p align="center">
  <a href="https://github.com/qhkm/zeptoclaw/actions/workflows/ci.yml"><img src="https://github.com/qhkm/zeptoclaw/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/qhkm/zeptoclaw/releases/latest"><img src="https://img.shields.io/github/v/release/qhkm/zeptoclaw?color=blue" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
</p>

---

```
$ zeptoclaw agent --stream -m "Analyze our API for security issues"

🤖 ZeptoClaw — Streaming analysis...

  [web_fetch]        Fetching API docs...
  [shell]            Running integration tests...
  [longterm_memory]  Storing findings...

→ Found 12 endpoints, 3 missing auth headers, 1 open redirect
→ Saved findings to long-term memory under "api-audit"

✓ Analysis complete in 4.2s
```

A single Rust binary with streaming LLM responses, agent swarms, plugins, batch processing, 5 channels, and container isolation. 17 tools out of the box — extend with JSON plugins or the `Tool` trait.

<p align="center">
  <img src="https://img.shields.io/badge/binary-~5MB-3b82f6" alt="~5MB binary">
  <img src="https://img.shields.io/badge/startup-~50ms-3b82f6" alt="~50ms startup">
  <img src="https://img.shields.io/badge/RAM-~6MB-3b82f6" alt="~6MB RAM">
  <img src="https://img.shields.io/badge/tests-1%2C100%2B-3b82f6" alt="1,100+ tests">
  <img src="https://img.shields.io/badge/crate-single-3b82f6" alt="single crate">
</p>

## Why ZeptoClaw

Most AI agent frameworks ask you to choose: powerful or lightweight. Feature-rich or easy to deploy. Secure or simple.

We refused to choose.

**ZeptoClaw** started as the question: *what if you could run hundreds of isolated AI agents on a single $5 VPS?* Not toy agents — real ones with shell access, web browsing, file management, scheduled tasks, and memory that persists across conversations.

The answer is Rust. No garbage collector. No runtime. No 200MB Docker images. Just a 5MB binary that starts in 50ms, uses 6MB of RAM per tenant, and ships with container isolation so your agent can't `rm -rf /` your server.

ZeptoClaw is the one you deploy when security and multi-tenancy matter more than anything else.

## Install

```bash
# One-liner (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/qhkm/zeptoclaw/main/install.sh | sh

# Homebrew
brew install qhkm/tap/zeptoclaw

# Docker
docker pull ghcr.io/qhkm/zeptoclaw:latest

# Build from source
cargo install zeptoclaw --git https://github.com/qhkm/zeptoclaw
```

## Quick Start

```bash
# Interactive setup (walks you through API keys, channels, workspace)
zeptoclaw onboard

# Talk to your agent
zeptoclaw agent -m "Hello, set up my workspace"

# Stream responses token-by-token
zeptoclaw agent --stream -m "Explain async Rust"

# Use a built-in template
zeptoclaw agent --template researcher -m "Search for Rust agent frameworks"

# Process prompts in batch
zeptoclaw batch --input prompts.txt --output results.jsonl

# Start as a Telegram/Slack/Discord/Webhook gateway
zeptoclaw gateway

# With full container isolation per request
zeptoclaw gateway --containerized
```

## Features

### Core

| Feature | What it does |
|---------|-------------|
| **Multi-Provider LLM** | Claude + OpenAI with SSE streaming, retry with backoff, auto-failover |
| **17 Tools + Plugins** | Shell, filesystem, web, memory, cron, WhatsApp, Google Sheets, and more |
| **Agent Swarms** | Delegate to sub-agents with role-specific prompts and tool whitelists |
| **Batch Mode** | Process hundreds of prompts from text/JSONL files with template support |
| **Agent Templates** | 4 built-in (coder, researcher, writer, analyst) + custom JSON templates |

### Channels & Integration

| Feature | What it does |
|---------|-------------|
| **5-Channel Gateway** | Telegram, Slack, Discord, Webhook, CLI — unified message bus |
| **Plugin System** | JSON manifest plugins auto-discovered from `~/.zeptoclaw/plugins/` |
| **Hooks** | `before_tool`, `after_tool`, `on_error` with Log, Block, and Notify actions |
| **Cron & Heartbeat** | Schedule recurring tasks, proactive check-ins, background spawning |
| **Memory & History** | Workspace memory, long-term key-value store, conversation history |

### Security & Ops

| Feature | What it does |
|---------|-------------|
| **Container Isolation** | Shell execution in Docker or Apple Container per request |
| **Tool Approval Gate** | Policy-based gating — require confirmation for dangerous tools |
| **SSRF Prevention** | DNS pinning, private IP blocking, scheme validation |
| **Shell Blocklist** | Regex patterns blocking reverse shells, rm -rf, privilege escalation |
| **Token Budget & Cost** | Per-session budget enforcement, per-model cost estimation for 8 models |
| **Telemetry** | Prometheus + JSON metrics export, structured logging, per-tenant tracing |
| **Multi-Tenant** | Hundreds of tenants on one VPS — isolated workspaces, ~6MB RAM each |

> **Full documentation** — [zeptoclaw.com/docs](https://zeptoclaw.com/docs/) covers configuration, environment variables, CLI reference, deployment guides, and more.

## Inspired By

ZeptoClaw is inspired by projects in the open-source AI agent ecosystem — OpenClaw, NanoClaw, and PicoClaw — each taking a different approach to the same problem. ZeptoClaw's contribution is Rust's memory safety, async performance, and container isolation for production multi-tenant deployments.

## Development

```bash
cargo test              # 1,100+ tests
cargo clippy -- -D warnings
cargo fmt -- --check
```

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<p align="center">
  <em>ZeptoClaw — Because your AI agent shouldn't need more RAM than your text editor.</em>
</p>
<p align="center">
  Built by <a href="https://github.com/qhkm">Aisar Labs</a>
</p>
