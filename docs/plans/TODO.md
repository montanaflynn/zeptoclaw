# ZeptoClaw Roadmap

> Last updated: 2026-02-14

## Process

After completing any feature, update these 3 files:
1. **This file** (`docs/plans/TODO.md`) — check off items, update "Last updated" date
2. **`CLAUDE.md`** — architecture tree, test counts, module docs, CLI flags
3. **`AGENTS.md`** — "Current State" section, test counts, "Not Yet Wired" list

---

## Completed

### Quick Wins (2026-02-13)
- [x] Tool result sanitization (`src/utils/sanitize.rs`) — strips base64, hex blobs, truncates to 50KB
- [x] Parallel tool execution (`src/agent/loop.rs`) — `futures::future::join_all`
- [x] Agent-level timeout — `agent_timeout_secs` config field (default 300s)
- [x] Config validation CLI (`src/config/validate.rs`) — `zeptoclaw config check`
- [x] Message queue modes — Collect (default) and Followup for busy sessions

### Agent Swarm (2026-02-13)
- [x] SwarmConfig + SwarmRole structs (`src/config/types.rs`)
- [x] DelegateTool (`src/tools/delegate.rs`) — creates sub-agent with role-specific prompt + tool whitelist
- [x] Recursion blocking via channel check
- [x] ProviderRef wrapper for shared provider
- [x] Wired into `create_agent()` after provider resolution

### Streaming Responses (2026-02-14)
- [x] StreamEvent enum + `chat_stream()` default on LLMProvider trait
- [x] Claude SSE streaming (`src/providers/claude.rs`)
- [x] OpenAI SSE streaming (`src/providers/openai.rs`)
- [x] Streaming config field + `--stream` CLI flag
- [x] ProviderRef `chat_stream()` forwarding for delegate tool
- [x] `process_message_streaming()` on AgentLoop
- [x] CLI output wiring (single-message + interactive modes)
- [x] Integration tests

### Provider Infrastructure (2026-02-14)
- [x] RetryProvider (`src/providers/retry.rs`) — exponential backoff on 429/5xx
- [x] FallbackProvider (`src/providers/fallback.rs`) — primary → secondary auto-failover
- [x] MetricsCollector (`src/utils/metrics.rs`) — tool call stats, token tracking, session summary

### Wiring (2026-02-14)
- [x] Config fields for retry/fallback (`config/types.rs`, `config/mod.rs` env overrides)
- [x] RetryProvider wired into provider resolution (`main.rs`) — base → fallback → retry stack
- [x] FallbackProvider wired with multi-provider resolution (`providers/registry.rs`)
- [x] MetricsCollector wired into AgentLoop — tracks tool duration/success + token usage
- [x] Status output shows retry/fallback state

## Backlog — Next Features

### High Priority
- [ ] **Conversation persistence** — persist CLI session history to disk across invocations
- [ ] **Token budget / rate limiting** — per-session token budget with configurable limits
- [ ] **Structured output** — JSON mode / structured output support for providers
- [ ] **Multi-turn memory** — long-term memory across sessions (beyond workspace markdown)

### Medium Priority
- [ ] **Webhook channel** — generic HTTP webhook inbound channel
- [ ] **Discord channel** — Discord bot integration
- [ ] **Tool approval mode** — require user confirmation before executing certain tools
- [ ] **Agent templates** — predefined agent configurations (coder, researcher, writer)
- [ ] **Plugin system** — dynamic tool loading from external crates/WASM

### Low Priority / Nice-to-Have
- [ ] **Web UI** — browser-based chat interface
- [ ] **Telemetry export** — export metrics to Prometheus/OpenTelemetry
- [ ] **Cost tracking** — per-session and per-provider cost estimation
- [ ] **Batch mode** — process multiple prompts from file

## Stats

- Codebase: ~29,600 lines of Rust
- Tests: ~549 lib + 63 integration + 82 doc = ~694 total
- Tools: 14 agent tools
- Providers: 2 (Claude, OpenAI) + RetryProvider + FallbackProvider
