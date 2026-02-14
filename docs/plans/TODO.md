# ZeptoClaw Roadmap

## Process

After completing any feature, update:
1. **This file** — check off items
2. **`CLAUDE.md`** — architecture tree, test counts, module docs, CLI flags
3. **`AGENTS.md`** — project snapshot

---

## Done

- [x] Tool result sanitization
- [x] Parallel tool execution
- [x] Agent-level timeout
- [x] Config validation CLI
- [x] Message queue modes
- [x] Agent swarm (DelegateTool)
- [x] Streaming responses (Claude + OpenAI SSE)
- [x] RetryProvider + FallbackProvider
- [x] MetricsCollector
- [x] Conversation history CLI
- [x] Token budget
- [x] Structured output (OutputFormat)
- [x] Long-term memory tool
- [x] Webhook channel
- [x] Discord channel
- [x] Tool approval gate
- [x] Agent templates
- [x] Plugin system
- [x] Telemetry export
- [x] Cost tracking
- [x] Batch mode
- [x] Hooks system
- [x] Deploy templates (Docker, Fly.io, Railway, Render)
- [x] GitHub Actions CI + Release workflow
- [x] Safety layer (injection detection, leak scanning, policy engine)
- [x] Context compaction
- [x] MCP client
- [x] Routines (event/webhook/cron triggers)
- [x] Landing page + animations
- [x] WhatsApp channel (via whatsmeow-rs bridge)
- [x] CLI channel management (channel list/setup/test)

---

## Backlog

- [ ] CLI surface smoke tests
- [ ] Web UI (browser-based chat)
- [ ] Pre-commit hooks
- [ ] Audit `.clone()` calls

---

## Stats

- Tests: ~1,314 total
- Tools: 15 built-in + MCP + plugins
- Channels: 4 (Telegram, Slack, Discord, Webhook)
- Providers: 2 (Claude, OpenAI) + Retry + Fallback
