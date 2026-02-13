# Quick Wins Design: 5 Performance & Reliability Features

Date: 2026-02-14

## Overview

Implement 5 quick-win features inspired by Moltis to improve ZeptoClaw's performance, reliability, and token efficiency.

## Feature 1: Parallel Tool Execution

### Problem
Tool calls execute sequentially in `src/agent/loop.rs:316`. When the LLM requests 3 tool calls (e.g., web_search + read_file + shell), they run one after another. If each takes 2s, that's 6s total instead of ~2s parallel.

### Design
Replace the sequential `for tool_call in &response.tool_calls` loop with `futures::future::join_all`.

**File**: `src/agent/loop.rs`

```rust
// Build all tool futures
let tool_futures: Vec<_> = response.tool_calls.iter().map(|tool_call| {
    let tools = Arc::clone(&self.tools);
    let tool_ctx = tool_ctx.clone();
    let tool_name = tool_call.name.clone();
    let tool_id = tool_call.id.clone();
    let tool_args = tool_call.arguments.clone();
    async move {
        let args: serde_json::Value = serde_json::from_str(&tool_args)
            .unwrap_or(serde_json::json!({"_parse_error": "Invalid JSON"}));
        let start = std::time::Instant::now();
        let tools_guard = tools.read().await;
        let result = match tools_guard.execute_with_context(&tool_name, args, &tool_ctx).await {
            Ok(r) => r,
            Err(e) => format!("Error: {}", e),
        };
        let latency_ms = start.elapsed().as_millis() as u64;
        (tool_id, tool_name, result, latency_ms)
    }
}).collect();

let results = futures::future::join_all(tool_futures).await;
```

### Constraints
- `ToolContext` must implement `Clone` (add derive)
- `tools` RwLock allows concurrent readers — no contention
- Results maintain ordering (join_all preserves order)

## Feature 2: Tool Result Sanitization

### Problem
Tool results can contain large base64 data URIs, hex blobs, or oversized outputs that waste LLM tokens without providing value.

### Design
New function in `src/utils/sanitize.rs`:

```rust
pub fn sanitize_tool_result(result: &str, max_bytes: usize) -> String
```

**Rules (applied in order)**:
1. Strip `data:[mediatype];base64,...` URIs -> `[base64 data removed, N bytes]`
2. Strip hex blobs >= 200 contiguous hex chars -> `[hex data removed, N chars]`
3. Truncate to `max_bytes` (default 51200 = 50KB) -> append `\n...[truncated, N total bytes]`

**Integration point**: `src/agent/loop.rs` — apply after tool execution, before `session.add_message(Message::tool_result(...))`.

### Constants
- `DEFAULT_MAX_RESULT_BYTES: usize = 51_200` (50KB)
- `MIN_HEX_BLOB_LEN: usize = 200`

## Feature 3: Agent-Level Timeout

### Problem
A runaway agent (infinite tool loop, hanging API call) can block a session forever. The per-request provider timeout (120s) only covers individual LLM calls, not the entire multi-turn tool loop.

### Design
Wrap `process_message` invocation in `AgentLoop::start()` with `tokio::time::timeout`.

**Config addition** in `AgentDefaults`:
```rust
pub agent_timeout_secs: u64,  // default: 300
```

**Integration** in `loop.rs` start() method:
```rust
let timeout = std::time::Duration::from_secs(self.config.agents.defaults.agent_timeout_secs);
match tokio::time::timeout(timeout, self.process_message(msg_ref)).await {
    Ok(result) => { /* existing handling */ }
    Err(_) => {
        error!("Agent run timed out after {}s", timeout.as_secs());
        let error_msg = OutboundMessage::new(
            &msg_ref.channel, &msg_ref.chat_id,
            &format!("Agent run timed out after {}s", timeout.as_secs()),
        );
        bus_ref.publish_outbound(error_msg).await.ok();
    }
}
```

## Feature 4: Config Validation CLI

### Problem
No way to check if config.json is valid before running. Typos in field names silently ignored by `#[serde(default)]`.

### Design
New subcommand: `zeptoclaw config check`

**Implementation** in `src/main.rs`:
1. Load raw JSON from config file
2. Walk all keys recursively
3. Compare against known fields from Config struct
4. Report unknown fields with Levenshtein distance suggestions
5. Report security warnings

**Validation checks**:
- Unknown fields at any nesting level
- Empty `allow_from` lists (security warning)
- Missing API keys for configured provider
- Native runtime without security considerations

**Output format**:
```
Config file: ~/.zeptoclaw/config.json
[OK] Valid JSON
[OK] All fields recognized
[WARN] channels.telegram.allow_from is empty — anyone can message the bot
[WARN] No Brave Search API key configured — web_search tool will fail
```

**Helper**: Simple Levenshtein distance function for "did you mean?" suggestions.

## Feature 5: Message Queue Modes

### Problem
When a message arrives while the agent is processing another message for the same session, it blocks on the per-session mutex. The user gets no feedback that their message was received, and queued messages execute one-by-one with no batching.

### Design

**Config addition** in `AgentDefaults`:
```rust
pub message_queue_mode: MessageQueueMode,  // default: Collect
```

**Enum**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MessageQueueMode {
    #[default]
    Collect,
    Followup,
}
```

**Implementation** — new field in `AgentLoop`:
```rust
pending_messages: Arc<Mutex<HashMap<String, Vec<InboundMessage>>>>
```

**Collect mode**: When a session is busy, buffer incoming messages. When the active run completes, concatenate all buffered messages into one and process as a single turn:
```
"[Queued messages while I was busy]\n\n1. First message\n2. Second message"
```

**Followup mode**: When a session is busy, buffer incoming messages. When the active run completes, replay each as a separate run in order.

**Key change**: Instead of blocking on the per-session mutex in `process_message`, use `try_lock` first. If locked, add to pending queue and return immediately with an acknowledgment.

## Files Changed

| File | Change |
|------|--------|
| `src/agent/loop.rs` | Parallel tools, timeout, queue modes |
| `src/utils/sanitize.rs` | New: result sanitization |
| `src/utils/mod.rs` | Export sanitize module |
| `src/config/types.rs` | New fields: agent_timeout_secs, message_queue_mode |
| `src/main.rs` | New: `config check` subcommand |
| `src/tools/types.rs` | Add Clone to ToolContext |

## Testing Plan

- Parallel tools: unit test with mock tools verifying concurrent execution
- Sanitization: unit tests for base64 stripping, hex stripping, truncation
- Timeout: integration test with slow mock provider
- Config check: unit tests for unknown field detection, suggestion generation
- Queue modes: unit tests for collect and followup behavior
