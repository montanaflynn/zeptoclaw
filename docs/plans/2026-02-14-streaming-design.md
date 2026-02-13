# Streaming Responses Design

**Goal:** Add optional token-by-token streaming for CLI mode so users see responses appearing in real-time instead of waiting for the full LLM completion.

**Scope:**
- CLI mode only (Telegram/Slack/channels always get full message at the end)
- Final LLM response only (tool loop iterations remain non-streaming)
- Optional — disabled by default, enabled via `--stream` flag or config

## Architecture

### StreamEvent enum (`src/providers/types.rs`)

```rust
pub enum StreamEvent {
    /// A chunk of text content
    Delta(String),
    /// Tool calls detected mid-stream (fall back to non-streaming tool loop)
    ToolCalls(Vec<LLMToolCall>),
    /// Stream complete — carries assembled full content + usage
    Done { content: String, usage: Option<Usage> },
    /// Provider error mid-stream
    Error(ZeptoError),
}
```

`Done` carries the full assembled content so callers don't have to concatenate deltas.

### LLMProvider trait addition (`src/providers/types.rs`)

New method with a default implementation that wraps the existing `chat()`:

```rust
async fn chat_stream(
    &self,
    messages: Vec<Message>,
    tools: Vec<ToolDefinition>,
    model: Option<&str>,
    options: ChatOptions,
) -> Result<mpsc::Receiver<StreamEvent>> {
    let response = self.chat(messages, tools, model, options).await?;
    let (tx, rx) = mpsc::channel(1);
    tx.send(StreamEvent::Done {
        content: response.content,
        usage: response.usage,
    }).await.ok();
    Ok(rx)
}
```

Providers that support SSE streaming override this method. Those that don't get the non-streaming fallback for free.

### ClaudeProvider streaming (`src/providers/claude.rs`)

Override `chat_stream()` to:
1. Set `"stream": true` in the request JSON body
2. Use `response.bytes_stream()` from reqwest to read SSE events
3. Parse line-by-line:
   - `event: content_block_delta` → `StreamEvent::Delta(text)`
   - `event: content_block_start` with `type: "tool_use"` → collect tool call, emit `StreamEvent::ToolCalls`
   - `event: message_stop` → `StreamEvent::Done { content, usage }`
4. Send events through the `mpsc::Sender<StreamEvent>` channel
5. Spawn a background tokio task to read the SSE stream, so the caller can consume events concurrently

### OpenAI Provider

No changes in v1. Gets the default fallback `chat_stream()` which calls `chat()` and emits a single `Done` event. Can be upgraded later to use OpenAI's `"stream": true` endpoint.

### Agent loop (`src/agent/loop.rs`)

New field on `AgentLoop`:
```rust
streaming: bool  // default false
```

Set by `create_agent()` based on CLI mode + `--stream` flag.

In `process_message()`, only the **final LLM call** changes behavior. After the tool loop ends (no more tool calls), if `self.streaming` is true:

```
if self.streaming {
    let rx = provider.chat_stream(messages, tools, model, options).await?;
    let mut assembled = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            Delta(text) => {
                print!("{}", text);
                assembled.push_str(&text);
            }
            ToolCalls(tc) => {
                // Unexpected tool calls — process them non-streaming
                // Continue tool loop with these calls
            }
            Done { content, usage } => {
                final_response = content;
                break;
            }
            Error(e) => return Err(e),
        }
    }
    println!(); // newline after streaming
} else {
    // existing non-streaming path (unchanged)
}
```

**Tool call handling during streaming:** Since we can't predict whether the LLM will return tool calls, the agent always tries streaming. If `ToolCalls` arrives mid-stream, it falls back to processing them normally and continues the tool loop in non-streaming mode.

### Config (`src/config/types.rs`)

Add to `AgentDefaults`:
```rust
pub streaming: bool,  // default: false
```

### CLI flag (`src/main.rs`)

Add `--stream` flag to the `Agent` command variant:
```rust
Agent {
    #[arg(short, long)]
    message: Option<String>,
    #[arg(long)]
    stream: bool,
}
```

When `--stream` is true OR config `streaming: true`, set `agent.set_streaming(true)`.

### What stays the same

- Channel output (Telegram, Slack) — always non-streaming
- DelegateTool / SpawnTool — non-streaming (sub-agents)
- Tool loop iterations — non-streaming
- OutboundMessage / MessageBus — unchanged
- Session management — unchanged
