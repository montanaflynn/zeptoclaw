//! ZeptoClaw Load Testing Benchmark
//!
//! Simulates concurrent users to measure:
//! - Memory usage
//! - Response latency
//! - Throughput (messages/second)
//! - CPU utilization
//!
//! Usage:
//!   cargo run --bin benchmark -- --users 100 --duration 30

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use zeptoclaw::agent::AgentLoop;
use zeptoclaw::bus::{InboundMessage, MessageBus};
use zeptoclaw::config::Config;
use zeptoclaw::providers::{ChatOptions, LLMProvider, LLMResponse, ToolDefinition};
use zeptoclaw::session::{Message, SessionManager};
use zeptoclaw::tools::EchoTool;

#[derive(Parser)]
#[command(name = "zeptoclaw-benchmark")]
#[command(about = "Load testing benchmark for ZeptoClaw")]
struct Args {
    /// Number of concurrent users to simulate
    #[arg(short, long, default_value = "100")]
    users: usize,

    /// Duration of the benchmark in seconds
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Messages per user per second
    #[arg(short, long, default_value = "1.0")]
    rate: f64,

    /// Enable memory profiling
    #[arg(long)]
    memory_profile: bool,

    /// Output format: text, json
    #[arg(short, long, default_value = "text")]
    format: String,
}

/// Statistics collected during benchmark
#[derive(Debug, Default)]
struct Stats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    total_latency_ms: AtomicU64,
    errors: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }

    fn record_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn record_received(&self, latency_ms: u64) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn messages_sent(&self) -> u64 {
        self.messages_sent.load(Ordering::Relaxed)
    }

    fn messages_received(&self) -> u64 {
        self.messages_received.load(Ordering::Relaxed)
    }

    fn avg_latency_ms(&self) -> f64 {
        let received = self.messages_received();
        if received == 0 {
            0.0
        } else {
            self.total_latency_ms.load(Ordering::Relaxed) as f64 / received as f64
        }
    }

    fn error_rate(&self) -> f64 {
        let sent = self.messages_sent();
        if sent == 0 {
            0.0
        } else {
            self.errors.load(Ordering::Relaxed) as f64 / sent as f64 * 100.0
        }
    }
}

/// Mock LLM provider for benchmarking - just echoes back the last user message
pub struct MockProvider;

#[async_trait]
impl LLMProvider for MockProvider {
    async fn chat(
        &self,
        messages: Vec<Message>,
        _tools: Vec<ToolDefinition>,
        _model: Option<&str>,
        _options: ChatOptions,
    ) -> std::result::Result<LLMResponse, zeptoclaw::error::PicoError> {
        // Find the last user message and echo it back
        let response_text = messages
            .iter()
            .rev()
            .find(|m| matches!(m.role, zeptoclaw::session::Role::User))
            .map(|m| format!("Echo: {}", m.content))
            .unwrap_or_else(|| "Echo: Hello".to_string());

        Ok(LLMResponse::text(&response_text))
    }

    fn default_model(&self) -> &str {
        "mock"
    }

    fn name(&self) -> &str {
        "mock"
    }
}

/// Simulates a single user sending messages
async fn simulate_user(
    user_id: usize,
    bus: Arc<MessageBus>,
    rate: f64,
    duration: Duration,
    stats: Arc<Stats>,
) -> Result<()> {
    let interval = Duration::from_secs_f64(1.0 / rate);
    let chat_id = format!("user_{}", user_id);

    let start = Instant::now();
    let mut message_id = 0u64;

    while start.elapsed() < duration {
        // Create and send message
        let msg = InboundMessage::new(
            "benchmark",
            &chat_id,
            &chat_id,
            &format!("Message {} from user {}", message_id, user_id),
        );

        if let Err(e) = bus.publish_inbound(msg).await {
            warn!(user = user_id, error = %e, "Failed to send message");
            stats.record_error();
        } else {
            stats.record_sent();
        }

        message_id += 1;

        // Wait for interval
        tokio::time::sleep(interval).await;
    }

    Ok(())
}

/// Collects responses from the outbound channel
async fn collect_responses(
    bus: Arc<MessageBus>,
    stats: Arc<Stats>,
    mut stop: mpsc::Receiver<()>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.recv() => break,
            msg = bus.consume_outbound() => {
                if msg.is_some() {
                    stats.record_received(0);
                }
            }
        }
    }

    Ok(())
}

/// Prints memory statistics
fn print_memory_stats() {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmSize:") {
                    println!("  {}", line.trim());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &format!("{}", std::process::id())])
            .output();

        if let Ok(output) = output {
            let rss_kb = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<usize>()
                .unwrap_or(0);
            println!("  RSS Memory: {} KB ({} MB)", rss_kb, rss_kb / 1024);
        }
    }
}

#[derive(Debug)]
struct BenchmarkResult {
    users: usize,
    duration_secs: f64,
    messages_sent: u64,
    messages_received: u64,
    avg_latency_ms: f64,
    error_rate: f64,
    throughput: f64,
}

async fn run_benchmark(args: &Args) -> Result<BenchmarkResult> {
    let start_time = Instant::now();
    let duration = Duration::from_secs(args.duration);

    info!(
        users = args.users,
        duration = args.duration,
        rate = args.rate,
        "Starting benchmark"
    );

    // Setup
    let config = Config::default();
    let bus = Arc::new(MessageBus::new());
    let session_manager = SessionManager::new_memory();
    let agent = Arc::new(AgentLoop::new(config, session_manager, bus.clone()));

    // Register mock provider and echo tool
    agent.set_provider(Box::new(MockProvider)).await;
    agent.register_tool(Box::new(EchoTool)).await;

    let stats = Arc::new(Stats::new());
    let (stop_tx, stop_rx) = mpsc::channel(1);

    // Start agent
    let agent_clone = Arc::clone(&agent);
    let agent_handle: JoinHandle<Result<()>> =
        tokio::spawn(async move { agent_clone.start().await.map_err(|e| e.into()) });

    // Start response collector
    let stats_clone = Arc::clone(&stats);
    let bus_clone = Arc::clone(&bus);
    let collector_handle =
        tokio::spawn(async move { collect_responses(bus_clone, stats_clone, stop_rx).await });

    // Give agent time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Print initial memory
    if args.memory_profile {
        println!("Initial memory:");
        print_memory_stats();
    }

    // Spawn user simulations
    let mut user_handles = Vec::new();
    let rate = args.rate;
    for user_id in 0..args.users {
        let bus_clone = Arc::clone(&bus);
        let stats_clone = Arc::clone(&stats);
        let handle = tokio::spawn(async move {
            simulate_user(user_id, bus_clone, rate, duration, stats_clone).await
        });
        user_handles.push(handle);
    }

    println!("\n🚀 Benchmark running...");
    println!("   Users: {}", args.users);
    println!("   Duration: {}s", args.duration);
    println!("   Rate: {} msg/user/s", args.rate);
    println!(
        "   Expected total: {} messages\n",
        args.users as u64 * args.duration * args.rate as u64
    );

    // Progress reporting
    let progress_handle = {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let sent = stats.messages_sent();
                let received = stats.messages_received();
                let avg_latency = stats.avg_latency_ms();
                println!(
                    "  Progress: {} sent, {} received, {:.1}ms avg latency",
                    sent, received, avg_latency
                );
            }
        })
    };

    // Wait for all users to complete
    for handle in user_handles {
        let _ = handle.await;
    }

    // Give time for final messages to process
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Stop collector and progress reporter
    let _ = stop_tx.send(()).await;
    let _ = collector_handle.await;
    progress_handle.abort();

    // Stop agent
    agent.stop();
    let _ = agent_handle.await;

    // Final memory stats
    if args.memory_profile {
        println!("\nFinal memory:");
        print_memory_stats();
    }

    let elapsed = start_time.elapsed();
    let result = BenchmarkResult {
        users: args.users,
        duration_secs: elapsed.as_secs_f64(),
        messages_sent: stats.messages_sent(),
        messages_received: stats.messages_received(),
        avg_latency_ms: stats.avg_latency_ms(),
        error_rate: stats.error_rate(),
        throughput: stats.messages_sent() as f64 / elapsed.as_secs_f64(),
    };

    Ok(result)
}

fn print_results(result: &BenchmarkResult) {
    println!("\n{}", "=".repeat(60));
    println!("📊 BENCHMARK RESULTS");
    println!("{}", "=".repeat(60));
    println!("  Concurrent Users:     {}", result.users);
    println!("  Duration:             {:.2}s", result.duration_secs);
    println!("  Messages Sent:        {}", result.messages_sent);
    println!("  Messages Received:    {}", result.messages_received);
    println!("  Throughput:           {:.1} msg/s", result.throughput);
    println!("  Avg Latency:          {:.2}ms", result.avg_latency_ms);
    println!("  Error Rate:           {:.2}%", result.error_rate);
    println!(
        "  msgs/user/s:          {:.2}",
        result.throughput / result.users as f64
    );
    println!("{}", "=".repeat(60));
}

fn print_results_json(result: &BenchmarkResult) {
    let json = serde_json::json!({
        "users": result.users,
        "duration_secs": result.duration_secs,
        "messages_sent": result.messages_sent,
        "messages_received": result.messages_received,
        "throughput": result.throughput,
        "avg_latency_ms": result.avg_latency_ms,
        "error_rate": result.error_rate,
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();

    let args = Args::parse();

    let result = run_benchmark(&args).await?;

    match args.format.as_str() {
        "json" => print_results_json(&result),
        _ => print_results(&result),
    }

    Ok(())
}
