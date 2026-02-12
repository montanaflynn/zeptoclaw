//! Web access tools.
//!
//! Provides:
//! - `web_search`: search the web with Brave Search API.
//! - `web_fetch`: fetch URL content and extract readable text.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{PicoError, Result};

use super::{Tool, ToolContext};

const BRAVE_API_URL: &str = "https://api.search.brave.com/res/v1/web/search";
const WEB_USER_AGENT: &str = "zeptoclaw/0.1 (+https://github.com/zeptoclaw/zeptoclaw)";
const MAX_WEB_SEARCH_COUNT: usize = 10;
const DEFAULT_MAX_FETCH_CHARS: usize = 50_000;
const MAX_FETCH_CHARS: usize = 200_000;
const MIN_FETCH_CHARS: usize = 256;

/// Web search tool backed by Brave Search.
pub struct WebSearchTool {
    api_key: String,
    client: Client,
    max_results: usize,
}

impl WebSearchTool {
    /// Create a new web search tool.
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: Client::new(),
            max_results: 5,
        }
    }

    /// Create a web search tool with custom default result count.
    pub fn with_max_results(api_key: &str, max_results: usize) -> Self {
        Self {
            api_key: api_key.to_string(),
            client: Client::new(),
            max_results: max_results.clamp(1, MAX_WEB_SEARCH_COUNT),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BraveResponse {
    web: Option<BraveWebResults>,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    #[serde(default)]
    results: Vec<BraveResult>,
}

#[derive(Debug, Deserialize)]
struct BraveResult {
    title: String,
    url: String,
    #[serde(default)]
    description: Option<String>,
}

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "web_search"
    }

    fn description(&self) -> &str {
        "Search the web and return result titles, URLs, and snippets."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "count": {
                    "type": "integer",
                    "description": "Number of results (1-10)",
                    "minimum": 1,
                    "maximum": 10
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<String> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| PicoError::Tool("Missing 'query' parameter".to_string()))?;

        let count = args
            .get("count")
            .and_then(|v| v.as_u64())
            .map(|c| c as usize)
            .unwrap_or(self.max_results)
            .clamp(1, MAX_WEB_SEARCH_COUNT);

        if self.api_key.trim().is_empty() {
            return Err(PicoError::Tool(
                "Brave Search API key is not configured".to_string(),
            ));
        }

        let response = self
            .client
            .get(BRAVE_API_URL)
            .header("Accept", "application/json")
            .header("User-Agent", WEB_USER_AGENT)
            .header("X-Subscription-Token", &self.api_key)
            .query(&[("q", query), ("count", &count.to_string())])
            .send()
            .await
            .map_err(|e| PicoError::Tool(format!("Web search request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let detail = response.text().await.unwrap_or_default();
            let detail = detail.trim();
            return Err(PicoError::Tool(if detail.is_empty() {
                format!("Brave Search API error: {}", status)
            } else {
                format!("Brave Search API error: {} ({})", status, detail)
            }));
        }

        let payload: BraveResponse = response
            .json()
            .await
            .map_err(|e| PicoError::Tool(format!("Failed to parse search response: {}", e)))?;

        let results = payload
            .web
            .map(|w| w.results)
            .unwrap_or_default()
            .into_iter()
            .take(count)
            .collect::<Vec<_>>();

        if results.is_empty() {
            return Ok(format!("No web search results found for '{}'.", query));
        }

        let mut output = format!("Web search results for '{}':\n\n", query);
        for (index, item) in results.iter().enumerate() {
            output.push_str(&format!("{}. {}\n", index + 1, item.title));
            output.push_str(&format!("   {}\n", item.url));
            if let Some(description) = item.description.as_deref().map(str::trim) {
                if !description.is_empty() {
                    output.push_str(&format!("   {}\n", description));
                }
            }
            output.push('\n');
        }

        Ok(output.trim_end().to_string())
    }
}

/// Web fetch tool for URL content retrieval.
pub struct WebFetchTool {
    client: Client,
    max_chars: usize,
}

impl WebFetchTool {
    /// Create a new web fetch tool.
    pub fn new() -> Self {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            max_chars: DEFAULT_MAX_FETCH_CHARS,
        }
    }

    /// Create with a custom maximum output size.
    pub fn with_max_chars(max_chars: usize) -> Self {
        let mut tool = Self::new();
        tool.max_chars = max_chars.clamp(MIN_FETCH_CHARS, MAX_FETCH_CHARS);
        tool
    }

    fn extract_title(&self, html: &str) -> Option<String> {
        let regex = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
        let captures = regex.captures(html)?;
        let raw = captures.get(1)?.as_str();
        normalize_whitespace(&decode_common_html_entities(raw))
            .trim()
            .to_string()
            .into()
    }

    fn extract_text(&self, html: &str) -> String {
        let without_scripts = strip_regex(html, r"(?is)<script[^>]*>.*?</script>", " ");
        let without_styles = strip_regex(&without_scripts, r"(?is)<style[^>]*>.*?</style>", " ");
        let without_noscript =
            strip_regex(&without_styles, r"(?is)<noscript[^>]*>.*?</noscript>", " ");
        let with_line_breaks = strip_regex(
            &without_noscript,
            r"(?i)</?(p|div|h[1-6]|li|tr|td|th|br)\b[^>]*>",
            "\n",
        );
        let without_tags = strip_regex(&with_line_breaks, r"(?is)<[^>]+>", " ");

        normalize_whitespace(&decode_common_html_entities(&without_tags))
    }
}

impl Default for WebFetchTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "Fetch a URL and return extracted readable content."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "http/https URL to fetch"
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum output characters",
                    "minimum": MIN_FETCH_CHARS,
                    "maximum": MAX_FETCH_CHARS
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> Result<String> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| PicoError::Tool("Missing 'url' parameter".to_string()))?;

        let parsed = Url::parse(url)
            .map_err(|e| PicoError::Tool(format!("Invalid URL '{}': {}", url, e)))?;

        match parsed.scheme() {
            "http" | "https" => {}
            _ => {
                return Err(PicoError::Tool(
                    "Only http/https URLs are allowed".to_string(),
                ));
            }
        }

        if is_blocked_host(&parsed) {
            return Err(PicoError::SecurityViolation(
                "Blocked URL host (local or private network)".to_string(),
            ));
        }

        let max_chars = args
            .get("max_chars")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(self.max_chars)
            .clamp(MIN_FETCH_CHARS, MAX_FETCH_CHARS);

        let response = self
            .client
            .get(parsed.clone())
            .header("User-Agent", WEB_USER_AGENT)
            .send()
            .await
            .map_err(|e| PicoError::Tool(format!("Web fetch failed: {}", e)))?;

        let status = response.status();
        let final_url = response.url().to_string();

        if !status.is_success() {
            return Err(PicoError::Tool(format!("HTTP error: {}", status)));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = response
            .text()
            .await
            .map_err(|e| PicoError::Tool(format!("Failed to read response body: {}", e)))?;

        let (extractor, mut text) = if content_type.contains("application/json") {
            ("json", body)
        } else if content_type.contains("text/html") || body.trim_start().starts_with('<') {
            let title = self.extract_title(&body).unwrap_or_default();
            let extracted = self.extract_text(&body);
            if title.is_empty() {
                ("html", extracted)
            } else {
                ("html", format!("# {}\n\n{}", title, extracted))
            }
        } else {
            ("raw", body)
        };

        let truncated = text.len() > max_chars;
        if truncated {
            text.truncate(max_chars);
        }

        Ok(json!({
            "url": url,
            "final_url": final_url,
            "status": status.as_u16(),
            "extractor": extractor,
            "truncated": truncated,
            "length": text.len(),
            "text": text,
        })
        .to_string())
    }
}

fn strip_regex(input: &str, pattern: &str, replacement: &str) -> String {
    match Regex::new(pattern) {
        Ok(regex) => regex.replace_all(input, replacement).into_owned(),
        Err(_) => input.to_string(),
    }
}

fn normalize_whitespace(input: &str) -> String {
    input
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn decode_common_html_entities(input: &str) -> String {
    let mut decoded = input.replace("&nbsp;", " ");
    decoded = decoded.replace("&amp;", "&");
    decoded = decoded.replace("&lt;", "<");
    decoded = decoded.replace("&gt;", ">");
    decoded = decoded.replace("&quot;", "\"");
    decoded.replace("&#39;", "'")
}

fn is_blocked_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return true;
    };

    let host = host.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_private_or_local_ip(ip);
    }

    false
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_private_or_local_ipv4(addr),
        IpAddr::V6(addr) => is_private_or_local_ipv6(addr),
    }
}

fn is_private_or_local_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified()
        || addr.octets()[0] == 0
}

fn is_private_or_local_ipv6(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];

    addr.is_loopback()
        || addr.is_unspecified()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first & 0xff00) == 0xff00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web_search_tool_properties() {
        let tool = WebSearchTool::new("test-key");
        assert_eq!(tool.name(), "web_search");
        assert!(tool.description().contains("Search the web"));
    }

    #[test]
    fn test_web_fetch_tool_properties() {
        let tool = WebFetchTool::new();
        assert_eq!(tool.name(), "web_fetch");
        assert!(tool.description().contains("Fetch"));
    }

    #[test]
    fn test_extract_title() {
        let tool = WebFetchTool::new();
        let html = "<html><head><title> Test Page </title></head><body>x</body></html>";
        assert_eq!(tool.extract_title(html), Some("Test Page".to_string()));
    }

    #[test]
    fn test_extract_text() {
        let tool = WebFetchTool::new();
        let html = r#"
            <html>
              <body>
                <h1>Hello</h1>
                <p>World</p>
                <script>alert('x')</script>
                <style>body {color: red;}</style>
              </body>
            </html>
        "#;

        let text = tool.extract_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(!text.contains("alert"));
        assert!(!text.contains("color:"));
    }

    #[test]
    fn test_blocked_hosts() {
        let localhost = Url::parse("http://localhost:8080/").unwrap();
        let private_v4 = Url::parse("http://192.168.1.2/").unwrap();
        let public_host = Url::parse("https://example.com/").unwrap();

        assert!(is_blocked_host(&localhost));
        assert!(is_blocked_host(&private_v4));
        assert!(!is_blocked_host(&public_host));
    }
}
