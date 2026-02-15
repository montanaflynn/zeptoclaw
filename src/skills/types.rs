//! Skills type definitions.

use serde::{Deserialize, Serialize};

/// Loaded skill model.
#[derive(Debug, Clone)]
pub struct Skill {
    /// Skill name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Absolute path to `SKILL.md`.
    pub path: String,
    /// Source type: `workspace` or `builtin`.
    pub source: String,
    /// Parsed frontmatter metadata.
    pub metadata: SkillMetadata,
    /// Markdown body content.
    pub content: String,
}

/// Skill listing entry.
#[derive(Debug, Clone)]
pub struct SkillInfo {
    /// Skill name.
    pub name: String,
    /// Skill file path.
    pub path: String,
    /// Source type: `workspace` or `builtin`.
    pub source: String,
}

/// Parsed frontmatter metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SkillMetadata {
    /// Skill name.
    pub name: String,
    /// Skill description.
    pub description: String,
    /// Optional version (semver).
    pub version: Option<String>,
    /// Optional homepage URL.
    pub homepage: Option<String>,
    /// ZeptoClaw metadata payload.
    pub metadata: Option<serde_json::Value>,
}

/// ZeptoClaw metadata extension.
/// Compatible with both `metadata.zeptoclaw` and `metadata.openclaw` namespaces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ZeptoMetadata {
    /// Optional emoji for UI and summaries.
    pub emoji: Option<String>,
    /// Runtime requirements.
    pub requires: SkillRequirements,
    /// Suggested install options.
    pub install: Vec<InstallOption>,
    /// Whether to always inject this skill into context.
    pub always: bool,
    /// Platform filter (e.g. `["darwin", "linux", "win32"]`). Empty means all platforms.
    pub os: Vec<String>,
}

/// Requirement model for a skill.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SkillRequirements {
    /// Required binaries in `PATH` (all must be present).
    pub bins: Vec<String>,
    /// At least one of these binaries must be in `PATH` (OpenClaw compat).
    #[serde(default, alias = "anyBins")]
    pub any_bins: Vec<String>,
    /// Required environment variables.
    pub env: Vec<String>,
}

/// Install option metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallOption {
    /// Option identifier.
    pub id: String,
    /// Install kind (`brew`, `apt`, `cargo`, ...).
    pub kind: String,
    /// Optional formula.
    pub formula: Option<String>,
    /// Optional package name.
    pub package: Option<String>,
    /// Binaries expected after install.
    #[serde(default)]
    pub bins: Vec<String>,
    /// User-facing label.
    pub label: String,
}
