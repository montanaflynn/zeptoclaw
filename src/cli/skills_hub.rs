//! ClawHub-backed skills commands.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use zeptoclaw::config::Config;
use zeptoclaw::security::encryption::{resolve_master_key, SecretEncryption};
use zeptoclaw::security::validate_path_in_workspace;

use super::common::expand_tilde;
use super::SkillsHubAction;

const DEFAULT_CLAWHUB_REGISTRY: &str = "https://clawhub.ai";
const DEFAULT_CLAWHUB_SITE: &str = "https://clawhub.ai";
const CLAWHUB_USER_AGENT: &str = concat!("zeptoclaw/", env!("CARGO_PKG_VERSION"), " clawhub-cli");
const MAX_BUNDLE_BYTES: usize = 60 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClawHubAuthState {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    registry_url: Option<String>,
    #[serde(default)]
    site_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClawHubLockState {
    #[serde(default)]
    installed: Vec<InstalledSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstalledSkill {
    slug: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    install_path: String,
    installed_at: String,
    source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OriginFile {
    source: String,
    slug: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    installed_at: String,
    registry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateProtection {
    Allow,
    Dirty,
    MissingBaseline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncBump {
    Patch,
    Minor,
    Major,
}

#[derive(Debug, Clone, Serialize)]
struct SyncPlanItem {
    slug: String,
    path: String,
    reason: String,
    current_version: Option<String>,
    next_version: String,
}

#[derive(Debug, Default, Serialize)]
struct SyncReport {
    dry_run: bool,
    planned: Vec<SyncPlanItem>,
    published: Vec<SyncPlanItem>,
    skipped: Vec<String>,
}

struct PublishSkillRequest<'a> {
    slug: &'a str,
    display_name: &'a str,
    version: &'a str,
    changelog: &'a str,
    tags: &'a [String],
    skill_dir: &'a Path,
}

pub(crate) async fn cmd_skills_hub(action: SkillsHubAction) -> Result<()> {
    match action {
        SkillsHubAction::Login { token } => cmd_login(token),
        SkillsHubAction::Whoami { json } => cmd_whoami(json).await,
        SkillsHubAction::Search { query, limit, json } => cmd_search(&query, limit, json).await,
        SkillsHubAction::Explore { limit, sort, json } => cmd_explore(limit, &sort, json).await,
        SkillsHubAction::Inspect {
            slug,
            version,
            tag,
            json,
        } => cmd_inspect(&slug, version.as_deref(), tag.as_deref(), json).await,
        SkillsHubAction::Install {
            slug,
            version,
            tag,
            yes,
        } => cmd_install(&slug, version.as_deref(), tag.as_deref(), yes).await,
        SkillsHubAction::Update { slug, all, force } => {
            cmd_update(slug.as_deref(), all, force).await
        }
        SkillsHubAction::Sync {
            root,
            execute,
            yes,
            bump,
            changelog,
            tags,
            json,
        } => {
            cmd_sync(
                &root,
                execute,
                yes,
                &bump,
                changelog.as_deref(),
                tags.as_deref(),
                json,
            )
            .await
        }
        SkillsHubAction::Uninstall { slug, yes } => cmd_uninstall(&slug, yes),
        SkillsHubAction::List { json } => cmd_list(json),
    }
}

fn cmd_login(token_arg: Option<String>) -> Result<()> {
    let mut state = load_auth_state()?;
    let token = token_arg
        .and_then(non_empty)
        .or_else(resolve_token_from_env)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing ClawHub token. Pass --token <clh_...> or set ZEPTOCLAW_CLAWHUB_TOKEN."
            )
        })?;

    state.token = Some(prepare_token_for_storage(&token)?);
    state.registry_url = Some(resolve_registry_url(&state));
    state.site_url = Some(resolve_site_url(&state));
    save_auth_state(&state)?;

    println!(
        "ClawHub token saved at {}",
        clawhub_auth_state_path().display()
    );
    println!("Registry: {}", resolve_registry_url(&state));
    println!("Site: {}", resolve_site_url(&state));
    if state
        .token
        .as_deref()
        .is_some_and(SecretEncryption::is_encrypted)
    {
        println!("Token storage: encrypted (master key enabled)");
    } else {
        println!("Token storage: plaintext (set ZEPTOCLAW_MASTER_KEY to encrypt)");
    }
    Ok(())
}

async fn cmd_whoami(json: bool) -> Result<()> {
    let state = load_auth_state()?;
    let token = resolve_token(&state)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No ClawHub token configured. Run: zeptoclaw skills hub login --token <...>"
        )
    })?;
    let base = resolve_registry_url(&state);
    let client = build_client()?;

    let payload = fetch_json(
        &client,
        &format!("{}/api/v1/whoami", base),
        Some(token.as_str()),
        &[],
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let user = payload.get("user").unwrap_or(&payload);
    let handle = user
        .get("handle")
        .and_then(Value::as_str)
        .or_else(|| user.get("username").and_then(Value::as_str))
        .unwrap_or("unknown");
    let role = user.get("role").and_then(Value::as_str).unwrap_or("user");
    let id = user
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| user.get("_id").and_then(Value::as_str))
        .unwrap_or("-");

    println!("ClawHub user");
    println!("  Handle: {}", handle);
    println!("  Role: {}", role);
    println!("  ID: {}", id);
    Ok(())
}

async fn cmd_search(query: &str, limit: u32, json: bool) -> Result<()> {
    let state = load_auth_state()?;
    let client = build_client()?;
    let base = resolve_registry_url(&state);
    let params = vec![("q", query.to_string()), ("limit", limit.to_string())];
    let token = resolve_token(&state)?;
    let payload = fetch_json(
        &client,
        &format!("{}/api/v1/search", base),
        token.as_deref(),
        &params,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    print_skill_list(&payload);
    Ok(())
}

async fn cmd_explore(limit: u32, sort: &str, json: bool) -> Result<()> {
    let state = load_auth_state()?;
    let client = build_client()?;
    let base = resolve_registry_url(&state);
    let params = vec![("limit", limit.to_string()), ("sort", sort.to_string())];
    let token = resolve_token(&state)?;
    let payload = fetch_json(
        &client,
        &format!("{}/api/v1/skills", base),
        token.as_deref(),
        &params,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    print_skill_list(&payload);
    Ok(())
}

async fn cmd_inspect(
    slug: &str,
    version: Option<&str>,
    tag: Option<&str>,
    json: bool,
) -> Result<()> {
    validate_slug(slug)?;
    let state = load_auth_state()?;
    let base = resolve_registry_url(&state);
    let token = resolve_token(&state)?;
    let client = build_client()?;

    let params = build_version_tag_params(version, tag);
    let payload = fetch_inspect_payload(&client, &base, token.as_deref(), slug, &params).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let skill = payload.get("skill").unwrap_or(&payload);
    let name = skill
        .get("displayName")
        .and_then(Value::as_str)
        .or_else(|| skill.get("name").and_then(Value::as_str))
        .or_else(|| skill.get("slug").and_then(Value::as_str))
        .unwrap_or(slug);
    let summary = skill
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| skill.get("description").and_then(Value::as_str))
        .unwrap_or("");
    let latest_version = skill
        .pointer("/latestVersion/version")
        .and_then(Value::as_str)
        .or_else(|| skill.get("version").and_then(Value::as_str))
        .unwrap_or("-");
    let owner = skill
        .pointer("/owner/handle")
        .and_then(Value::as_str)
        .or_else(|| skill.get("owner").and_then(Value::as_str))
        .unwrap_or("-");

    println!("Skill: {}", name);
    println!("Slug: {}", slug);
    println!("Owner: {}", owner);
    println!("Latest version: {}", latest_version);
    if !summary.is_empty() {
        println!("Summary: {}", summary);
    }

    if let Some(tags) = skill.get("tags").and_then(Value::as_object) {
        let mut tag_names = tags.keys().cloned().collect::<Vec<_>>();
        tag_names.sort();
        if !tag_names.is_empty() {
            println!("Tags: {}", tag_names.join(", "));
        }
    }

    Ok(())
}

async fn cmd_install(
    slug: &str,
    version: Option<&str>,
    tag: Option<&str>,
    yes: bool,
) -> Result<()> {
    validate_slug(slug)?;
    let state = load_auth_state()?;
    let base = resolve_registry_url(&state);
    let token = resolve_token(&state)?;
    let workspace = skills_workspace_dir()?;
    fs::create_dir_all(&workspace)
        .with_context(|| format!("Failed to create skills workspace {}", workspace.display()))?;

    let workspace_str = workspace.to_string_lossy().to_string();
    let target_dir = validate_path_in_workspace(slug, &workspace_str)?.into_path_buf();
    if target_dir.exists() && !yes {
        anyhow::bail!(
            "Skill '{}' is already installed at {}. Re-run with --yes to overwrite.",
            slug,
            target_dir.display()
        );
    }

    let client = build_client()?;
    let installed = install_or_update_skill(
        &client,
        &base,
        token.as_deref(),
        slug,
        version,
        tag,
        &target_dir,
    )
    .await?;
    upsert_lock_entry(installed)?;

    println!("Installed '{}' to {}", slug, target_dir.display());
    Ok(())
}

async fn cmd_update(slug: Option<&str>, all: bool, force: bool) -> Result<()> {
    if all && slug.is_some() {
        anyhow::bail!("Use either a slug or --all, not both.");
    }
    if !all && slug.is_none() {
        anyhow::bail!("Provide a skill slug or pass --all.");
    }

    let state = load_auth_state()?;
    let base = resolve_registry_url(&state);
    let token = resolve_token(&state)?;
    let workspace = skills_workspace_dir()?;
    fs::create_dir_all(&workspace)
        .with_context(|| format!("Failed to create skills workspace {}", workspace.display()))?;

    let client = build_client()?;
    let lock = load_lock_state()?;
    let targets = if all {
        lock.installed
            .iter()
            .map(|item| item.slug.clone())
            .collect::<Vec<_>>()
    } else {
        vec![slug.unwrap_or_default().to_string()]
    };

    if targets.is_empty() {
        println!("No ClawHub-installed skills found.");
        return Ok(());
    }

    let workspace_str = workspace.to_string_lossy().to_string();
    let mut updated = Vec::new();
    let mut skipped = Vec::new();

    for target_slug in targets {
        validate_slug(&target_slug)?;
        let existing = lock
            .installed
            .iter()
            .find(|item| item.slug == target_slug)
            .cloned();

        if existing.is_none() && !force {
            if all {
                skipped.push(format!("{}: not tracked in lockfile", target_slug));
                continue;
            }
            anyhow::bail!(
                "Skill '{}' is not tracked in {}. Re-run with --force to install anyway.",
                target_slug,
                clawhub_lock_path().display()
            );
        }

        let target_dir = validate_path_in_workspace(&target_slug, &workspace_str)?.into_path_buf();
        if target_dir.exists() {
            let current = compute_skill_fingerprint(&target_dir)?;
            if let Some(entry) = &existing {
                match evaluate_update_protection(entry.fingerprint.as_deref(), &current, force) {
                    UpdateProtection::Allow => {}
                    UpdateProtection::Dirty => {
                        skipped.push(format!("{}: local modifications detected", target_slug));
                        continue;
                    }
                    UpdateProtection::MissingBaseline => {
                        skipped.push(format!(
                            "{}: no fingerprint baseline (re-run with --force)",
                            target_slug
                        ));
                        continue;
                    }
                }
            }
        }

        let version = existing.as_ref().and_then(|item| item.version.as_deref());
        let tag = existing.as_ref().and_then(|item| item.tag.as_deref());
        let installed = install_or_update_skill(
            &client,
            &base,
            token.as_deref(),
            &target_slug,
            version,
            tag,
            &target_dir,
        )
        .await?;
        upsert_lock_entry(installed)?;
        updated.push(target_slug);
    }

    if !updated.is_empty() {
        println!("Updated {} skill(s): {}", updated.len(), updated.join(", "));
    }
    if !skipped.is_empty() {
        println!("Skipped {} skill(s):", skipped.len());
        for reason in skipped {
            println!("  - {}", reason);
        }
    }
    Ok(())
}

async fn cmd_sync(
    roots: &[String],
    execute: bool,
    yes: bool,
    bump_raw: &str,
    changelog: Option<&str>,
    tags_raw: Option<&str>,
    json: bool,
) -> Result<()> {
    if execute && !yes {
        anyhow::bail!("Refusing to execute sync without --yes");
    }

    let bump = parse_sync_bump(bump_raw)?;
    let state = load_auth_state()?;
    let base = resolve_registry_url(&state);
    let token = resolve_token(&state)?;
    if execute && token.is_none() {
        anyhow::bail!("No ClawHub token configured. Run: zeptoclaw skills hub login --token <...>");
    }

    let client = build_client()?;
    let tags = parse_sync_tags(tags_raw);
    let roots = resolve_sync_roots(roots)?;
    let skill_dirs = discover_local_skill_dirs(&roots)?;
    let lock = load_lock_state()?;

    let mut report = SyncReport {
        dry_run: !execute,
        ..SyncReport::default()
    };

    for skill_dir in skill_dirs {
        let raw_name = skill_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let slug = raw_name.to_ascii_lowercase();
        if let Err(err) = validate_slug(&slug) {
            report
                .skipped
                .push(format!("{}: invalid slug ({})", raw_name, err));
            continue;
        }

        let fingerprint = compute_skill_fingerprint(&skill_dir)?;
        let lock_entry = lock.installed.iter().find(|item| item.slug == slug);
        if lock_entry
            .and_then(|item| item.fingerprint.as_deref())
            .is_some_and(|known| known == fingerprint)
        {
            continue;
        }

        let remote_latest =
            match fetch_remote_latest_version(&client, &base, token.as_deref(), &slug).await {
                Ok(version) => version,
                Err(err) => {
                    if let Some(version) = lock_entry.and_then(|item| item.version.clone()) {
                        Some(version)
                    } else {
                        report.skipped.push(format!(
                            "{}: failed resolving remote version ({})",
                            slug, err
                        ));
                        continue;
                    }
                }
            };

        let next_version = match bump_semver(remote_latest.as_deref(), bump) {
            Ok(version) => version,
            Err(err) => {
                report
                    .skipped
                    .push(format!("{}: invalid version source ({})", slug, err));
                continue;
            }
        };

        let reason = if lock_entry.is_some() {
            "changed".to_string()
        } else {
            "new".to_string()
        };
        let plan = SyncPlanItem {
            slug: slug.clone(),
            path: skill_dir.to_string_lossy().to_string(),
            reason,
            current_version: remote_latest.clone(),
            next_version: next_version.clone(),
        };
        report.planned.push(plan.clone());

        if !execute {
            continue;
        }

        let display_name = infer_display_name(&skill_dir, &slug)?;
        let publish = PublishSkillRequest {
            slug: &slug,
            display_name: &display_name,
            version: &next_version,
            changelog: changelog.unwrap_or("Synced via ZeptoClaw CLI"),
            tags: &tags,
            skill_dir: &skill_dir,
        };
        publish_skill_from_dir(
            &client,
            &base,
            token.as_deref().unwrap_or_default(),
            &publish,
        )
        .await?;

        let installed = InstalledSkill {
            slug: slug.clone(),
            version: Some(next_version),
            tag: None,
            fingerprint: Some(fingerprint),
            install_path: skill_dir.to_string_lossy().to_string(),
            installed_at: Utc::now().to_rfc3339(),
            source: "clawhub-sync".to_string(),
        };
        write_origin_file(&skill_dir, &installed, &base)?;
        upsert_lock_entry(installed)?;
        report.published.push(plan);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.planned.is_empty() {
        println!("No new or changed local skills to sync.");
        if !report.skipped.is_empty() {
            println!("Skipped {} skill(s):", report.skipped.len());
            for skipped in report.skipped {
                println!("  - {}", skipped);
            }
        }
        return Ok(());
    }

    if report.dry_run {
        println!("Sync plan (dry-run):");
        for item in &report.planned {
            let current = item.current_version.as_deref().unwrap_or("-");
            println!(
                "  - {} [{}] {} -> {} ({})",
                item.slug, item.reason, current, item.next_version, item.path
            );
        }
        println!("Re-run with --execute --yes to publish.");
    } else {
        println!("Published {} skill(s).", report.published.len());
        for item in &report.published {
            println!("  - {} -> {}", item.slug, item.next_version);
        }
    }

    if !report.skipped.is_empty() {
        println!("Skipped {} skill(s):", report.skipped.len());
        for skipped in report.skipped {
            println!("  - {}", skipped);
        }
    }
    Ok(())
}

async fn install_or_update_skill(
    client: &Client,
    base: &str,
    token: Option<&str>,
    slug: &str,
    version: Option<&str>,
    tag: Option<&str>,
    target_dir: &Path,
) -> Result<InstalledSkill> {
    if target_dir.exists() {
        fs::remove_dir_all(target_dir)
            .with_context(|| format!("Failed to remove existing {}", target_dir.display()))?;
    }

    let bundle = download_skill_bundle(client, base, token, slug, version, tag).await?;
    extract_bundle_to_target(&bundle, target_dir)?;
    let fingerprint = compute_skill_fingerprint(target_dir)?;

    let installed = InstalledSkill {
        slug: slug.to_string(),
        version: version.map(str::to_string).and_then(non_empty),
        tag: tag.map(str::to_string).and_then(non_empty),
        fingerprint: Some(fingerprint),
        install_path: target_dir.to_string_lossy().to_string(),
        installed_at: Utc::now().to_rfc3339(),
        source: "clawhub".to_string(),
    };

    write_origin_file(target_dir, &installed, base)?;
    Ok(installed)
}

fn cmd_uninstall(slug: &str, yes: bool) -> Result<()> {
    validate_slug(slug)?;
    if !yes {
        anyhow::bail!("Refusing to uninstall without --yes");
    }

    let workspace = skills_workspace_dir()?;
    let workspace_str = workspace.to_string_lossy().to_string();
    let target_dir = validate_path_in_workspace(slug, &workspace_str)?.into_path_buf();

    if target_dir.exists() {
        fs::remove_dir_all(&target_dir)
            .with_context(|| format!("Failed to remove {}", target_dir.display()))?;
    }

    remove_lock_entry(slug)?;
    println!("Uninstalled '{}'", slug);
    Ok(())
}

fn cmd_list(json: bool) -> Result<()> {
    let lock = load_lock_state()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&lock)?);
        return Ok(());
    }

    if lock.installed.is_empty() {
        println!("No ClawHub-installed skills found.");
        return Ok(());
    }

    println!("Installed ClawHub skills:");
    for item in &lock.installed {
        let version = item
            .version
            .as_deref()
            .or(item.tag.as_deref())
            .unwrap_or("-");
        println!("  - {} ({})", item.slug, version);
        println!("    {}", item.install_path);
    }
    Ok(())
}

fn write_origin_file(skill_dir: &Path, installed: &InstalledSkill, registry: &str) -> Result<()> {
    let origin = OriginFile {
        source: installed.source.clone(),
        slug: installed.slug.clone(),
        version: installed.version.clone(),
        tag: installed.tag.clone(),
        fingerprint: installed.fingerprint.clone(),
        installed_at: installed.installed_at.clone(),
        registry: registry.to_string(),
    };
    let meta_dir = skill_dir.join(".clawhub");
    fs::create_dir_all(&meta_dir)
        .with_context(|| format!("Failed to create {}", meta_dir.display()))?;
    let origin_path = meta_dir.join("origin.json");
    let raw = serde_json::to_string_pretty(&origin)?;
    fs::write(&origin_path, raw)
        .with_context(|| format!("Failed to write {}", origin_path.display()))?;
    Ok(())
}

async fn fetch_inspect_payload(
    client: &Client,
    base: &str,
    token: Option<&str>,
    slug: &str,
    params: &[(&str, String)],
) -> Result<Value> {
    let primary_url = format!("{}/api/v1/skills/{}", base, slug);
    let mut req = client.get(&primary_url).query(params);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let (status, body) = send_raw(req, &primary_url).await?;

    if status == StatusCode::NOT_FOUND {
        let fallback_url = format!("{}/api/v1/resolve", base);
        let mut fallback_params = vec![("slug", slug.to_string())];
        fallback_params.extend(params.iter().map(|(k, v)| (*k, v.clone())));
        let mut fallback_req = client.get(&fallback_url).query(&fallback_params);
        if let Some(token) = token {
            fallback_req = fallback_req.bearer_auth(token);
        }
        let (fb_status, fb_body) = send_raw(fallback_req, &fallback_url).await?;
        return parse_json_response(fb_status, fb_body, &fallback_url);
    }

    parse_json_response(status, body, &primary_url)
}

async fn download_skill_bundle(
    client: &Client,
    base: &str,
    token: Option<&str>,
    slug: &str,
    version: Option<&str>,
    tag: Option<&str>,
) -> Result<Vec<u8>> {
    let mut params = vec![("slug", slug.to_string())];
    params.extend(build_version_tag_params(version, tag));

    let url = format!("{}/api/v1/download", base);
    let mut req = client.get(&url).query(&params);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }

    let response = req
        .send()
        .await
        .with_context(|| format!("Request failed: {}", url))?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("Failed reading response body: {}", url))?;

    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&bytes)
            .chars()
            .take(300)
            .collect::<String>();
        anyhow::bail!("ClawHub download failed ({}): {}", status.as_u16(), snippet);
    }

    let mut bundle = bytes.to_vec();
    let looks_json = content_type.contains("application/json")
        || bundle.first().copied() == Some(b'{')
        || bundle.first().copied() == Some(b'[');
    if looks_json {
        let payload: Value = serde_json::from_slice(&bundle)
            .with_context(|| "Expected zip payload or JSON download descriptor")?;
        if let Some(download_url) = extract_download_url(&payload) {
            let absolute_url =
                if download_url.starts_with("http://") || download_url.starts_with("https://") {
                    download_url
                } else {
                    format!("{}{}", base, download_url)
                };
            let mut download_req = client.get(&absolute_url);
            if let Some(token) = token {
                download_req = download_req.bearer_auth(token);
            }
            let download_resp = download_req
                .send()
                .await
                .with_context(|| format!("Request failed: {}", absolute_url))?;
            let download_status = download_resp.status();
            let downloaded = download_resp
                .bytes()
                .await
                .with_context(|| format!("Failed reading response body: {}", absolute_url))?;
            if !download_status.is_success() {
                let snippet = String::from_utf8_lossy(&downloaded)
                    .chars()
                    .take(300)
                    .collect::<String>();
                anyhow::bail!(
                    "ClawHub download URL failed ({}): {}",
                    download_status.as_u16(),
                    snippet
                );
            }
            bundle = downloaded.to_vec();
        }
    }

    if bundle.len() > MAX_BUNDLE_BYTES {
        anyhow::bail!(
            "Skill bundle too large ({} bytes, max {})",
            bundle.len(),
            MAX_BUNDLE_BYTES
        );
    }
    Ok(bundle)
}

fn extract_bundle_to_target(bundle: &[u8], target_dir: &Path) -> Result<()> {
    let temp_root = tempfile::tempdir().with_context(|| "Failed to create temp extraction dir")?;
    let zip_path = temp_root.path().join("bundle.zip");
    fs::write(&zip_path, bundle)
        .with_context(|| format!("Failed to write {}", zip_path.display()))?;

    let unzip_check = Command::new("unzip")
        .args(["-Z", "-1"])
        .arg(&zip_path)
        .output()
        .with_context(|| "Failed to run unzip -Z -1 (is 'unzip' installed?)")?;
    if !unzip_check.status.success() {
        let stderr = String::from_utf8_lossy(&unzip_check.stderr);
        anyhow::bail!("Failed listing zip entries: {}", stderr.trim());
    }

    let listing = String::from_utf8_lossy(&unzip_check.stdout);
    for entry in listing.lines() {
        validate_zip_entry_path(entry)?;
    }

    let extract_root = temp_root.path().join("extract");
    fs::create_dir_all(&extract_root)
        .with_context(|| format!("Failed to create {}", extract_root.display()))?;

    let unzip_extract = Command::new("unzip")
        .args(["-qq", "-o"])
        .arg(&zip_path)
        .args(["-d", extract_root.to_string_lossy().as_ref()])
        .output()
        .with_context(|| "Failed to run unzip for extraction")?;
    if !unzip_extract.status.success() {
        let stderr = String::from_utf8_lossy(&unzip_extract.stderr);
        anyhow::bail!("Failed extracting skill zip: {}", stderr.trim());
    }

    let skill_root = find_skill_root(&extract_root)?;
    if !skill_root.join("SKILL.md").is_file() && !skill_root.join("skill.md").is_file() {
        anyhow::bail!("Downloaded skill bundle is missing SKILL.md");
    }

    if target_dir.exists() {
        fs::remove_dir_all(target_dir)
            .with_context(|| format!("Failed to remove {}", target_dir.display()))?;
    }
    fs::create_dir_all(target_dir)
        .with_context(|| format!("Failed to create {}", target_dir.display()))?;
    copy_dir_recursive(&skill_root, target_dir)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("Failed to read {}", src.display()))? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry
            .file_type()
            .with_context(|| format!("Failed to inspect {}", src_path.display()))?
            .is_symlink()
        {
            anyhow::bail!("Refusing to install symlink entry: {}", src_path.display());
        }
        if src_path.is_dir() {
            fs::create_dir_all(&dst_path)
                .with_context(|| format!("Failed to create {}", dst_path.display()))?;
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "Failed to copy {} -> {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn validate_zip_entry_path(entry: &str) -> Result<()> {
    if entry.trim().is_empty() {
        return Ok(());
    }
    let path = Path::new(entry);
    if path.is_absolute() {
        anyhow::bail!("Zip contains absolute path entry: {}", entry);
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("Zip contains traversal path entry: {}", entry);
    }
    Ok(())
}

fn find_skill_root(extract_root: &Path) -> Result<PathBuf> {
    if extract_root.join("SKILL.md").is_file() || extract_root.join("skill.md").is_file() {
        return Ok(extract_root.to_path_buf());
    }

    let mut dirs = fs::read_dir(extract_root)
        .with_context(|| format!("Failed to read {}", extract_root.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    dirs.sort();
    if dirs.len() == 1 {
        return Ok(dirs.remove(0));
    }

    Ok(extract_root.to_path_buf())
}

fn compute_skill_fingerprint(skill_dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_files_for_fingerprint(skill_dir, skill_dir, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel_path, abs_path) in files {
        hasher.update(rel_path.as_bytes());
        hasher.update([0]);

        let mut file = fs::File::open(&abs_path)
            .with_context(|| format!("Failed to open {}", abs_path.display()))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .with_context(|| format!("Failed to read {}", abs_path.display()))?;
        hasher.update((buf.len() as u64).to_le_bytes());
        hasher.update([0]);
        hasher.update(buf);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn collect_files_for_fingerprint(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("Failed to inspect {}", path.display()))?;

        if file_type.is_symlink() {
            anyhow::bail!("Refusing to fingerprint symlink entry: {}", path.display());
        }

        if file_type.is_dir() {
            if path
                .strip_prefix(root)
                .ok()
                .is_some_and(|rel| rel.components().any(|comp| comp.as_os_str() == ".clawhub"))
            {
                continue;
            }
            collect_files_for_fingerprint(root, &path, out)?;
            continue;
        }

        if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .with_context(|| format!("Failed to strip prefix for {}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

fn evaluate_update_protection(
    expected_fingerprint: Option<&str>,
    current_fingerprint: &str,
    force: bool,
) -> UpdateProtection {
    if force {
        return UpdateProtection::Allow;
    }
    match expected_fingerprint {
        Some(expected) if expected == current_fingerprint => UpdateProtection::Allow,
        Some(_) => UpdateProtection::Dirty,
        None => UpdateProtection::MissingBaseline,
    }
}

fn parse_sync_bump(raw: &str) -> Result<SyncBump> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "patch" => Ok(SyncBump::Patch),
        "minor" => Ok(SyncBump::Minor),
        "major" => Ok(SyncBump::Major),
        other => anyhow::bail!("Invalid --bump '{}'. Use patch, minor, or major.", other),
    }
}

fn parse_sync_tags(raw: Option<&str>) -> Vec<String> {
    if let Some(tags) = raw {
        let mut parsed = tags
            .split(',')
            .filter_map(|tag| non_empty(tag.to_string()))
            .collect::<Vec<_>>();
        parsed.sort();
        parsed.dedup();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec!["latest".to_string()]
}

fn resolve_sync_roots(roots: &[String]) -> Result<Vec<PathBuf>> {
    if roots.is_empty() {
        return Ok(vec![skills_workspace_dir()?]);
    }
    Ok(roots.iter().map(|root| expand_tilde(root)).collect())
}

fn discover_local_skill_dirs(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for root in roots {
        if has_skill_markdown(root) {
            dirs.push(root.to_path_buf());
            continue;
        }
        if !root.exists() {
            continue;
        }
        if !root.is_dir() {
            anyhow::bail!("Sync root is not a directory: {}", root.display());
        }
        for entry in
            fs::read_dir(root).with_context(|| format!("Failed to read {}", root.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if has_skill_markdown(&path) {
                dirs.push(path);
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

fn has_skill_markdown(path: &Path) -> bool {
    path.join("SKILL.md").is_file() || path.join("skill.md").is_file()
}

async fn fetch_remote_latest_version(
    client: &Client,
    base: &str,
    token: Option<&str>,
    slug: &str,
) -> Result<Option<String>> {
    let url = format!("{}/api/v1/skills/{}", base, slug);
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let (status, body) = send_raw(req, &url).await?;
    if status == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let payload = parse_json_response(status, body, &url)?;
    Ok(payload
        .pointer("/latestVersion/version")
        .and_then(Value::as_str)
        .or_else(|| payload.pointer("/latestVersion").and_then(Value::as_str))
        .or_else(|| {
            payload
                .pointer("/skill/latestVersion/version")
                .and_then(Value::as_str)
        })
        .or_else(|| payload.get("version").and_then(Value::as_str))
        .map(str::to_string))
}

fn bump_semver(current: Option<&str>, bump: SyncBump) -> Result<String> {
    if current.is_none() {
        return Ok("0.1.0".to_string());
    }
    let (mut major, mut minor, mut patch) = parse_semver_triplet(current.unwrap_or_default())?;
    match bump {
        SyncBump::Patch => patch = patch.saturating_add(1),
        SyncBump::Minor => {
            minor = minor.saturating_add(1);
            patch = 0;
        }
        SyncBump::Major => {
            major = major.saturating_add(1);
            minor = 0;
            patch = 0;
        }
    }
    Ok(format!("{}.{}.{}", major, minor, patch))
}

fn parse_semver_triplet(version: &str) -> Result<(u64, u64, u64)> {
    let core = version
        .split(['-', '+'])
        .next()
        .unwrap_or(version)
        .trim()
        .to_string();
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        anyhow::bail!("Expected semver format x.y.z, got '{}'", version);
    }
    let major = parts[0]
        .parse::<u64>()
        .with_context(|| format!("Invalid semver major in '{}'", version))?;
    let minor = parts[1]
        .parse::<u64>()
        .with_context(|| format!("Invalid semver minor in '{}'", version))?;
    let patch = parts[2]
        .parse::<u64>()
        .with_context(|| format!("Invalid semver patch in '{}'", version))?;
    Ok((major, minor, patch))
}

fn infer_display_name(skill_dir: &Path, fallback_slug: &str) -> Result<String> {
    let skill_doc = if skill_dir.join("SKILL.md").is_file() {
        skill_dir.join("SKILL.md")
    } else {
        skill_dir.join("skill.md")
    };
    if !skill_doc.is_file() {
        return Ok(fallback_slug.to_string());
    }
    let raw = fs::read_to_string(&skill_doc)
        .with_context(|| format!("Failed to read {}", skill_doc.display()))?;
    for line in raw.lines().take(80) {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("name:") {
            if let Some(clean) = non_empty(name.trim_matches('"').trim_matches('\'').to_string()) {
                return Ok(clean);
            }
        }
    }
    Ok(fallback_slug.to_string())
}

async fn publish_skill_from_dir(
    client: &Client,
    base: &str,
    token: &str,
    publish: &PublishSkillRequest<'_>,
) -> Result<()> {
    let files = collect_publish_files(publish.skill_dir)?;
    if files.is_empty() {
        anyhow::bail!("No files found for {}", publish.skill_dir.display());
    }

    let payload = serde_json::json!({
        "slug": publish.slug,
        "displayName": publish.display_name,
        "version": publish.version,
        "changelog": publish.changelog,
        "tags": publish.tags,
    });
    let mut form = Form::new().text("payload", payload.to_string());
    for (path, bytes) in files {
        form = form.part("files", Part::bytes(bytes).file_name(path));
    }

    let url = format!("{}/api/v1/skills", base);
    let req = client.post(&url).bearer_auth(token).multipart(form);
    let (status, body) = send_raw(req, &url).await?;
    if !status.is_success() {
        let snippet = body.chars().take(400).collect::<String>();
        anyhow::bail!("ClawHub publish failed ({}): {}", status.as_u16(), snippet);
    }
    Ok(())
}

fn collect_publish_files(skill_dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    collect_files_for_fingerprint(skill_dir, skill_dir, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::with_capacity(files.len());
    for (rel, abs) in files {
        let bytes = fs::read(&abs)
            .with_context(|| format!("Failed to read file for publish: {}", abs.display()))?;
        out.push((rel, bytes));
    }
    Ok(out)
}

fn build_version_tag_params(
    version: Option<&str>,
    tag: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut params = Vec::new();
    if let Some(v) = version.map(str::to_string).and_then(non_empty) {
        params.push(("version", v));
    }
    if let Some(t) = tag.map(str::to_string).and_then(non_empty) {
        params.push(("tag", t));
    }
    params
}

fn extract_download_url(payload: &Value) -> Option<String> {
    payload
        .get("download_url")
        .and_then(Value::as_str)
        .or_else(|| payload.get("downloadUrl").and_then(Value::as_str))
        .or_else(|| payload.get("url").and_then(Value::as_str))
        .or_else(|| payload.pointer("/download/url").and_then(Value::as_str))
        .map(str::to_string)
}

fn print_skill_list(payload: &Value) {
    let items = extract_items(payload);
    if items.is_empty() {
        println!("No skills found.");
        return;
    }

    println!("Skills:");
    for item in items {
        let slug = item
            .get("slug")
            .and_then(Value::as_str)
            .or_else(|| item.get("id").and_then(Value::as_str))
            .unwrap_or("unknown");
        let version = item
            .pointer("/latestVersion/version")
            .and_then(Value::as_str)
            .or_else(|| item.get("version").and_then(Value::as_str))
            .unwrap_or("-");
        let summary = item
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| item.get("description").and_then(Value::as_str))
            .unwrap_or("");
        if summary.is_empty() {
            println!("  - {} (v{})", slug, version);
        } else {
            println!("  - {} (v{}) — {}", slug, version, summary);
        }
    }
}

fn extract_items(payload: &Value) -> Vec<&Value> {
    if let Some(items) = payload.get("items").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = payload.get("skills").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = payload.get("results").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = payload.as_array() {
        return items.iter().collect();
    }
    Vec::new()
}

fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(CLAWHUB_USER_AGENT)
        .build()
        .with_context(|| "Failed to build ClawHub HTTP client")
}

async fn fetch_json(
    client: &Client,
    url: &str,
    token: Option<&str>,
    query: &[(&str, String)],
) -> Result<Value> {
    let mut req = client.get(url).query(query);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let (status, body) = send_raw(req, url).await?;
    parse_json_response(status, body, url)
}

async fn send_raw(req: reqwest::RequestBuilder, url: &str) -> Result<(StatusCode, String)> {
    let resp = req
        .send()
        .await
        .with_context(|| format!("Request failed: {}", url))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("Failed reading response body: {}", url))?;
    Ok((status, body))
}

fn parse_json_response(status: StatusCode, body: String, url: &str) -> Result<Value> {
    if !status.is_success() {
        let snippet = body.chars().take(400).collect::<String>();
        anyhow::bail!(
            "ClawHub request failed ({}): {} — {}",
            status.as_u16(),
            url,
            snippet
        );
    }
    serde_json::from_str::<Value>(&body)
        .with_context(|| format!("Invalid JSON response from {}", url))
}

fn skills_workspace_dir() -> Result<PathBuf> {
    let config = Config::load().unwrap_or_default();
    Ok(config
        .skills
        .workspace_dir
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| Config::dir().join("skills")))
}

fn clawhub_auth_state_path() -> PathBuf {
    Config::dir().join("clawhub").join("config.json")
}

fn clawhub_lock_path() -> PathBuf {
    Config::dir().join("clawhub").join("lock.json")
}

fn load_auth_state() -> Result<ClawHubAuthState> {
    let path = clawhub_auth_state_path();
    if !path.is_file() {
        return Ok(ClawHubAuthState::default());
    }

    let raw =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let state = serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(state)
}

fn save_auth_state(state: &ClawHubAuthState) -> Result<()> {
    let path = clawhub_auth_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(&path, raw).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn load_lock_state() -> Result<ClawHubLockState> {
    let path = clawhub_lock_path();
    if !path.is_file() {
        return Ok(ClawHubLockState::default());
    }
    let raw =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let lock = serde_json::from_str(&raw)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(lock)
}

fn save_lock_state(state: &ClawHubLockState) -> Result<()> {
    let path = clawhub_lock_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(&path, raw).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn upsert_lock_entry(entry: InstalledSkill) -> Result<()> {
    let mut lock = load_lock_state()?;
    upsert_lock_entry_in_state(&mut lock, entry);
    save_lock_state(&lock)
}

fn remove_lock_entry(slug: &str) -> Result<()> {
    let mut lock = load_lock_state()?;
    remove_lock_entry_in_state(&mut lock, slug);
    save_lock_state(&lock)
}

fn upsert_lock_entry_in_state(lock: &mut ClawHubLockState, entry: InstalledSkill) {
    lock.installed.retain(|skill| skill.slug != entry.slug);
    lock.installed.push(entry);
    lock.installed.sort_by(|a, b| a.slug.cmp(&b.slug));
}

fn remove_lock_entry_in_state(lock: &mut ClawHubLockState, slug: &str) {
    lock.installed.retain(|skill| skill.slug != slug);
}

fn resolve_registry_url(state: &ClawHubAuthState) -> String {
    std::env::var("ZEPTOCLAW_CLAWHUB_REGISTRY")
        .ok()
        .and_then(non_empty)
        .or_else(|| std::env::var("CLAWHUB_REGISTRY").ok().and_then(non_empty))
        .or_else(|| state.registry_url.clone().and_then(non_empty))
        .map(normalize_base_url)
        .unwrap_or_else(|| DEFAULT_CLAWHUB_REGISTRY.to_string())
}

fn resolve_site_url(state: &ClawHubAuthState) -> String {
    std::env::var("ZEPTOCLAW_CLAWHUB_SITE")
        .ok()
        .and_then(non_empty)
        .or_else(|| std::env::var("CLAWHUB_SITE").ok().and_then(non_empty))
        .or_else(|| state.site_url.clone().and_then(non_empty))
        .map(normalize_base_url)
        .unwrap_or_else(|| DEFAULT_CLAWHUB_SITE.to_string())
}

fn resolve_token(state: &ClawHubAuthState) -> Result<Option<String>> {
    if let Some(token) = resolve_token_from_env() {
        return Ok(Some(token));
    }
    let stored = match state.token.clone().and_then(non_empty) {
        Some(token) => token,
        None => return Ok(None),
    };
    if !SecretEncryption::is_encrypted(&stored) {
        return Ok(Some(stored));
    }

    let encryption = resolve_master_key(false).map_err(|err| {
        anyhow::anyhow!(
            "Failed to decrypt stored ClawHub token: {}. Set ZEPTOCLAW_MASTER_KEY or re-run `zeptoclaw skills hub login --token ...`.",
            err
        )
    })?;
    let decrypted = encryption
        .decrypt(&stored)
        .map_err(|err| anyhow::anyhow!("Failed to decrypt stored ClawHub token: {}", err))?;
    Ok(non_empty(decrypted))
}

fn resolve_token_from_env() -> Option<String> {
    std::env::var("ZEPTOCLAW_CLAWHUB_TOKEN")
        .ok()
        .and_then(non_empty)
        .or_else(|| std::env::var("CLAWHUB_TOKEN").ok().and_then(non_empty))
}

fn normalize_base_url(raw: String) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

fn non_empty(raw: String) -> Option<String> {
    let trimmed = raw.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn prepare_token_for_storage(token: &str) -> Result<String> {
    let plaintext = token.trim();
    if plaintext.is_empty() {
        anyhow::bail!("ClawHub token cannot be empty.");
    }

    match resolve_master_key(false) {
        Ok(encryption) => encryption
            .encrypt(plaintext)
            .map_err(|err| anyhow::anyhow!("Failed to encrypt ClawHub token: {}", err)),
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("no master key available") {
                Ok(plaintext.to_string())
            } else {
                Err(anyhow::anyhow!(
                    "Failed to initialize token encryption: {}",
                    msg
                ))
            }
        }
    }
}

fn validate_slug(slug: &str) -> Result<()> {
    let valid = !slug.is_empty()
        && slug
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if !valid {
        anyhow::bail!(
            "Invalid skill slug '{}'. Use lowercase letters, digits, and '-'.",
            slug
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn test_installed(slug: &str, version: &str) -> InstalledSkill {
        InstalledSkill {
            slug: slug.to_string(),
            version: Some(version.to_string()),
            tag: None,
            fingerprint: Some(format!("fp-{}", slug)),
            install_path: format!("/tmp/{}", slug),
            installed_at: "2026-01-01T00:00:00Z".to_string(),
            source: "clawhub".to_string(),
        }
    }

    #[test]
    fn test_extract_items_prefers_items() {
        let payload = serde_json::json!({
            "items": [{"slug":"a"}],
            "skills": [{"slug":"b"}]
        });
        let items = extract_items(&payload);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("slug").and_then(Value::as_str), Some("a"));
    }

    #[test]
    fn test_normalize_base_url() {
        assert_eq!(
            normalize_base_url(" https://clawhub.ai/ ".to_string()),
            "https://clawhub.ai"
        );
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("my-skill-1").is_ok());
        assert!(validate_slug("MySkill").is_err());
        assert!(validate_slug("../evil").is_err());
    }

    #[test]
    fn test_evaluate_update_protection() {
        assert_eq!(
            evaluate_update_protection(Some("abc"), "abc", false),
            UpdateProtection::Allow
        );
        assert_eq!(
            evaluate_update_protection(Some("abc"), "xyz", false),
            UpdateProtection::Dirty
        );
        assert_eq!(
            evaluate_update_protection(None, "xyz", false),
            UpdateProtection::MissingBaseline
        );
        assert_eq!(
            evaluate_update_protection(None, "xyz", true),
            UpdateProtection::Allow
        );
    }

    #[test]
    fn test_fingerprint_changes_on_content_change() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("SKILL.md"), "name: test\nbody: one\n").unwrap();
        let before = compute_skill_fingerprint(dir.path()).unwrap();
        fs::write(dir.path().join("SKILL.md"), "name: test\nbody: two\n").unwrap();
        let after = compute_skill_fingerprint(dir.path()).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn test_fingerprint_ignores_clawhub_metadata() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("SKILL.md"), "hello").unwrap();
        let before = compute_skill_fingerprint(dir.path()).unwrap();

        let meta = dir.path().join(".clawhub");
        fs::create_dir_all(&meta).unwrap();
        fs::write(meta.join("origin.json"), "{\"installed_at\":\"now\"}").unwrap();
        let after = compute_skill_fingerprint(dir.path()).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn test_bump_semver() {
        assert_eq!(bump_semver(None, SyncBump::Patch).unwrap(), "0.1.0");
        assert_eq!(
            bump_semver(Some("1.2.3"), SyncBump::Patch).unwrap(),
            "1.2.4"
        );
        assert_eq!(
            bump_semver(Some("1.2.3"), SyncBump::Minor).unwrap(),
            "1.3.0"
        );
        assert_eq!(
            bump_semver(Some("1.2.3"), SyncBump::Major).unwrap(),
            "2.0.0"
        );
    }

    #[test]
    fn test_parse_sync_tags() {
        assert_eq!(parse_sync_tags(None), vec!["latest".to_string()]);
        assert_eq!(
            parse_sync_tags(Some(" latest,stable,latest ")),
            vec!["latest".to_string(), "stable".to_string()]
        );
    }

    #[test]
    fn test_validate_zip_entry_path_rejects_traversal_and_absolute() {
        assert!(validate_zip_entry_path("skill/SKILL.md").is_ok());
        assert!(validate_zip_entry_path("../evil").is_err());
        assert!(validate_zip_entry_path("/tmp/evil").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_dir_recursive_rejects_symlink_entries() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::write(src.path().join("SKILL.md"), "demo").unwrap();
        symlink(src.path().join("SKILL.md"), src.path().join("SKILL.link")).unwrap();
        let err = copy_dir_recursive(src.path(), dst.path()).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn test_lock_state_helpers_upsert_and_remove() {
        let mut lock = ClawHubLockState::default();
        upsert_lock_entry_in_state(&mut lock, test_installed("b-skill", "1.0.0"));
        upsert_lock_entry_in_state(&mut lock, test_installed("a-skill", "1.0.0"));
        upsert_lock_entry_in_state(&mut lock, test_installed("b-skill", "1.1.0"));
        assert_eq!(lock.installed.len(), 2);
        assert_eq!(lock.installed[0].slug, "a-skill");
        assert_eq!(lock.installed[1].slug, "b-skill");
        assert_eq!(lock.installed[1].version.as_deref(), Some("1.1.0"));

        remove_lock_entry_in_state(&mut lock, "a-skill");
        assert_eq!(lock.installed.len(), 1);
        assert_eq!(lock.installed[0].slug, "b-skill");
    }
}
