//! Skills management command handler.

use anyhow::{Context, Result};

use zeptoclaw::config::Config;

use super::common::skills_loader_from_config;
use super::SkillsAction;

/// Skills management command.
pub(crate) async fn cmd_skills(action: SkillsAction) -> Result<()> {
    match action {
        SkillsAction::Hub { action } => super::skills_hub::cmd_skills_hub(action).await,
        SkillsAction::List { all } => {
            let config = Config::load().with_context(|| "Failed to load configuration")?;
            let loader = skills_loader_from_config(&config);
            let disabled: std::collections::HashSet<String> = config
                .skills
                .disabled
                .iter()
                .map(|name| name.to_ascii_lowercase())
                .collect();
            let mut listed = loader.list_skills(!all);
            listed.retain(|info| !disabled.contains(&info.name.to_ascii_lowercase()));

            if listed.is_empty() {
                println!("No skills found.");
                return Ok(());
            }

            println!("Skills:");
            for info in listed {
                let ready = loader
                    .load_skill(&info.name)
                    .map(|skill| loader.check_requirements(&skill))
                    .unwrap_or(false);
                let marker = if ready {
                    "ready"
                } else {
                    "missing requirements"
                };
                println!("  - {} ({}, {})", info.name, info.source, marker);
            }
            Ok(())
        }
        SkillsAction::Show { name } => {
            let config = Config::load().with_context(|| "Failed to load configuration")?;
            let loader = skills_loader_from_config(&config);
            if let Some(skill) = loader.load_skill(&name) {
                println!("Name: {}", skill.name);
                println!("Description: {}", skill.description);
                println!("Source: {}", skill.source);
                println!("Path: {}", skill.path);
                println!();
                println!("{}", skill.content);
            } else {
                anyhow::bail!("Skill '{}' not found", name);
            }
            Ok(())
        }
        SkillsAction::Create { name } => {
            let config = Config::load().with_context(|| "Failed to load configuration")?;
            let loader = skills_loader_from_config(&config);
            let dir = loader.workspace_dir().join(&name);
            let skill_file = dir.join("SKILL.md");
            if skill_file.exists() {
                anyhow::bail!("Skill '{}' already exists at {:?}", name, skill_file);
            }

            std::fs::create_dir_all(&dir)?;
            let template = format!(
                r#"---
name: {name}
description: Describe what this skill does.
metadata: {{"zeptoclaw":{{"emoji":"📚","requires":{{}}}}}}
---

# {name} Skill

Describe usage and concrete command examples.
"#
            );
            std::fs::write(&skill_file, template)?;
            println!("Created skill at {:?}", skill_file);
            Ok(())
        }
    }
}
