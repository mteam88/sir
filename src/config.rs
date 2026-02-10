use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
struct PartialConfig {
    claude_bin: Option<String>,
    claude_model: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub(crate) claude_bin: String,
    pub(crate) claude_model: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            claude_bin: "claude".to_string(),
            claude_model: "sonnet".to_string(),
        }
    }
}

impl Config {
    pub(crate) fn load() -> Result<Self> {
        let mut config = Self::default();
        for path in config_paths() {
            if !path.exists() {
                continue;
            }
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config file {}", path.display()))?;
            let parsed: PartialConfig = toml::from_str(&raw)
                .with_context(|| format!("failed to parse config file {}", path.display()))?;
            if let Some(claude_bin) = parsed.claude_bin
                && !claude_bin.trim().is_empty()
            {
                config.claude_bin = claude_bin;
            }
            if let Some(claude_model) = parsed.claude_model
                && !claude_model.trim().is_empty()
            {
                config.claude_model = claude_model;
            }
            break;
        }
        Ok(config)
    }
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("sir").join("config.toml"));
    }
    if let Some(home_dir) = dirs::home_dir() {
        paths.push(home_dir.join(".sir.toml"));
    }
    paths
}
