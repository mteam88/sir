use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load()?;

    match cli.command {
        Commands::Doctor => cmd_doctor(&config),
        Commands::New { name, from, args } => {
            let parsed = parse_new_command_args(name, from, args)?;
            cmd_new(
                &config,
                parsed.name.as_deref(),
                parsed.from.as_deref(),
                &parsed.agent_cmd,
            )
        }
        Commands::Status { json } => cmd_status(json),
        Commands::Open { name } => cmd_open(&name),
        Commands::Rm { name, all_clean } => cmd_rm(name.as_deref(), all_clean),
        Commands::Settle { name, prompt } => {
            cmd_settle(&config, name.as_deref(), prompt.as_deref())
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sir",
    version,
    about = "Small workspace wrapper for git worktrees + Claude in the raw terminal"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run sanity checks and print remediation commands.
    Doctor,
    /// Create/open a workspace and run an agent command in the current terminal.
    #[command(alias = "n")]
    New {
        /// Optional explicit workspace name. If omitted, name is generated automatically.
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Base revision used when creating a new workspace branch.
        #[arg(long)]
        from: Option<String>,
        /// Agent command to run in the workspace.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show discovered workspaces and status.
    #[command(alias = "t")]
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Open an interactive shell in the workspace.
    Open { name: String },
    /// Remove a workspace by name, or remove all clean workspaces.
    Rm {
        /// Workspace name. Omit when using `--all-clean`.
        name: Option<String>,
        /// Remove all workspaces that have no unstaged or untracked changes.
        #[arg(long)]
        all_clean: bool,
    },
    /// Let Claude integrate a workspace back to main.
    #[command(alias = "s")]
    Settle {
        /// Optional workspace name. If omitted, inferred from cwd when inside `.worktrees/<name>`.
        name: Option<String>,
        /// Extra instructions appended to the settle Claude prompt.
        #[arg(short = 'p', long = "prompt")]
        prompt: Option<String>,
    },
}

#[derive(Debug, Deserialize, Default)]
struct PartialConfig {
    claude_bin: Option<String>,
    claude_model: Option<String>,
}

#[derive(Debug, Clone)]
struct Config {
    claude_bin: String,
    claude_model: String,
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
    fn load() -> Result<Self> {
        let mut config = Self::default();
        for path in config_paths() {
            if !path.exists() {
                continue;
            }
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config file {}", path.display()))?;
            let parsed: PartialConfig = toml::from_str(&raw)
                .with_context(|| format!("failed to parse config file {}", path.display()))?;
            if let Some(claude_bin) = parsed.claude_bin {
                if !claude_bin.trim().is_empty() {
                    config.claude_bin = claude_bin;
                }
            }
            if let Some(claude_model) = parsed.claude_model {
                if !claude_model.trim().is_empty() {
                    config.claude_model = claude_model;
                }
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

fn cmd_doctor(config: &Config) -> Result<()> {
    progress("doctor: running environment checks");
    let mut checks = Vec::new();
    let mut failed = false;

    let repo_root = match repo_root() {
        Ok(path) => {
            checks.push(Check::ok(
                "Inside git repo",
                format!("repo root: {}", path.display()),
            ));
            Some(path)
        }
        Err(_) => {
            failed = true;
            checks.push(Check::fail(
                "Inside git repo",
                "current directory is not inside a git repository".to_string(),
                Some("cd <your-repo>".to_string()),
            ));
            None
        }
    };

    if let Some(root) = &repo_root {
        let (worktrees_dir, created) = ensure_worktrees_dir(root)?;
        if created {
            checks.push(Check::ok(
                ".worktrees exists",
                format!("created {}", worktrees_dir.display()),
            ));
        } else {
            checks.push(Check::ok(
                ".worktrees exists",
                format!("found {}", worktrees_dir.display()),
            ));
        }

        if is_worktrees_gitignored(root)? {
            checks.push(Check::ok(
                ".worktrees is gitignored",
                "found in .gitignore".to_string(),
            ));
        } else {
            failed = true;
            checks.push(Check::fail(
                ".worktrees is gitignored",
                "missing from .gitignore".to_string(),
                Some("echo '.worktrees/' >> .gitignore".to_string()),
            ));
        }
        match run_capture("git", &["worktree", "list"], Some(root)) {
            Ok(output) if output.status.success() => {
                checks.push(Check::ok(
                    "git worktree support",
                    "`git worktree list` works".to_string(),
                ));
            }
            Ok(output) => {
                failed = true;
                checks.push(Check::fail(
                    "git worktree support",
                    first_line(&output.stderr),
                    Some("upgrade git to a version with worktree support".to_string()),
                ));
            }
            Err(err) => {
                failed = true;
                checks.push(Check::fail(
                    "git worktree support",
                    err.to_string(),
                    Some("ensure git is installed and callable".to_string()),
                ));
            }
        }
    }

    if binary_available(&config.claude_bin) {
        checks.push(Check::ok(
            "Claude CLI installed",
            format!("`{} --version` works", config.claude_bin),
        ));
    } else {
        failed = true;
        checks.push(Check::fail(
            "Claude CLI installed",
            format!("`{}` is not callable", config.claude_bin),
            Some("Install Claude Code CLI and ensure it is on PATH".to_string()),
        ));
    }

    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        checks.push(Check::ok(
            "Terminal mode",
            "new/open will run directly in this terminal".to_string(),
        ));
    } else {
        checks.push(Check::ok(
            "Terminal mode",
            "non-interactive environment detected; new/open still run commands but open avoids launching an interactive shell"
                .to_string(),
        ));
    }

    for check in checks {
        check.print();
    }

    if failed {
        bail!("doctor found failing checks")
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct ParsedNewCommand {
    name: Option<String>,
    from: Option<String>,
    agent_cmd: Vec<String>,
}

fn parse_new_command_args(
    name: Option<String>,
    from: Option<String>,
    args: Vec<String>,
) -> Result<ParsedNewCommand> {
    if args.is_empty() {
        bail!("agent command must not be empty");
    }

    if let Some(name) = name {
        return Ok(ParsedNewCommand {
            name: Some(name),
            from,
            agent_cmd: args,
        });
    }

    Ok(ParsedNewCommand {
        name: None,
        from,
        agent_cmd: args,
    })
}

fn cmd_new(
    config: &Config,
    explicit_name: Option<&str>,
    from_revision: Option<&str>,
    agent_cmd: &[String],
) -> Result<()> {
    let repo_root = repo_root()?;
    let (worktrees_dir, _) = ensure_worktrees_dir(&repo_root)?;
    let name =
        resolve_new_workspace_name(config, explicit_name, agent_cmd, &repo_root, &worktrees_dir)?;

    progress(&format!("new: preparing workspace `{name}`"));
    validate_workspace_name(&name)?;
    let workspace_path = worktrees_dir.join(&name);
    let mut created_workspace = false;

    if workspace_path.is_dir() {
        progress(&format!(
            "new: inspecting existing workspace `{}`",
            workspace_path.display()
        ));
        let backend = detect_workspace_backend(&workspace_path);
        let metadata_only = workspace_is_metadata_only(&workspace_path)?;
        let has_tracked =
            workspace_has_tracked_content(&repo_root, &workspace_path).unwrap_or(true);
        if backend != WorkspaceBackend::Git || metadata_only || !has_tracked {
            let reason = if backend != WorkspaceBackend::Git {
                "not a git worktree"
            } else if metadata_only {
                "only git metadata"
            } else {
                "no tracked repository files"
            };
            eprintln!("warning: workspace `{name}` appears incomplete ({reason}); recreating it");
            if let Ok(workspace_str) = path_to_str(&workspace_path) {
                let _ = run_capture(
                    "git",
                    &["worktree", "remove", "--force", workspace_str],
                    Some(&repo_root),
                );
            }
            fs::remove_dir_all(&workspace_path).with_context(|| {
                format!(
                    "failed to remove incomplete workspace {}",
                    workspace_path.display()
                )
            })?;
        }
    }

    if !workspace_path.exists() {
        progress("new: creating git worktree");
        let revision = from_revision.unwrap_or("HEAD").trim();
        if revision.is_empty() {
            bail!("--from must not be empty");
        }
        if !git_revision_exists(&repo_root, revision) {
            bail!("revision `{revision}` is not valid or cannot be resolved");
        }
        let workspace_branch = workspace_branch_name(&repo_root, &name)?;
        let workspace_str = path_to_str(&workspace_path)?;
        let output = if git_branch_exists(&repo_root, &workspace_branch) {
            if from_revision.is_some() {
                progress(&format!(
                    "new: branch `{workspace_branch}` already exists; ignoring `--from {revision}`"
                ));
            }
            run_capture(
                "git",
                &["worktree", "add", workspace_str, &workspace_branch],
                Some(&repo_root),
            )?
        } else {
            run_capture(
                "git",
                &[
                    "worktree",
                    "add",
                    "-b",
                    &workspace_branch,
                    workspace_str,
                    revision,
                ],
                Some(&repo_root),
            )?
        };
        if !output.status.success() {
            let error_line = best_error_line(&output.stderr);
            if workspace_path.exists() {
                let _ = run_capture(
                    "git",
                    &["worktree", "remove", "--force", workspace_str],
                    Some(&repo_root),
                );
                let _ = fs::remove_dir_all(&workspace_path);
            }
            bail!("failed to create git worktree `{name}`: {error_line}");
        }
        created_workspace = true;
    }

    if created_workspace {
        progress("new: applying uncommitted changes from source working tree");
        apply_uncommitted_changes(&repo_root, &workspace_path)?;
    }

    progress("new: running initialization via Claude");
    let init_prompt = new_init_prompt(&workspace_path);
    run_claude(config, &init_prompt, &repo_root)?;

    progress("new: launching agent command");
    run_agent_command(agent_cmd, &workspace_path)
}

fn resolve_new_workspace_name(
    config: &Config,
    explicit_name: Option<&str>,
    agent_cmd: &[String],
    repo_root: &Path,
    worktrees_dir: &Path,
) -> Result<String> {
    if let Some(name) = explicit_name {
        validate_workspace_name(name)?;
        return Ok(name.to_string());
    }

    progress("new: generating workspace name via Claude");
    let command = shell_join(agent_cmd);
    let claude_result = suggest_workspace_name_from_claude(config, &command, repo_root);
    let mut selected = match claude_result {
        Ok(Some(name)) => name,
        Ok(None) => fallback_workspace_name(worktrees_dir),
        Err(err) => {
            eprintln!("warning: failed to generate workspace name via Claude: {err}");
            fallback_workspace_name(worktrees_dir)
        }
    };

    if validate_workspace_name(&selected).is_err() {
        selected = fallback_workspace_name(worktrees_dir);
    }

    progress(&format!("new: selected workspace name `{selected}`"));
    Ok(selected)
}

fn suggest_workspace_name_from_claude(
    config: &Config,
    agent_command: &str,
    cwd: &Path,
) -> Result<Option<String>> {
    let prompt = auto_name_prompt(agent_command);
    let output = run_claude_text(config, &prompt, cwd)?;
    Ok(parse_auto_name_response(&output))
}

fn auto_name_prompt(agent_command: &str) -> String {
    format!(
        "You generate short workspace names for git worktrees.

Task:
- Read this command that the user will run inside the new workspace.
- If the command is too vague to infer intent, return null.
- Otherwise return a short memorable name.

Command:
{agent_command}

Rules:
- Return exactly one line.
- Output must be either:
  1) null
  2) a plain text name (1-4 words, lowercase, no punctuation except spaces, hyphen, underscore, or dot)
- No quotes, no markdown, no extra commentary."
    )
}

fn run_claude_text(config: &Config, prompt: &str, cwd: &Path) -> Result<String> {
    let args = build_claude_text_args(prompt, &config.claude_model);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_capture(&config.claude_bin, &arg_refs, Some(cwd))
        .with_context(|| format!("failed while running `{}`", config.claude_bin))?;
    if !output.status.success() {
        bail!(
            "failed while running `{}`: {}",
            config.claude_bin,
            best_error_line(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn build_claude_text_args(prompt: &str, model: &str) -> Vec<String> {
    let mut args = vec![
        "-p".to_string(),
        prompt.to_string(),
        "--output-format".to_string(),
        "text".to_string(),
    ];
    if !model.trim().is_empty() {
        args.push("--model".to_string());
        args.push(model.trim().to_string());
    }
    args
}

fn parse_auto_name_response(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return parse_auto_name_json(&value);
    }

    let candidate = trimmed
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("```"))
        .unwrap_or("");
    normalize_auto_name_candidate(candidate)
}

fn parse_auto_name_json(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(name) => normalize_auto_name_candidate(name),
        serde_json::Value::Object(map) => {
            let name = map.get("name")?;
            if name.is_null() {
                return None;
            }
            name.as_str().and_then(normalize_auto_name_candidate)
        }
        _ => None,
    }
}

fn normalize_auto_name_candidate(candidate: &str) -> Option<String> {
    let raw = candidate.trim().trim_matches('`').trim_matches('"').trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
        return None;
    }

    let mut normalized = String::new();
    let mut previous_space = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            normalized.push(ch.to_ascii_lowercase());
            previous_space = false;
            continue;
        }
        if ch.is_whitespace() {
            if !normalized.is_empty() && !previous_space {
                normalized.push(' ');
            }
            previous_space = true;
        }
    }

    let normalized = normalized.trim().to_string();
    if normalized.is_empty() || normalized.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(normalized)
    }
}

fn fallback_workspace_name(worktrees_dir: &Path) -> String {
    const ADJECTIVES: &[&str] = &[
        "pink", "brisk", "crisp", "lucky", "quiet", "rapid", "sunny", "tidy", "witty", "bold",
        "swift", "fuzzy",
    ];
    const NOUNS: &[&str] = &[
        "elephant", "otter", "falcon", "harbor", "forest", "rocket", "lantern", "meadow", "beacon",
        "comet", "panther", "sailor",
    ];

    for attempt in 0..100u64 {
        let adjective = ADJECTIVES[pseudo_random_index(ADJECTIVES.len(), attempt)];
        let noun = NOUNS[pseudo_random_index(NOUNS.len(), attempt + 97)];
        let base = format!("{adjective} {noun}");
        if !worktrees_dir.join(&base).exists() {
            return base;
        }
        let with_suffix = format!("{base} {}", attempt + 2);
        if !worktrees_dir.join(&with_suffix).exists() {
            return with_suffix;
        }
    }

    "pink elephant".to_string()
}

fn pseudo_random_index(len: usize, salt: u64) -> usize {
    if len == 0 {
        return 0;
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let mut value = nanos ^ pid.rotate_left(17) ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 33;
    value = value.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    value ^= value >> 33;
    (value as usize) % len
}

fn cmd_open(name: &str) -> Result<()> {
    progress(&format!("open: resolving workspace `{name}`"));
    validate_workspace_name(name)?;
    let repo_root = repo_root()?;
    let workspace_path = repo_root.join(".worktrees").join(name);
    if !workspace_path.is_dir() {
        bail!("workspace does not exist: {}", workspace_path.display());
    }

    run_workspace_shell(&workspace_path)
}

fn cmd_rm(name: Option<&str>, all_clean: bool) -> Result<()> {
    if all_clean {
        if name.is_some() {
            bail!("cannot pass <name> with --all-clean");
        }
        return cmd_rm_all_clean();
    }

    let name = name.context("workspace name is required unless --all-clean is set")?;
    cmd_rm_single(name)
}

fn cmd_rm_single(name: &str) -> Result<()> {
    progress(&format!("rm: resolving workspace `{name}`"));
    validate_workspace_name(name)?;
    let repo_root = repo_root()?;
    let workspace_path = repo_root.join(".worktrees").join(name);
    if !workspace_path.exists() {
        bail!("workspace does not exist: {}", workspace_path.display());
    }
    if !workspace_path.is_dir() {
        bail!(
            "workspace path is not a directory: {}",
            workspace_path.display()
        );
    }

    let workspace_str = path_to_str(&workspace_path)?;
    let output = run_capture(
        "git",
        &["worktree", "remove", "--force", workspace_str],
        Some(&repo_root),
    )?;
    if output.status.success() {
        progress(&format!("rm: removed workspace `{name}`"));
        return Ok(());
    }

    if detect_workspace_backend(&workspace_path) == WorkspaceBackend::Unknown {
        fs::remove_dir_all(&workspace_path)
            .with_context(|| format!("failed to remove {}", workspace_path.display()))?;
        progress(&format!("rm: removed non-git workspace `{name}`"));
        return Ok(());
    }

    bail!(
        "failed to remove git worktree `{name}`: {}",
        best_error_line(&output.stderr)
    );
}

fn cmd_rm_all_clean() -> Result<()> {
    progress("rm: scanning for clean workspaces");
    let repo_root = repo_root()?;
    let worktrees_dir = repo_root.join(".worktrees");
    let entries = list_workspace_dirs(&worktrees_dir)?;
    if entries.is_empty() {
        println!("No workspaces found under {}", worktrees_dir.display());
        return Ok(());
    }

    let mut removed = 0usize;
    let mut skipped_dirty = 0usize;
    let mut skipped_non_git = 0usize;
    let mut failures = Vec::new();

    for (name, path) in entries {
        if detect_workspace_backend(&path) != WorkspaceBackend::Git {
            skipped_non_git += 1;
            continue;
        }

        match workspace_has_unstaged_changes(&path) {
            Ok(true) => {
                skipped_dirty += 1;
            }
            Ok(false) => {
                progress(&format!("rm: removing clean workspace `{name}`"));
                if let Err(err) = cmd_rm_single(&name) {
                    failures.push(format!("{name}: {err:#}"));
                } else {
                    removed += 1;
                }
            }
            Err(err) => failures.push(format!("{name}: {err:#}")),
        }
    }

    println!(
        "rm --all-clean: removed {removed}, skipped dirty {skipped_dirty}, skipped non-git {skipped_non_git}"
    );

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("- {failure}");
        }
        bail!("rm --all-clean failed for {} workspace(s)", failures.len());
    }

    Ok(())
}

fn cmd_status(as_json: bool) -> Result<()> {
    progress("status: scanning workspaces");
    let repo_root = repo_root()?;
    let worktrees_dir = repo_root.join(".worktrees");
    let entries = list_workspace_dirs(&worktrees_dir)?;

    let mut rows = Vec::new();
    for (name, path) in entries {
        let backend = detect_workspace_backend(&path);
        let summary = workspace_status_summary(backend, &path);
        rows.push(StatusRow {
            name,
            path,
            backend: backend.to_string(),
            summary,
        });
    }

    if as_json {
        let json_rows: Vec<JsonStatusRow> = rows
            .iter()
            .map(|row| JsonStatusRow {
                name: row.name.clone(),
                path: row.path.display().to_string(),
                backend: row.backend.clone(),
                summary: row.summary.clone(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No workspaces found under {}", worktrees_dir.display());
        return Ok(());
    }

    println!("{:<24} {:<8} STATUS", "NAME", "BACKEND");
    for row in rows {
        println!(
            "{:<24} {:<8} {}",
            row.name,
            row.backend,
            truncate(&row.summary, 100)
        );
    }

    Ok(())
}

fn cmd_settle(config: &Config, maybe_name: Option<&str>, prompt: Option<&str>) -> Result<()> {
    progress("settle: resolving workspace");
    let repo_root = repo_common_root()?;
    let worktrees_dir = repo_root.join(".worktrees");
    let started_in_worktree = invoked_from_worktree(&worktrees_dir);
    let (effective_name, additional_prompt) =
        normalize_settle_inputs(&worktrees_dir, started_in_worktree, maybe_name, prompt);

    let (name, workspace_path) = match effective_name.as_deref() {
        Some(name) => {
            validate_workspace_name(name)?;
            let path = worktrees_dir.join(name);
            if !path.is_dir() {
                bail!("workspace does not exist: {}", path.display());
            }
            (name.to_string(), path)
        }
        None => infer_workspace_from_cwd(&worktrees_dir)
            .context("could not infer workspace name; pass one explicitly")?,
    };

    progress("settle: running integration via Claude");
    let settle_prompt = settle_prompt(&name, &workspace_path, additional_prompt.as_deref());
    run_claude(config, &settle_prompt, &workspace_path)?;

    progress("settle: running post-checks");
    println!("\nPost-check:");
    match run_capture("git", &["status", "-sb"], Some(&repo_root)) {
        Ok(output) => {
            print_command_output("git status -sb", &output.stdout, &output.stderr);
        }
        Err(err) => {
            println!("- git status -sb failed: {err}");
        }
    }

    if started_in_worktree {
        settle_to_repo_root(&repo_root)?;
    }

    Ok(())
}

fn run_agent_command(agent_cmd: &[String], workspace_path: &Path) -> Result<()> {
    if agent_cmd.is_empty() {
        bail!("agent command must not be empty");
    }

    println!(
        "Running in {}: {}",
        workspace_path.display(),
        agent_cmd.join(" ")
    );

    run_agent_command_with_shell(agent_cmd, workspace_path)
}

fn run_agent_command_with_shell(agent_cmd: &[String], workspace_path: &Path) -> Result<()> {
    let zsh = "/bin/zsh";
    if !Path::new(zsh).exists() {
        bail!("new requires `{zsh}` to exist");
    }

    let command = shell_join(agent_cmd);
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return run_stream(zsh, &["-c", &command], Some(workspace_path))
            .context("failed to run agent command inside /bin/zsh");
    }

    let script = format!("{command};\necho;\nexec {zsh} -i");
    run_stream(zsh, &["-i", "-c", &script], Some(workspace_path))
        .context("failed to run agent command inside zsh")
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "@%_+=:,./-".contains(ch))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_workspace_shell(workspace_path: &Path) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        println!(
            "Non-interactive terminal detected; workspace path: {}",
            workspace_path.display()
        );
        return Ok(());
    }

    let shell = env::var("SHELL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sh".to_string());

    println!("Opening shell `{shell}` in {}", workspace_path.display());
    run_stream(&shell, &[], Some(workspace_path))
        .with_context(|| format!("failed to run `{shell}`"))
}

fn settle_to_repo_root(repo_root: &Path) -> Result<()> {
    progress("settle: returning to repo root");
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        println!("\nSettle complete. Repo root: {}", repo_root.display());
        return Ok(());
    }

    let shell = env::var("SHELL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "sh".to_string());

    println!(
        "\nSettle complete. Opening shell `{shell}` in {}",
        repo_root.display()
    );
    run_stream(&shell, &[], Some(repo_root))
        .with_context(|| format!("failed to run `{shell}` at repo root"))
}

fn print_command_output(command: &str, stdout: &str, stderr: &str) {
    println!("- {command}");
    let out = stdout.trim();
    let err = stderr.trim();
    if !out.is_empty() {
        for line in out.lines() {
            println!("  {line}");
        }
    }
    if !err.is_empty() {
        for line in err.lines() {
            println!("  [stderr] {line}");
        }
    }
}

fn new_init_prompt(workspace_path: &Path) -> String {
    format!(
        "You are in the repo root. Copy initialization data into workspace at:\n{}\n\nRequirements:\n- Copy .env into the workspace if present, but do not overwrite workspace .env if it already exists.\n- Copy target/ into the workspace if present.\n- Copy node_modules/ into the workspace if present.\n- Use copy-on-write on macOS when possible (cp -c). Otherwise use plain recursive copy (cp -R).\n- Never create symlinks.\n- Be conservative and avoid destructive actions.\n- Do not ask questions; execute directly and report what you did.",
        workspace_path.display()
    )
}

fn settle_prompt(name: &str, workspace_path: &Path, additional_prompt: Option<&str>) -> String {
    let mut prompt = format!(
        "You are in workspace `{name}` at `{}`.\n\nGoal: integrate this workspace back into `main` using git.\n\nRequirements:\n- Inspect changes with git status/diff/log.\n- Ensure changes are in a clean commit (or a small clean commit stack) with excellent commit message quality based on the diff intent.\n- Rebase or merge onto the latest `main` and resolve conflicts.\n- Integrate the result onto `main` using git primitives.\n- Do not remove/delete/prune this worktree (do not run `git worktree remove`); workspace cleanup is handled separately.\n- If .env.example or any similar example-env file changed, update .env by adding new keys/defaults without overwriting existing secrets.\n- Leave the workspace and main in a sensible state.\n- Run commands directly with no follow-up questions unless absolutely blocked.",
        workspace_path.display()
    );
    if let Some(extra) = additional_prompt
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        prompt.push_str(
            "\n\nAdditional user instructions:\n- Follow this extra instruction exactly: ",
        );
        prompt.push_str(extra);
    }
    prompt
}

fn run_claude(config: &Config, prompt: &str, cwd: &Path) -> Result<()> {
    let args = build_claude_args(prompt, &config.claude_model);
    run_claude_stream(&config.claude_bin, &args, Some(cwd))
        .with_context(|| format!("failed while running `{}`", config.claude_bin))
}

fn build_claude_args(prompt: &str, model: &str) -> Vec<String> {
    let mut args = vec![
        "-p".to_string(),
        prompt.to_string(),
        "--dangerously-skip-permissions".to_string(),
    ];
    if !model.trim().is_empty() {
        args.push("--model".to_string());
        args.push(model.trim().to_string());
    }
    ensure_claude_streaming_args(&args)
}

fn workspace_branch_name(repo_root: &Path, workspace_name: &str) -> Result<String> {
    let replaced_whitespace = collapse_whitespace_with_hyphen(workspace_name);
    let direct = format!("sir/{replaced_whitespace}");
    if git_branch_name_valid(repo_root, &direct) {
        return Ok(direct);
    }

    let slug = slugify_branch_component(workspace_name);
    if slug.is_empty() {
        bail!("workspace name `{workspace_name}` cannot be converted to a valid git branch name");
    }
    let fallback = format!("sir/{slug}");
    if git_branch_name_valid(repo_root, &fallback) {
        return Ok(fallback);
    }

    bail!("workspace name `{workspace_name}` cannot be converted to a valid git branch name");
}

fn collapse_whitespace_with_hyphen(value: &str) -> String {
    let mut output = String::new();
    let mut last_hyphen = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !output.is_empty() && !last_hyphen {
                output.push('-');
            }
            last_hyphen = true;
        } else {
            output.push(ch);
            last_hyphen = false;
        }
    }
    output.trim_matches('-').to_string()
}

fn slugify_branch_component(value: &str) -> String {
    let mut output = String::new();
    let mut last_separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            let mut next = ch.to_ascii_lowercase();
            if next == '.' && output.ends_with('.') {
                next = '-';
            }
            output.push(next);
            last_separator = next == '-';
            continue;
        }

        if !output.is_empty() && !last_separator {
            output.push('-');
            last_separator = true;
        }
    }

    let mut output = output.trim_matches(['-', '.']).to_string();
    while output.contains("..") {
        output = output.replace("..", ".");
    }
    while output.contains(".-") {
        output = output.replace(".-", "-");
    }
    while output.contains("-.") {
        output = output.replace("-.", "-");
    }
    while output.contains("--") {
        output = output.replace("--", "-");
    }
    output.trim_matches(['-', '.']).to_string()
}

fn progress(message: &str) {
    eprintln!("==> {message}");
}

fn apply_uncommitted_changes(repo_root: &Path, workspace_path: &Path) -> Result<()> {
    let diff_output = run_capture("git", &["diff", "--binary", "HEAD"], Some(repo_root))
        .context("failed to capture tracked uncommitted changes")?;
    if !diff_output.status.success() {
        bail!(
            "failed to generate working-tree diff: {}",
            best_error_line(&diff_output.stderr)
        );
    }

    if !diff_output.stdout.trim().is_empty() {
        let apply_output = run_capture_with_input(
            "git",
            &["apply", "--3way", "--whitespace=nowarn"],
            Some(workspace_path),
            diff_output.stdout.as_bytes(),
        )
        .context("failed to apply tracked changes to new workspace")?;
        if !apply_output.status.success() {
            bail!(
                "failed to apply tracked changes: {}",
                best_error_line(&apply_output.stderr)
            );
        }
    }

    let untracked_output = run_capture(
        "git",
        &["ls-files", "--others", "--exclude-standard", "-z"],
        Some(repo_root),
    )
    .context("failed to list untracked files")?;
    if !untracked_output.status.success() {
        bail!(
            "failed to list untracked files: {}",
            best_error_line(&untracked_output.stderr)
        );
    }

    let mut copied_untracked = 0usize;
    for rel in untracked_output.stdout.split('\0') {
        if rel.is_empty() {
            continue;
        }
        let rel_path = Path::new(rel);
        if !is_safe_repo_relative_path(rel_path) {
            continue;
        }
        let src = repo_root.join(rel_path);
        let dst = workspace_path.join(rel_path);
        let metadata = match fs::symlink_metadata(&src) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(&src, &dst).with_context(|| {
            format!(
                "failed to copy untracked file {} to {}",
                src.display(),
                dst.display()
            )
        })?;
        copied_untracked += 1;
    }

    if diff_output.stdout.trim().is_empty() && copied_untracked == 0 {
        progress("new: no uncommitted changes found in source workspace");
    } else if copied_untracked > 0 {
        progress(&format!(
            "new: copied {copied_untracked} untracked file(s) into new workspace"
        ));
    }

    Ok(())
}

fn is_safe_repo_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

#[derive(Debug)]
struct Check {
    name: String,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

impl Check {
    fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            detail: detail.into(),
            fix: None,
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            detail: detail.into(),
            fix,
        }
    }

    fn print(&self) {
        let state = if self.ok { "OK" } else { "FAIL" };
        println!("[{state}] {}: {}", self.name, self.detail);
        if let Some(fix) = &self.fix {
            println!("      fix: {fix}");
        }
    }
}

#[derive(Debug)]
struct StatusRow {
    name: String,
    path: PathBuf,
    backend: String,
    summary: String,
}

#[derive(Debug, Serialize)]
struct JsonStatusRow {
    name: String,
    path: String,
    backend: String,
    summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceBackend {
    Git,
    Unknown,
}

impl std::fmt::Display for WorkspaceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Git => write!(f, "git"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

fn detect_workspace_backend(path: &Path) -> WorkspaceBackend {
    if path.join(".git").exists() {
        WorkspaceBackend::Git
    } else {
        WorkspaceBackend::Unknown
    }
}

fn workspace_status_summary(backend: WorkspaceBackend, workspace_path: &Path) -> String {
    match backend {
        WorkspaceBackend::Git => match run_capture("git", &["status", "-sb"], Some(workspace_path))
        {
            Ok(output) if output.status.success() => squash_status_lines(&output.stdout),
            Ok(output) => format!("error: {}", first_line(&output.stderr)),
            Err(err) => format!("error: {err}"),
        },
        WorkspaceBackend::Unknown => "no backend metadata detected".to_string(),
    }
}

fn squash_status_lines(raw: &str) -> String {
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect();
    if lines.is_empty() {
        "clean".to_string()
    } else {
        lines.join(" | ")
    }
}

fn workspace_has_unstaged_changes(workspace_path: &Path) -> Result<bool> {
    let output = run_capture("git", &["status", "--porcelain"], Some(workspace_path))
        .with_context(|| format!("failed to read status for {}", workspace_path.display()))?;
    if !output.status.success() {
        bail!(
            "failed to read status for {}: {}",
            workspace_path.display(),
            best_error_line(&output.stderr)
        );
    }

    Ok(output
        .stdout
        .lines()
        .map(str::trim_end)
        .any(porcelain_line_has_unstaged_changes))
}

fn porcelain_line_has_unstaged_changes(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 2 {
        return true;
    }
    bytes[1] != b' '
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value
        .chars()
        .take(max.saturating_sub(3))
        .collect::<String>()
        + "..."
}

fn validate_workspace_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("workspace name must not be empty");
    }
    if name == "." || name == ".." {
        bail!("workspace name `{name}` is invalid");
    }
    if name == "_logs" || name == "_tmp" {
        bail!("workspace name `{name}` is reserved");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("workspace name must not contain path separators");
    }
    Ok(())
}

fn repo_root() -> Result<PathBuf> {
    let output = run_capture("git", &["rev-parse", "--show-toplevel"], None)
        .context("failed to run git to detect repo root")?;
    if !output.status.success() {
        bail!("not inside a git repository");
    }
    let root = output.stdout.trim();
    if root.is_empty() {
        bail!("git did not return a repository root");
    }
    Ok(PathBuf::from(root))
}

fn repo_common_root() -> Result<PathBuf> {
    let output = run_capture(
        "git",
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        None,
    )
    .context("failed to run git to detect common git dir")?;

    if output.status.success() {
        let common_dir = PathBuf::from(output.stdout.trim());
        if let Some(root) = common_root_from_git_common_dir(&common_dir) {
            return Ok(root);
        }
    }

    repo_root()
}

fn common_root_from_git_common_dir(common_dir: &Path) -> Option<PathBuf> {
    if common_dir.file_name()? != ".git" {
        return None;
    }
    common_dir.parent().map(Path::to_path_buf)
}

fn ensure_worktrees_dir(repo_root: &Path) -> Result<(PathBuf, bool)> {
    let path = repo_root.join(".worktrees");
    let created = !path.exists();
    if created {
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
    }
    Ok((path, created))
}

fn is_worktrees_gitignored(repo_root: &Path) -> Result<bool> {
    let gitignore_path = repo_root.join(".gitignore");
    if !gitignore_path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(&gitignore_path)
        .with_context(|| format!("failed to read {}", gitignore_path.display()))?;
    Ok(content.lines().any(matches_worktrees_ignore_line))
}

fn matches_worktrees_ignore_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }

    let mut value = trimmed;
    if let Some(before_comment) = value.split(" #").next() {
        value = before_comment.trim();
    }

    if let Some(stripped) = value.strip_prefix('/') {
        value = stripped;
    }
    if let Some(stripped) = value.strip_suffix('/') {
        value = stripped;
    }

    value == ".worktrees"
}

fn list_workspace_dirs(worktrees_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    if !worktrees_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(worktrees_dir)
        .with_context(|| format!("failed to read {}", worktrees_dir.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "_logs" || name == "_tmp" {
            continue;
        }
        entries.push((name, entry.path()));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn workspace_is_metadata_only(workspace_path: &Path) -> Result<bool> {
    if !workspace_path.is_dir() {
        return Ok(false);
    }

    let mut saw_non_metadata_entry = false;
    for entry in fs::read_dir(workspace_path)
        .with_context(|| format!("failed to read workspace {}", workspace_path.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" {
            continue;
        }
        saw_non_metadata_entry = true;
        break;
    }

    Ok(!saw_non_metadata_entry)
}

fn workspace_has_tracked_content(repo_root: &Path, workspace_path: &Path) -> Result<bool> {
    let output = run_capture("git", &["ls-files"], Some(repo_root))
        .context("failed to list tracked files for workspace health check")?;
    if !output.status.success() {
        return Ok(true);
    }

    let mut saw_any_tracked = false;
    for path in output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        saw_any_tracked = true;
        if workspace_path.join(path).exists() {
            return Ok(true);
        }
    }

    if !saw_any_tracked {
        return Ok(true);
    }

    Ok(false)
}

fn infer_workspace_from_cwd(worktrees_dir: &Path) -> Option<(String, PathBuf)> {
    let cwd = env::current_dir().ok()?;
    if let Some(found) = infer_workspace_from_paths(worktrees_dir, &cwd) {
        return Some(found);
    }

    let canonical_worktrees = worktrees_dir.canonicalize().ok()?;
    let canonical_cwd = cwd.canonicalize().ok()?;
    infer_workspace_from_paths(&canonical_worktrees, &canonical_cwd)
}

fn invoked_from_worktree(worktrees_dir: &Path) -> bool {
    infer_workspace_from_cwd(worktrees_dir).is_some()
}

fn infer_workspace_from_paths(worktrees_dir: &Path, cwd: &Path) -> Option<(String, PathBuf)> {
    let stripped = cwd.strip_prefix(worktrees_dir).ok()?;
    let mut components = stripped.components();
    let component = components.next()?;
    let Component::Normal(name) = component else {
        return None;
    };
    let workspace_name = name.to_string_lossy().to_string();
    let workspace_path = worktrees_dir.join(&workspace_name);
    Some((workspace_name, workspace_path))
}

fn git_branch_exists(repo_root: &Path, branch: &str) -> bool {
    run_capture(
        "git",
        &[
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
        Some(repo_root),
    )
    .map(|output| output.status.success())
    .unwrap_or(false)
}

fn git_branch_name_valid(repo_root: &Path, branch: &str) -> bool {
    run_capture(
        "git",
        &["check-ref-format", "--branch", branch],
        Some(repo_root),
    )
    .map(|output| output.status.success())
    .unwrap_or(false)
}

fn git_revision_exists(repo_root: &Path, revision: &str) -> bool {
    run_capture(
        "git",
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{revision}^{{commit}}"),
        ],
        Some(repo_root),
    )
    .map(|output| output.status.success())
    .unwrap_or(false)
}

fn normalize_settle_inputs(
    worktrees_dir: &Path,
    started_in_worktree: bool,
    maybe_name: Option<&str>,
    prompt: Option<&str>,
) -> (Option<String>, Option<String>) {
    let mut effective_name = maybe_name.map(str::to_string);
    let mut additional_prompt = prompt.map(str::to_string);
    if additional_prompt.is_none() && started_in_worktree {
        if let Some(candidate) = effective_name.as_ref() {
            if !worktrees_dir.join(candidate).is_dir() {
                additional_prompt = Some(candidate.clone());
                effective_name = None;
            }
        }
    }
    (effective_name, additional_prompt)
}

fn binary_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

struct CmdOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run_capture(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<CmdOutput> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run `{program}`"))?;

    Ok(CmdOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn run_capture_with_input(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    input: &[u8],
) -> Result<CmdOutput> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to run `{program}`"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input)
            .with_context(|| format!("failed to write stdin to `{program}`"))?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for `{program}`"))?;

    Ok(CmdOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn run_stream(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    let status = command
        .status()
        .with_context(|| format!("failed to run `{program}`"))?;
    if !status.success() {
        bail!("`{program}` exited with status {status}");
    }
    Ok(())
}

fn run_claude_stream(program: &str, args: &[String], cwd: Option<&Path>) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args.iter().map(String::as_str));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to run `{program}`"))?;
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("failed to capture stdout for `{program}`"))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut saw_text_delta = false;
    let mut ended_with_newline = true;

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .with_context(|| format!("failed to read stdout from `{program}`"))?;
        if read == 0 {
            break;
        }
        match parse_claude_stream_line(&line) {
            ClaudeStreamLine::TextDelta(delta) => {
                print!("{delta}");
                std::io::stdout()
                    .flush()
                    .context("failed to flush stdout")?;
                saw_text_delta = true;
                ended_with_newline = delta.ends_with('\n');
            }
            ClaudeStreamLine::Error(message) => {
                eprintln!("error: {message}");
            }
            ClaudeStreamLine::OtherJson => {}
            ClaudeStreamLine::NonJson(chunk) => {
                print!("{chunk}");
                std::io::stdout()
                    .flush()
                    .context("failed to flush stdout")?;
                ended_with_newline = chunk.ends_with('\n');
            }
        }
    }

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for `{program}`"))?;
    if saw_text_delta && !ended_with_newline {
        println!();
    }
    if !status.success() {
        bail!("`{program}` exited with status {status}");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ClaudeStreamLine {
    TextDelta(String),
    Error(String),
    OtherJson,
    NonJson(String),
}

fn parse_claude_stream_line(line: &str) -> ClaudeStreamLine {
    let parsed = match serde_json::from_str::<serde_json::Value>(line) {
        Ok(value) => value,
        Err(_) => return ClaudeStreamLine::NonJson(line.to_string()),
    };

    if parsed.get("type").and_then(serde_json::Value::as_str) == Some("stream_event")
        && parsed
            .pointer("/event/delta/type")
            .and_then(serde_json::Value::as_str)
            == Some("text_delta")
    {
        if let Some(text) = parsed
            .pointer("/event/delta/text")
            .and_then(serde_json::Value::as_str)
        {
            return ClaudeStreamLine::TextDelta(text.to_string());
        }
    }

    if parsed.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let message = parsed
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str)
            .or_else(|| parsed.get("message").and_then(serde_json::Value::as_str))
            .unwrap_or("unknown Claude stream error");
        return ClaudeStreamLine::Error(message.to_string());
    }

    ClaudeStreamLine::OtherJson
}

fn ensure_claude_streaming_args(args: &[String]) -> Vec<String> {
    let mut with_streaming = args.to_vec();
    if claude_output_format(args).is_none() {
        with_streaming.push("--output-format".to_string());
        with_streaming.push("stream-json".to_string());
    }
    if !args.iter().any(|arg| arg == "--verbose" || arg == "-v") {
        with_streaming.push("--verbose".to_string());
    }
    if !args.iter().any(|arg| arg == "--include-partial-messages") {
        with_streaming.push("--include-partial-messages".to_string());
    }
    with_streaming
}

fn claude_output_format(args: &[String]) -> Option<String> {
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = &args[idx];
        if let Some(value) = arg.strip_prefix("--output-format=") {
            return Some(value.to_string());
        }
        if arg == "--output-format" {
            return args.get(idx + 1).cloned().or_else(|| Some(String::new()));
        }
        idx += 1;
    }
    None
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("unknown error")
        .to_string()
}

fn best_error_line(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    if lines.is_empty() {
        return "unknown error".to_string();
    }

    if let Some(line) = lines
        .iter()
        .find(|line| line.to_ascii_lowercase().starts_with("error:"))
    {
        return (*line).to_string();
    }

    lines
        .last()
        .map(|line| (*line).to_string())
        .unwrap_or_else(|| "unknown error".to_string())
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, OnceLock as StdOnceLock};
    use tempfile::TempDir;

    fn cwd_lock() -> &'static StdMutex<()> {
        static LOCK: StdOnceLock<StdMutex<()>> = StdOnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    struct CwdReset(PathBuf);

    impl Drop for CwdReset {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.0);
        }
    }

    #[test]
    fn test_matches_worktrees_ignore_line() {
        assert!(matches_worktrees_ignore_line(".worktrees/"));
        assert!(matches_worktrees_ignore_line("/.worktrees"));
        assert!(matches_worktrees_ignore_line(".worktrees # keep out"));
        assert!(!matches_worktrees_ignore_line("target/"));
        assert!(!matches_worktrees_ignore_line("# .worktrees/"));
    }

    #[test]
    fn test_list_workspace_dirs_filters_reserved() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join("alpha")).expect("mkdir alpha");
        fs::create_dir_all(root.join("_logs")).expect("mkdir logs");
        fs::create_dir_all(root.join("_tmp")).expect("mkdir tmp");

        let dirs = list_workspace_dirs(root).expect("list dirs");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].0, "alpha");
    }

    #[test]
    fn test_infer_workspace_from_cwd() {
        let _cwd_guard = cwd_lock().lock().expect("lock cwd");
        let temp = TempDir::new().expect("tempdir");
        let worktrees = temp.path().join(".worktrees");
        let target = worktrees.join("foo").join("src");
        fs::create_dir_all(&target).expect("mkdir tree");

        let old = env::current_dir().expect("cwd");
        let _reset = CwdReset(old);
        env::set_current_dir(&target).expect("set cwd");
        let inferred = infer_workspace_from_cwd(&worktrees).expect("infer workspace");

        assert_eq!(inferred.0, "foo");
        let expected = worktrees
            .join("foo")
            .canonicalize()
            .expect("canonical path");
        assert_eq!(
            inferred.1.canonicalize().expect("canonical inferred path"),
            expected
        );
    }

    #[test]
    fn test_invoked_from_worktree() {
        let _cwd_guard = cwd_lock().lock().expect("lock cwd");
        let temp = TempDir::new().expect("tempdir");
        let worktrees = temp.path().join(".worktrees");
        let target = worktrees.join("foo").join("src");
        fs::create_dir_all(&target).expect("mkdir tree");

        let old = env::current_dir().expect("cwd");
        let _reset = CwdReset(old);
        env::set_current_dir(&target).expect("set cwd");
        assert!(invoked_from_worktree(&worktrees));

        env::set_current_dir(temp.path()).expect("set cwd to temp root");
        assert!(!invoked_from_worktree(&worktrees));
    }

    #[test]
    fn test_parse_claude_stream_line_text_delta() {
        let line =
            r#"{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"hello"}}}"#;
        assert_eq!(
            parse_claude_stream_line(line),
            ClaudeStreamLine::TextDelta("hello".to_string())
        );
    }

    #[test]
    fn test_parse_claude_stream_line_non_json() {
        let line = "plain output\n";
        assert_eq!(
            parse_claude_stream_line(line),
            ClaudeStreamLine::NonJson("plain output\n".to_string())
        );
    }

    #[test]
    fn test_common_root_from_git_common_dir() {
        let root = PathBuf::from("/tmp/repo");
        let git_common = root.join(".git");
        let nested = git_common.join("worktrees").join("foo");

        assert_eq!(common_root_from_git_common_dir(&git_common), Some(root));
        assert_eq!(common_root_from_git_common_dir(&nested), None);
    }

    #[test]
    fn test_ensure_claude_streaming_args_adds_defaults() {
        let args = vec!["-p".to_string(), "hello".to_string()];
        let augmented = ensure_claude_streaming_args(&args);
        assert!(augmented.iter().any(|arg| arg == "--verbose"));
        assert!(augmented
            .iter()
            .any(|arg| arg == "--include-partial-messages"));
        assert_eq!(
            claude_output_format(&augmented),
            Some("stream-json".to_string())
        );
    }

    #[test]
    fn test_ensure_claude_streaming_args_respects_existing_output_format() {
        let args = vec![
            "-p".to_string(),
            "hello".to_string(),
            "--output-format".to_string(),
            "text".to_string(),
            "--verbose".to_string(),
        ];
        let augmented = ensure_claude_streaming_args(&args);
        assert_eq!(claude_output_format(&augmented), Some("text".to_string()));
        assert!(augmented
            .iter()
            .any(|arg| arg == "--include-partial-messages"));
    }

    #[test]
    fn test_build_claude_args_includes_model() {
        let args = build_claude_args("hello", "sonnet");
        assert!(args
            .iter()
            .any(|arg| arg == "--dangerously-skip-permissions"));
        assert!(args.windows(2).any(|win| win == ["--model", "sonnet"]));
    }

    #[test]
    fn test_build_claude_args_omits_blank_model() {
        let args = build_claude_args("hello", "   ");
        assert!(!args.iter().any(|arg| arg == "--model"));
    }

    #[test]
    fn test_shell_quote_safe_chars_unchanged() {
        assert_eq!(shell_quote("abc-123_/."), "abc-123_/.");
    }

    #[test]
    fn test_shell_quote_escapes_single_quote() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn test_shell_join_quotes_complex_args() {
        let args = vec![
            "claude".to_string(),
            "-p".to_string(),
            "hello world".to_string(),
        ];
        assert_eq!(shell_join(&args), "claude -p 'hello world'");
    }

    #[test]
    fn test_parse_new_command_args_named_flag() {
        let parsed = parse_new_command_args(
            Some("feature".to_string()),
            Some("main".to_string()),
            vec!["claude".to_string(), "-p".to_string()],
        )
        .expect("parse args");

        assert_eq!(parsed.name.as_deref(), Some("feature"));
        assert_eq!(parsed.from.as_deref(), Some("main"));
        assert_eq!(
            parsed.agent_cmd,
            vec!["claude".to_string(), "-p".to_string()]
        );
    }

    #[test]
    fn test_parse_new_command_args_auto_default() {
        let parsed =
            parse_new_command_args(None, None, vec!["claude".to_string(), "-p".to_string()])
                .expect("parse args");

        assert_eq!(parsed.name, None);
        assert_eq!(parsed.from, None);
        assert_eq!(
            parsed.agent_cmd,
            vec!["claude".to_string(), "-p".to_string()]
        );
    }

    #[test]
    fn test_parse_new_command_args_missing_agent_command() {
        let err = parse_new_command_args(None, None, vec![]).expect_err("error");
        assert!(
            err.to_string().contains("agent command must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_rm_command_parse_name() {
        let cli = Cli::try_parse_from(["sir", "rm", "foo"]).expect("parse rm name");
        match cli.command {
            Commands::Rm { name, all_clean } => {
                assert_eq!(name.as_deref(), Some("foo"));
                assert!(!all_clean);
            }
            _ => panic!("expected rm command"),
        }
    }

    #[test]
    fn test_rm_command_parse_all_clean() {
        let cli = Cli::try_parse_from(["sir", "rm", "--all-clean"]).expect("parse rm all clean");
        match cli.command {
            Commands::Rm { name, all_clean } => {
                assert_eq!(name, None);
                assert!(all_clean);
            }
            _ => panic!("expected rm command"),
        }
    }

    #[test]
    fn test_cmd_rm_requires_name_without_all_clean() {
        let err = cmd_rm(None, false).expect_err("expected missing name error");
        assert!(err
            .to_string()
            .contains("workspace name is required unless --all-clean is set"));
    }

    #[test]
    fn test_cmd_rm_rejects_name_with_all_clean() {
        let err = cmd_rm(Some("foo"), true).expect_err("expected invalid arg combination");
        assert!(err
            .to_string()
            .contains("cannot pass <name> with --all-clean"));
    }

    #[test]
    fn test_porcelain_line_has_unstaged_changes() {
        assert!(!porcelain_line_has_unstaged_changes("M  src/main.rs"));
        assert!(!porcelain_line_has_unstaged_changes("A  src/main.rs"));
        assert!(porcelain_line_has_unstaged_changes(" M src/main.rs"));
        assert!(porcelain_line_has_unstaged_changes("?? src/new.rs"));
    }

    #[test]
    fn test_parse_auto_name_response_handles_json_and_null() {
        assert_eq!(parse_auto_name_response("null"), None);
        assert_eq!(
            parse_auto_name_response("\"pink elephant\""),
            Some("pink elephant".to_string())
        );
        assert_eq!(
            parse_auto_name_response("{\"name\":\"Fix API Tests\"}"),
            Some("fix api tests".to_string())
        );
        assert_eq!(parse_auto_name_response("{\"name\":null}"), None);
    }

    #[test]
    fn test_normalize_auto_name_candidate_filters_noise() {
        assert_eq!(
            normalize_auto_name_candidate("  `Feature: Fix tests!`  "),
            Some("feature fix tests".to_string())
        );
        assert_eq!(normalize_auto_name_candidate(""), None);
        assert_eq!(normalize_auto_name_candidate("NULL"), None);
    }

    #[test]
    fn test_collapse_whitespace_with_hyphen() {
        assert_eq!(
            collapse_whitespace_with_hyphen("pink    elephant"),
            "pink-elephant"
        );
        assert_eq!(
            collapse_whitespace_with_hyphen("  hello world "),
            "hello-world"
        );
    }

    #[test]
    fn test_slugify_branch_component() {
        assert_eq!(slugify_branch_component("Fix API tests"), "fix-api-tests");
        assert_eq!(slugify_branch_component("...wow..ok..."), "wow-ok");
        assert_eq!(slugify_branch_component("###"), "");
    }

    #[test]
    fn test_validate_workspace_name_rejects_dot_paths() {
        assert!(validate_workspace_name(".").is_err());
        assert!(validate_workspace_name("..").is_err());
    }

    #[test]
    fn test_settle_prompt_includes_additional_prompt() {
        let prompt = settle_prompt("foo", Path::new("/tmp/foo"), Some("also run tests"));
        assert!(prompt.contains("Additional user instructions"));
        assert!(prompt.contains("also run tests"));
    }

    #[test]
    fn test_settle_prompt_omits_additional_prompt_when_empty() {
        let prompt = settle_prompt("foo", Path::new("/tmp/foo"), Some("   "));
        assert!(!prompt.contains("Additional user instructions"));
    }

    #[test]
    fn test_normalize_settle_inputs_uses_name_as_prompt_inside_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let worktrees = temp.path().join(".worktrees");
        fs::create_dir_all(worktrees.join("foo")).expect("mkdir foo");
        let (name, prompt) = normalize_settle_inputs(&worktrees, true, Some("run tests"), None);
        assert_eq!(name, None);
        assert_eq!(prompt.as_deref(), Some("run tests"));
    }

    #[test]
    fn test_normalize_settle_inputs_keeps_existing_workspace_name() {
        let temp = TempDir::new().expect("tempdir");
        let worktrees = temp.path().join(".worktrees");
        fs::create_dir_all(worktrees.join("foo")).expect("mkdir foo");
        let (name, prompt) = normalize_settle_inputs(&worktrees, true, Some("foo"), None);
        assert_eq!(name.as_deref(), Some("foo"));
        assert_eq!(prompt, None);
    }
}
