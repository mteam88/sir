use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

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
        Commands::Spawn { name, agent_cmd } => cmd_spawn(&config, &name, &agent_cmd),
        Commands::Status { json } => cmd_status(json),
        Commands::Open { name } => cmd_open(&name),
        Commands::Settle { name } => cmd_settle(&config, name.as_deref()),
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sir",
    version,
    about = "Small workspace wrapper for jj + Claude in the raw terminal"
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
    Spawn {
        name: String,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        agent_cmd: Vec<String>,
    },
    /// Show discovered workspaces and status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Open an interactive shell in the workspace.
    Open { name: String },
    /// Let Claude integrate a workspace back to main.
    Settle { name: Option<String> },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Backend {
    Jj,
    Git,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jj => write!(f, "jj"),
            Self::Git => write!(f, "git"),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct PartialConfig {
    backend: Option<Backend>,
    claude_bin: Option<String>,
}

#[derive(Debug, Clone)]
struct Config {
    backend: Backend,
    claude_bin: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: Backend::Jj,
            claude_bin: "claude".to_string(),
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
            if let Some(backend) = parsed.backend {
                config.backend = backend;
            }
            if let Some(claude_bin) = parsed.claude_bin
                && !claude_bin.trim().is_empty()
            {
                config.claude_bin = claude_bin;
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
    }

    if matches!(config.backend, Backend::Jj) {
        if binary_available("jj") {
            checks.push(Check::ok(
                "jj installed",
                "`jj --version` works".to_string(),
            ));
            if let Some(root) = &repo_root {
                let colocated = run_capture("jj", &["workspace", "list"], Some(root));
                match colocated {
                    Ok(output) if output.status.success() => {
                        checks.push(Check::ok(
                            "jj repo available",
                            "workspace metadata detected".to_string(),
                        ));
                    }
                    _ => {
                        failed = true;
                        checks.push(Check::fail(
                            "jj repo available",
                            "could not access jj workspace metadata in this repo".to_string(),
                            Some("jj git init --colocate".to_string()),
                        ));
                    }
                }
            }
        } else {
            failed = true;
            checks.push(Check::fail(
                "jj installed",
                "`jj` is not on PATH".to_string(),
                Some("brew install jj".to_string()),
            ));
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
            "spawn/open will run directly in this terminal".to_string(),
        ));
    } else {
        checks.push(Check::ok(
            "Terminal mode",
            "non-interactive environment detected; spawn/open still run commands but open avoids launching an interactive shell"
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

fn cmd_spawn(config: &Config, name: &str, agent_cmd: &[String]) -> Result<()> {
    validate_workspace_name(name)?;
    let repo_root = repo_root()?;
    let (worktrees_dir, _) = ensure_worktrees_dir(&repo_root)?;
    let workspace_path = worktrees_dir.join(name);

    if !workspace_path.exists() {
        match config.backend {
            Backend::Jj => {
                let workspace_str = path_to_str(&workspace_path)?;
                let output = run_capture(
                    "jj",
                    &[
                        "workspace",
                        "add",
                        "--name",
                        name,
                        "-r",
                        "main",
                        workspace_str,
                    ],
                    Some(&repo_root),
                )?;
                if !output.status.success() {
                    if workspace_path.join(".jj").exists() {
                        eprintln!(
                            "warning: `jj workspace add` exited non-zero, but workspace `{name}` was created; continuing"
                        );
                    } else {
                        bail!(
                            "failed to create jj workspace `{name}`: {}",
                            best_error_line(&output.stderr)
                        );
                    }
                }
            }
            Backend::Git => {
                bail!("git backend is not implemented yet");
            }
        }
    }

    let init_prompt = spawn_init_prompt(&workspace_path);
    run_claude(&config.claude_bin, &init_prompt, &repo_root)?;

    run_agent_command(agent_cmd, &workspace_path)
}

fn cmd_open(name: &str) -> Result<()> {
    validate_workspace_name(name)?;
    let repo_root = repo_root()?;
    let workspace_path = repo_root.join(".worktrees").join(name);
    if !workspace_path.is_dir() {
        bail!("workspace does not exist: {}", workspace_path.display());
    }

    run_workspace_shell(&workspace_path)
}

fn cmd_status(as_json: bool) -> Result<()> {
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

fn cmd_settle(config: &Config, maybe_name: Option<&str>) -> Result<()> {
    let repo_root = repo_root()?;
    let worktrees_dir = repo_root.join(".worktrees");

    let (name, workspace_path) = match maybe_name {
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

    let settle_prompt = settle_prompt(&name, &workspace_path);
    run_claude(&config.claude_bin, &settle_prompt, &workspace_path)?;

    println!("\nPost-check:");
    match run_capture("git", &["status", "-sb"], Some(&repo_root)) {
        Ok(output) => {
            print_command_output("git status -sb", &output.stdout, &output.stderr);
        }
        Err(err) => {
            println!("- git status -sb failed: {err}");
        }
    }

    match run_capture("jj", &["st"], Some(&repo_root)) {
        Ok(output) => {
            print_command_output("jj st", &output.stdout, &output.stderr);
        }
        Err(_) => {
            // JJ check is optional in post-check output.
        }
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

    let program = &agent_cmd[0];
    let args: Vec<&str> = agent_cmd.iter().skip(1).map(String::as_str).collect();
    run_stream(program, &args, Some(workspace_path))
        .with_context(|| format!("failed to run agent command `{}`", program))
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

fn spawn_init_prompt(workspace_path: &Path) -> String {
    format!(
        "You are in the repo root. Copy initialization data into workspace at:\n{}\n\nRequirements:\n- Copy .env into the workspace if present, but do not overwrite workspace .env if it already exists.\n- Copy target/ into the workspace if present.\n- Copy node_modules/ into the workspace if present.\n- Use copy-on-write on macOS when possible (cp -c). Otherwise use plain recursive copy (cp -R).\n- Never create symlinks.\n- Be conservative and avoid destructive actions.\n- Do not ask questions; execute directly and report what you did.",
        workspace_path.display()
    )
}

fn settle_prompt(name: &str, workspace_path: &Path) -> String {
    format!(
        "You are in workspace `{name}` at `{}`.\n\nGoal: integrate this workspace into main in a colocated jj+git repository.\n\nRequirements:\n- Inspect changes with jj status/diff/log.\n- Ensure changes are in a clean commit (or a small clean commit stack) with excellent commit message quality based on the diff intent.\n- Rebase/merge onto the latest main and resolve conflicts.\n- Integrate the result onto main using jj primitives suitable for a colocated repo.\n- If .env.example or any similar example-env file changed, update .env by adding new keys/defaults without overwriting existing secrets.\n- Leave the workspace and main in a sensible state.\n- Run commands directly with no follow-up questions unless absolutely blocked.",
        workspace_path.display()
    )
}

fn run_claude(claude_bin: &str, prompt: &str, cwd: &Path) -> Result<()> {
    let args = ["-p", prompt, "--dangerously-skip-permissions"];
    run_stream(claude_bin, &args, Some(cwd))
        .with_context(|| format!("failed while running `{claude_bin}`"))
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

#[derive(Debug, Clone, Copy)]
enum WorkspaceBackend {
    Jj,
    Git,
    Unknown,
}

impl std::fmt::Display for WorkspaceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jj => write!(f, "jj"),
            Self::Git => write!(f, "git"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

fn detect_workspace_backend(path: &Path) -> WorkspaceBackend {
    if path.join(".jj").exists() {
        WorkspaceBackend::Jj
    } else if path.join(".git").exists() {
        WorkspaceBackend::Git
    } else {
        WorkspaceBackend::Unknown
    }
}

fn workspace_status_summary(backend: WorkspaceBackend, workspace_path: &Path) -> String {
    match backend {
        WorkspaceBackend::Jj => match run_capture("jj", &["st"], Some(workspace_path)) {
            Ok(output) if output.status.success() => squash_status_lines(&output.stdout),
            Ok(output) => format!("error: {}", first_line(&output.stderr)),
            Err(err) => format!("error: {err}"),
        },
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

fn infer_workspace_from_cwd(worktrees_dir: &Path) -> Option<(String, PathBuf)> {
    let cwd = env::current_dir().ok()?;
    if let Some(found) = infer_workspace_from_paths(worktrees_dir, &cwd) {
        return Some(found);
    }

    let canonical_worktrees = worktrees_dir.canonicalize().ok()?;
    let canonical_cwd = cwd.canonicalize().ok()?;
    infer_workspace_from_paths(&canonical_worktrees, &canonical_cwd)
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
    use tempfile::TempDir;

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
        let temp = TempDir::new().expect("tempdir");
        let worktrees = temp.path().join(".worktrees");
        let target = worktrees.join("foo").join("src");
        fs::create_dir_all(&target).expect("mkdir tree");

        let old = env::current_dir().expect("cwd");
        env::set_current_dir(&target).expect("set cwd");
        let inferred = infer_workspace_from_cwd(&worktrees).expect("infer workspace");
        env::set_current_dir(old).expect("restore cwd");

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
}
