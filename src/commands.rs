use crate::claude::{
    auto_name_prompt, new_init_prompt, parse_auto_name_response, run_claude, run_claude_text,
    settle_prompt,
};
use crate::cli::{Commands, parse_new_command_args};
use crate::config::Config;
use crate::constants::{DEFAULT_WORKSPACE_REVISION, FALLBACK_NAME_MAX_RESERVATION_ATTEMPTS};
use crate::git::{
    git_branch_exists, git_revision_exists, repo_common_root, repo_root, workspace_branch_name,
};
use crate::process::{
    best_error_line, binary_available, first_line, path_to_str, print_command_output, run_capture,
    run_stream,
};
use crate::shell::{preferred_shell, shell_join, shell_quote};
use crate::ui::progress;
use crate::workspace::{
    WorkspaceBackend, WorkspaceSource, apply_uncommitted_changes, detect_workspace_backend,
    discover_workspaces, ensure_worktrees_dir, infer_workspace_from_current_git_worktree,
    infer_workspace_from_cwd, is_worktrees_gitignored, normalize_settle_inputs,
    remove_workspace_for_recreate, remove_workspace_record, reserve_workspace_name,
    resolve_workspace_for_rm, status_truncate_max_chars, truncate, validate_workspace_name,
    workspace_has_tracked_content, workspace_has_unstaged_changes, workspace_is_metadata_only,
    workspace_status_summary,
};
use crate::workspace_name::fallback_workspace_name_candidate;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::IsTerminal;
use std::path::Path;

pub(crate) fn run(command: Commands, config: &Config) -> Result<()> {
    match command {
        Commands::Doctor => cmd_doctor(config),
        Commands::New { name, from, args } => {
            let parsed = parse_new_command_args(name, from, args)?;
            cmd_new(
                config,
                parsed.name.as_deref(),
                parsed.from.as_deref(),
                &parsed.agent_cmd,
            )
        }
        Commands::Status { json } => cmd_status(json),
        Commands::Open { name } => cmd_open(&name),
        Commands::Rm { name, all_clean } => cmd_rm(name.as_deref(), all_clean),
        Commands::Settle { name, prompt } => cmd_settle(config, name.as_deref(), prompt.as_deref()),
    }
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
struct ResolvedWorkspaceName {
    name: String,
    reserved: bool,
}

fn cmd_new(
    config: &Config,
    explicit_name: Option<&str>,
    from_revision: Option<&str>,
    agent_cmd: &[String],
) -> Result<()> {
    let repo_root = repo_root()?;
    let (worktrees_dir, _) = ensure_worktrees_dir(&repo_root)?;
    let resolved_name =
        resolve_new_workspace_name(config, explicit_name, agent_cmd, &repo_root, &worktrees_dir)?;
    let name = resolved_name.name;
    let reserved_name = resolved_name.reserved;

    progress(&format!("new: preparing workspace `{name}`"));
    validate_workspace_name(&name)?;
    let workspace_path = worktrees_dir.join(&name);
    let mut created_workspace = false;

    if workspace_path.is_dir() && !reserved_name {
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
            remove_workspace_for_recreate(&repo_root, &workspace_path)?;
        }
    }

    if reserved_name || !workspace_path.exists() {
        let create_result = (|| -> Result<()> {
            progress("new: creating git worktree");
            let revision = from_revision.unwrap_or(DEFAULT_WORKSPACE_REVISION).trim();
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
                    remove_workspace_for_recreate(&repo_root, &workspace_path)?;
                }
                bail!("failed to create git worktree `{name}`: {error_line}");
            }
            created_workspace = true;
            Ok(())
        })();

        if let Err(err) = create_result {
            if reserved_name
                && workspace_path.exists()
                && let Err(cleanup_err) = remove_workspace_for_recreate(&repo_root, &workspace_path)
            {
                eprintln!(
                    "warning: failed to clean reserved workspace `{}` after error: {cleanup_err:#}",
                    workspace_path.display()
                );
            }
            return Err(err);
        }
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
) -> Result<ResolvedWorkspaceName> {
    if let Some(name) = explicit_name {
        validate_workspace_name(name)?;
        return Ok(ResolvedWorkspaceName {
            name: name.to_string(),
            reserved: false,
        });
    }

    progress("new: generating workspace name via Claude");
    let command = shell_join(agent_cmd);
    let mut claude_suggestion =
        match suggest_workspace_name_from_claude(config, &command, repo_root) {
            Ok(Some(name)) if validate_workspace_name(&name).is_ok() => Some(name),
            Ok(Some(name)) => {
                eprintln!("warning: ignoring invalid generated workspace name `{name}`");
                None
            }
            Ok(None) => None,
            Err(err) => {
                eprintln!("warning: failed to generate workspace name via Claude: {err}");
                None
            }
        };
    let mut fallback_attempt = 0u64;

    for _ in 0..FALLBACK_NAME_MAX_RESERVATION_ATTEMPTS {
        let candidate = match claude_suggestion.take() {
            Some(name) => name,
            None => {
                let name = fallback_workspace_name_candidate(fallback_attempt);
                fallback_attempt = fallback_attempt.saturating_add(1);
                name
            }
        };

        if validate_workspace_name(&candidate).is_err() {
            continue;
        }

        if reserve_workspace_name(worktrees_dir, &candidate)? {
            progress(&format!("new: selected workspace name `{candidate}`"));
            return Ok(ResolvedWorkspaceName {
                name: candidate,
                reserved: true,
            });
        }
    }

    bail!(
        "failed to reserve a unique workspace name under {}",
        worktrees_dir.display()
    )
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

pub(crate) fn cmd_rm(name: Option<&str>, all_clean: bool) -> Result<()> {
    if all_clean {
        if name.is_some() {
            bail!("cannot pass <name> with --all-clean");
        }
        return cmd_rm_all_clean();
    }

    let target = name.context("workspace name is required unless --all-clean is set")?;
    cmd_rm_single(target)
}

fn cmd_rm_single(target: &str) -> Result<()> {
    progress(&format!("rm: resolving workspace target `{target}`"));
    let repo_root = repo_common_root()?;
    let records = discover_workspaces(&repo_root)?;
    let resolved = resolve_workspace_for_rm(&records, target)?;
    remove_workspace_record(&repo_root, resolved.index, &resolved.record)
}

fn cmd_rm_all_clean() -> Result<()> {
    progress("rm: scanning for clean workspaces");
    let repo_root = repo_common_root()?;
    let records = discover_workspaces(&repo_root)?;
    let worktrees_dir = repo_root.join(".worktrees");
    if records.is_empty() {
        println!(
            "No workspaces found under {} or linked via git worktree",
            worktrees_dir.display()
        );
        return Ok(());
    }

    let mut removed = 0usize;
    let mut skipped_dirty = 0usize;
    let mut skipped_non_git = 0usize;
    let mut failures = Vec::new();

    for (offset, record) in records.iter().enumerate() {
        let index = offset + 1;
        if record.backend != WorkspaceBackend::Git {
            skipped_non_git += 1;
            continue;
        }

        match workspace_has_unstaged_changes(&record.path) {
            Ok(true) => {
                skipped_dirty += 1;
            }
            Ok(false) => {
                progress(&format!(
                    "rm: removing clean workspace [{}] `{}`",
                    index, record.name
                ));
                if let Err(err) = remove_workspace_record(&repo_root, index, record) {
                    failures.push(format!("{} [{}]: {err:#}", record.name, index));
                } else {
                    removed += 1;
                }
            }
            Err(err) => failures.push(format!("{} [{}]: {err:#}", record.name, index)),
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

#[derive(Debug)]
struct StatusRow {
    index: usize,
    name: String,
    path: std::path::PathBuf,
    backend: WorkspaceBackend,
    source: WorkspaceSource,
    summary: String,
}

#[derive(Debug, Serialize)]
struct JsonStatusRow {
    index: usize,
    name: String,
    path: String,
    backend: String,
    source: String,
    summary: String,
}

fn cmd_status(as_json: bool) -> Result<()> {
    progress("status: scanning workspaces");
    let repo_root = repo_common_root()?;
    let worktrees_dir = repo_root.join(".worktrees");
    let records = discover_workspaces(&repo_root)?;
    let rows: Vec<StatusRow> = records
        .into_iter()
        .enumerate()
        .map(|(offset, record)| {
            let path = record.path;
            let summary = workspace_status_summary(record.backend, &path);
            StatusRow {
                index: offset + 1,
                name: record.name,
                path,
                backend: record.backend,
                source: record.source,
                summary,
            }
        })
        .collect();

    if as_json {
        let json_rows: Vec<JsonStatusRow> = rows
            .iter()
            .map(|row| JsonStatusRow {
                index: row.index,
                name: row.name.clone(),
                path: row.path.display().to_string(),
                backend: row.backend.to_string(),
                source: row.source.to_string(),
                summary: row.summary.clone(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!(
            "No workspaces found under {} or linked via git worktree",
            worktrees_dir.display()
        );
        return Ok(());
    }

    println!(
        "{:<4} {:<24} {:<8} {:<8} STATUS",
        "IDX", "NAME", "BACKEND", "SOURCE"
    );
    for row in rows {
        println!(
            "{:<4} {:<24} {:<8} {:<8} {}",
            row.index,
            row.name,
            row.backend,
            row.source,
            truncate(&row.summary, status_truncate_max_chars())
        );
    }

    Ok(())
}

fn cmd_settle(config: &Config, maybe_name: Option<&str>, prompt: Option<&str>) -> Result<()> {
    progress("settle: resolving workspace");
    let repo_root = repo_common_root()?;
    let worktrees_dir = repo_root.join(".worktrees");
    let inferred_workspace = infer_workspace_from_cwd(&worktrees_dir)
        .or_else(|| infer_workspace_from_current_git_worktree(&repo_root));
    let started_in_worktree = inferred_workspace.is_some();
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
        None => {
            inferred_workspace.context("could not infer workspace name; pass one explicitly")?
        }
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
    let shell = preferred_shell();
    if !Path::new(&shell).exists() {
        bail!("new requires `$SHELL` to reference an existing shell (got `{shell}`)");
    }

    let command = shell_join(agent_cmd);
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return run_stream(&shell, &["-c", &command], Some(workspace_path))
            .with_context(|| format!("failed to run agent command inside `{shell}`"));
    }

    let shell_quoted = shell_quote(&shell);
    let script = format!("{command};\necho;\nexec {shell_quoted} -i");
    run_stream(&shell, &["-i", "-c", &script], Some(workspace_path))
        .with_context(|| format!("failed to run agent command inside `{shell}`"))
}

fn run_workspace_shell(workspace_path: &Path) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        println!(
            "Non-interactive terminal detected; workspace path: {}",
            workspace_path.display()
        );
        return Ok(());
    }

    let shell = preferred_shell();

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

    let shell = preferred_shell();

    println!(
        "\nSettle complete. Opening shell `{shell}` in {}",
        repo_root.display()
    );
    run_stream(&shell, &[], Some(repo_root))
        .with_context(|| format!("failed to run `{shell}` at repo root"))
}
