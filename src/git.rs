use crate::process::{best_error_line, run_capture};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub(crate) fn repo_root() -> Result<PathBuf> {
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

pub(crate) fn repo_common_root() -> Result<PathBuf> {
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

pub(crate) fn common_root_from_git_common_dir(common_dir: &Path) -> Option<PathBuf> {
    if common_dir.file_name()? != ".git" {
        return None;
    }
    common_dir.parent().map(Path::to_path_buf)
}

pub(crate) fn git_branch_exists(repo_root: &Path, branch: &str) -> bool {
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

pub(crate) fn git_branch_name_valid(repo_root: &Path, branch: &str) -> bool {
    run_capture(
        "git",
        &["check-ref-format", "--branch", branch],
        Some(repo_root),
    )
    .map(|output| output.status.success())
    .unwrap_or(false)
}

pub(crate) fn git_revision_exists(repo_root: &Path, revision: &str) -> bool {
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

pub(crate) fn workspace_branch_name(repo_root: &Path, workspace_name: &str) -> Result<String> {
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

pub(crate) fn collapse_whitespace_with_hyphen(value: &str) -> String {
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

pub(crate) fn slugify_branch_component(value: &str) -> String {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitWorktreeEntry {
    pub(crate) path: PathBuf,
    pub(crate) branch: Option<String>,
}

pub(crate) fn list_git_worktrees(repo_root: &Path) -> Result<Vec<GitWorktreeEntry>> {
    let output = run_capture("git", &["worktree", "list", "--porcelain"], Some(repo_root))
        .context("failed to list git worktrees")?;
    if !output.status.success() {
        bail!(
            "failed to list git worktrees: {}",
            best_error_line(&output.stderr)
        );
    }
    Ok(parse_git_worktree_porcelain(&output.stdout))
}

pub(crate) fn parse_git_worktree_porcelain(raw: &str) -> Vec<GitWorktreeEntry> {
    let mut entries = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_branch: Option<String> = None;

    let flush_current = |entries: &mut Vec<GitWorktreeEntry>,
                         current_path: &mut Option<PathBuf>,
                         current_branch: &mut Option<String>| {
        if let Some(path) = current_path.take() {
            entries.push(GitWorktreeEntry {
                path,
                branch: current_branch.take(),
            });
        } else {
            current_branch.take();
        }
    };

    for line in raw.lines() {
        if line.is_empty() {
            flush_current(&mut entries, &mut current_path, &mut current_branch);
            continue;
        }

        if let Some(value) = line.strip_prefix("worktree ") {
            flush_current(&mut entries, &mut current_path, &mut current_branch);
            current_path = Some(PathBuf::from(value.trim()));
            continue;
        }

        if let Some(value) = line.strip_prefix("branch ")
            && let Some(short) = value.trim().strip_prefix("refs/heads/")
        {
            current_branch = Some(short.to_string());
            continue;
        }
    }

    flush_current(&mut entries, &mut current_path, &mut current_branch);
    entries
}

pub(crate) fn current_git_worktree_path() -> Option<PathBuf> {
    let output = run_capture(
        "git",
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
        None,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = output.stdout.trim();
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

pub(crate) fn current_git_common_root() -> Option<PathBuf> {
    let output = run_capture(
        "git",
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        None,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let common_dir = PathBuf::from(output.stdout.trim());
    common_root_from_git_common_dir(&common_dir)
}

pub(crate) fn current_git_branch_name() -> Option<String> {
    let output = run_capture("git", &["rev-parse", "--abbrev-ref", "HEAD"], None).ok()?;
    if !output.status.success() {
        return None;
    }
    let branch = output.stdout.trim();
    if branch.is_empty() || branch == "HEAD" {
        return None;
    }
    Some(branch.to_string())
}
