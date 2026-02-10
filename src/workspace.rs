use crate::constants::{
    PORCELAIN_STATUS_MIN_BYTES, RESERVED_WORKTREE_LOGS, RESERVED_WORKTREE_TMP,
    STATUS_SUMMARY_MAX_LINES, STATUS_TRUNCATE_MAX_CHARS, TRUNCATE_ELLIPSIS_CHARS,
};
use crate::git::{
    current_git_branch_name, current_git_common_root, current_git_worktree_path, list_git_worktrees,
};
use crate::process::{best_error_line, path_to_str, run_capture, run_capture_with_input};
use anyhow::{Context, Result, bail};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct LinkedWorkspaceEntry {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceSource {
    Local,
    Linked,
}

impl std::fmt::Display for WorkspaceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Linked => write!(f, "linked"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceRecord {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) backend: WorkspaceBackend,
    pub(crate) source: WorkspaceSource,
}

#[derive(Debug, Clone)]
pub(crate) struct IndexedWorkspaceRecord {
    pub(crate) index: usize,
    pub(crate) record: WorkspaceRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceBackend {
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

pub(crate) fn detect_workspace_backend(path: &Path) -> WorkspaceBackend {
    if path.join(".git").exists() {
        WorkspaceBackend::Git
    } else {
        WorkspaceBackend::Unknown
    }
}

pub(crate) fn workspace_status_summary(backend: WorkspaceBackend, workspace_path: &Path) -> String {
    match backend {
        WorkspaceBackend::Git => match run_capture("git", &["status", "-sb"], Some(workspace_path))
        {
            Ok(output) if output.status.success() => squash_status_lines(&output.stdout),
            Ok(output) => format!("error: {}", crate::process::first_line(&output.stderr)),
            Err(err) => format!("error: {err}"),
        },
        WorkspaceBackend::Unknown => "no backend metadata detected".to_string(),
    }
}

pub(crate) fn squash_status_lines(raw: &str) -> String {
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(STATUS_SUMMARY_MAX_LINES)
        .collect();
    if lines.is_empty() {
        "clean".to_string()
    } else {
        lines.join(" | ")
    }
}

pub(crate) fn workspace_has_unstaged_changes(workspace_path: &Path) -> Result<bool> {
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

pub(crate) fn porcelain_line_has_unstaged_changes(line: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < PORCELAIN_STATUS_MIN_BYTES {
        return true;
    }
    bytes[1] != b' '
}

pub(crate) fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let head = value
        .chars()
        .take(max.saturating_sub(TRUNCATE_ELLIPSIS_CHARS))
        .collect::<String>();
    format!("{head}...")
}

pub(crate) fn status_truncate_max_chars() -> usize {
    STATUS_TRUNCATE_MAX_CHARS
}

pub(crate) fn validate_workspace_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("workspace name must not be empty");
    }
    if name == "." || name == ".." {
        bail!("workspace name `{name}` is invalid");
    }
    if name == RESERVED_WORKTREE_LOGS || name == RESERVED_WORKTREE_TMP {
        bail!("workspace name `{name}` is reserved");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("workspace name must not contain path separators");
    }
    Ok(())
}

pub(crate) fn ensure_worktrees_dir(repo_root: &Path) -> Result<(PathBuf, bool)> {
    let path = repo_root.join(".worktrees");
    let created = !path.exists();
    if created {
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
    }
    Ok((path, created))
}

pub(crate) fn is_worktrees_gitignored(repo_root: &Path) -> Result<bool> {
    let gitignore_path = repo_root.join(".gitignore");
    if !gitignore_path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(&gitignore_path)
        .with_context(|| format!("failed to read {}", gitignore_path.display()))?;
    Ok(content.lines().any(matches_worktrees_ignore_line))
}

pub(crate) fn matches_worktrees_ignore_line(line: &str) -> bool {
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

pub(crate) fn list_workspace_dirs(worktrees_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
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
        if name == RESERVED_WORKTREE_LOGS || name == RESERVED_WORKTREE_TMP {
            continue;
        }
        entries.push((name, entry.path()));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

pub(crate) fn workspace_is_metadata_only(workspace_path: &Path) -> Result<bool> {
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

pub(crate) fn workspace_has_tracked_content(
    repo_root: &Path,
    workspace_path: &Path,
) -> Result<bool> {
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

pub(crate) fn path_is_within_dir(path: &Path, dir: &Path) -> bool {
    if path.starts_with(dir) {
        return true;
    }
    match (path.canonicalize(), dir.canonicalize()) {
        (Ok(canonical_path), Ok(canonical_dir)) => canonical_path.starts_with(canonical_dir),
        _ => false,
    }
}

pub(crate) fn paths_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

pub(crate) fn discover_workspaces(repo_root: &Path) -> Result<Vec<WorkspaceRecord>> {
    let worktrees_dir = repo_root.join(".worktrees");
    let mut records = Vec::new();
    let mut seen_paths = Vec::new();

    for (name, path) in list_workspace_dirs(&worktrees_dir)? {
        let backend = detect_workspace_backend(&path);
        records.push(WorkspaceRecord {
            name,
            path: path.clone(),
            backend,
            source: WorkspaceSource::Local,
        });
        seen_paths.push(path);
    }

    let mut linked_entries = list_external_git_workspaces(repo_root, &worktrees_dir)?;
    linked_entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
    for linked in linked_entries {
        if seen_paths
            .iter()
            .any(|existing| paths_equal(existing, &linked.path))
        {
            continue;
        }
        let backend = detect_workspace_backend(&linked.path);
        records.push(WorkspaceRecord {
            name: linked.name,
            path: linked.path.clone(),
            backend,
            source: WorkspaceSource::Linked,
        });
        seen_paths.push(linked.path);
    }

    Ok(records)
}

pub(crate) fn list_external_git_workspaces(
    repo_root: &Path,
    worktrees_dir: &Path,
) -> Result<Vec<LinkedWorkspaceEntry>> {
    let entries = list_git_worktrees(repo_root)?;
    let mut linked = Vec::new();
    for entry in entries {
        if paths_equal(&entry.path, repo_root) || path_is_within_dir(&entry.path, worktrees_dir) {
            continue;
        }
        let name = entry.branch.clone().unwrap_or_else(|| {
            entry
                .path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| entry.path.display().to_string())
        });
        linked.push(LinkedWorkspaceEntry {
            name,
            path: entry.path,
        });
    }
    Ok(linked)
}

pub(crate) fn parse_workspace_index(value: &str) -> Option<usize> {
    let candidate = value.trim().strip_prefix('#').unwrap_or(value.trim());
    let parsed = candidate.parse::<usize>().ok()?;
    if parsed == 0 {
        return None;
    }
    Some(parsed)
}

pub(crate) fn resolve_workspace_for_rm(
    records: &[WorkspaceRecord],
    target: &str,
) -> Result<IndexedWorkspaceRecord> {
    if let Some(index) = parse_workspace_index(target)
        && let Some(record) = records.get(index.saturating_sub(1))
    {
        return Ok(IndexedWorkspaceRecord {
            index,
            record: record.clone(),
        });
    }

    let mut matches = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.name == target)
        .collect::<Vec<_>>();

    match matches.len() {
        1 => {
            let (offset, record) = matches.remove(0);
            Ok(IndexedWorkspaceRecord {
                index: offset + 1,
                record: record.clone(),
            })
        }
        0 => bail!("workspace target `{target}` was not found; run `sir status` to see indexes"),
        _ => {
            eprintln!("workspace target `{target}` is ambiguous; use an index from `sir status`:");
            for (offset, record) in matches {
                eprintln!(
                    "- [{}] {} ({})",
                    offset + 1,
                    record.name,
                    record.path.display()
                );
            }
            bail!("workspace target `{target}` matches multiple workspaces");
        }
    }
}

pub(crate) fn infer_workspace_from_cwd(worktrees_dir: &Path) -> Option<(String, PathBuf)> {
    let cwd = env::current_dir().ok()?;
    if let Some(found) = infer_workspace_from_paths(worktrees_dir, &cwd) {
        return Some(found);
    }

    let canonical_worktrees = worktrees_dir.canonicalize().ok()?;
    let canonical_cwd = cwd.canonicalize().ok()?;
    infer_workspace_from_paths(&canonical_worktrees, &canonical_cwd)
}

pub(crate) fn infer_workspace_from_current_git_worktree(
    repo_root: &Path,
) -> Option<(String, PathBuf)> {
    let workspace_path = current_git_worktree_path()?;
    let common_root = current_git_common_root()?;
    if !paths_equal(&common_root, repo_root) || paths_equal(&workspace_path, repo_root) {
        return None;
    }

    let workspace_name = current_git_branch_name()
        .or_else(|| {
            workspace_path
                .file_name()
                .map(|component| component.to_string_lossy().to_string())
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| workspace_path.display().to_string());
    Some((workspace_name, workspace_path))
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

pub(crate) fn normalize_settle_inputs(
    worktrees_dir: &Path,
    started_in_worktree: bool,
    maybe_name: Option<&str>,
    prompt: Option<&str>,
) -> (Option<String>, Option<String>) {
    let mut effective_name = maybe_name.map(str::to_string);
    let mut additional_prompt = prompt.map(str::to_string);
    if additional_prompt.is_none()
        && started_in_worktree
        && let Some(candidate) = effective_name.as_ref()
        && !worktrees_dir.join(candidate).is_dir()
    {
        additional_prompt = Some(candidate.clone());
        effective_name = None;
    }
    (effective_name, additional_prompt)
}

pub(crate) fn reserve_workspace_name(worktrees_dir: &Path, name: &str) -> Result<bool> {
    let workspace_path = worktrees_dir.join(name);
    match fs::create_dir(&workspace_path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to reserve workspace name `{name}` at {}",
                workspace_path.display()
            )
        }),
    }
}

pub(crate) fn remove_workspace_for_recreate(repo_root: &Path, workspace_path: &Path) -> Result<()> {
    if workspace_path.exists() {
        let workspace_str = path_to_str(workspace_path)?;
        match run_capture(
            "git",
            &["worktree", "remove", "--force", workspace_str],
            Some(repo_root),
        ) {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                eprintln!(
                    "warning: git worktree remove failed for {}: {}",
                    workspace_path.display(),
                    best_error_line(&output.stderr)
                );
            }
            Err(err) => {
                eprintln!(
                    "warning: failed to run git worktree remove for {}: {err:#}",
                    workspace_path.display()
                );
            }
        }
    }

    if workspace_path.exists() {
        fs::remove_dir_all(workspace_path).with_context(|| {
            format!(
                "failed to remove incomplete workspace {}",
                workspace_path.display()
            )
        })?;
    }

    Ok(())
}

pub(crate) fn apply_uncommitted_changes(repo_root: &Path, workspace_path: &Path) -> Result<()> {
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
        crate::ui::progress("new: no uncommitted changes found in source workspace");
    } else if copied_untracked > 0 {
        crate::ui::progress(&format!(
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

pub(crate) fn remove_workspace_record(
    repo_root: &Path,
    index: usize,
    record: &WorkspaceRecord,
) -> Result<()> {
    crate::ui::progress(&format!(
        "rm: removing workspace [{}] `{}` at {}",
        index,
        record.name,
        record.path.display()
    ));
    if !record.path.exists() {
        bail!("workspace path does not exist: {}", record.path.display());
    }
    if !record.path.is_dir() {
        bail!(
            "workspace path is not a directory: {}",
            record.path.display()
        );
    }

    match record.backend {
        WorkspaceBackend::Git => {
            let workspace_str = path_to_str(&record.path)?;
            let output = run_capture(
                "git",
                &["worktree", "remove", "--force", workspace_str],
                Some(repo_root),
            )?;
            if output.status.success() {
                crate::ui::progress(&format!(
                    "rm: removed workspace [{}] `{}`",
                    index, record.name
                ));
                return Ok(());
            }

            if detect_workspace_backend(&record.path) == WorkspaceBackend::Unknown {
                fs::remove_dir_all(&record.path)
                    .with_context(|| format!("failed to remove {}", record.path.display()))?;
                crate::ui::progress(&format!(
                    "rm: removed non-git workspace [{}] `{}`",
                    index, record.name
                ));
                return Ok(());
            }

            bail!(
                "failed to remove git worktree [{}] `{}`: {}",
                index,
                record.name,
                best_error_line(&output.stderr)
            );
        }
        WorkspaceBackend::Unknown => {
            fs::remove_dir_all(&record.path)
                .with_context(|| format!("failed to remove {}", record.path.display()))?;
            crate::ui::progress(&format!(
                "rm: removed non-git workspace [{}] `{}`",
                index, record.name
            ));
            Ok(())
        }
    }
}
