use crate::claude::{
    ClaudeStreamLine, build_claude_args, claude_output_format, ensure_claude_streaming_args,
    normalize_auto_name_candidate, parse_auto_name_response, parse_claude_stream_line,
    settle_prompt,
};
use crate::cli::{Cli, Commands, parse_new_command_args};
use crate::commands::cmd_rm;
use crate::git::{
    collapse_whitespace_with_hyphen, common_root_from_git_common_dir, parse_git_worktree_porcelain,
    slugify_branch_component,
};
use crate::process::run_capture;
use crate::shell::{shell_join, shell_quote};
use crate::workspace::{
    WorkspaceBackend, WorkspaceRecord, WorkspaceSource, infer_workspace_from_current_git_worktree,
    infer_workspace_from_cwd, list_external_git_workspaces, list_workspace_dirs,
    matches_worktrees_ignore_line, normalize_settle_inputs, parse_workspace_index,
    porcelain_line_has_unstaged_changes, reserve_workspace_name, resolve_workspace_for_rm,
    validate_workspace_name,
};
use clap::Parser;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
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

fn run_git_checked(cwd: &Path, args: &[&str]) {
    let output = run_capture("git", args, Some(cwd)).expect("run git command");
    assert!(
        output.status.success(),
        "git {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        output.stdout,
        output.stderr
    );
}

fn init_test_repo(root: &Path) -> PathBuf {
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("mkdir repo");
    run_git_checked(&repo, &["init"]);
    run_git_checked(&repo, &["config", "user.email", "test@example.com"]);
    run_git_checked(&repo, &["config", "user.name", "Test User"]);
    fs::write(repo.join("README.md"), "hello\n").expect("write README");
    run_git_checked(&repo, &["add", "README.md"]);
    run_git_checked(&repo, &["commit", "-m", "init"]);
    repo
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
fn test_reserve_workspace_name_is_atomic_for_existing_dir() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    fs::create_dir_all(root).expect("mkdir root");
    assert!(reserve_workspace_name(root, "alpha").expect("reserve first"));
    assert!(!reserve_workspace_name(root, "alpha").expect("reserve second"));
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
fn test_infer_workspace_from_current_git_worktree_external_path() {
    let _cwd_guard = cwd_lock().lock().expect("lock cwd");
    let temp = TempDir::new().expect("tempdir");
    let repo = init_test_repo(temp.path());
    let worktree = temp
        .path()
        .join(".codex")
        .join("worktrees")
        .join("3ed7")
        .join("sir");
    let worktree_parent = worktree.parent().expect("worktree parent");
    fs::create_dir_all(worktree_parent).expect("mkdir worktree parent");
    run_git_checked(
        &repo,
        &[
            "worktree",
            "add",
            "-b",
            "codex/worktree-compatibility",
            worktree.to_string_lossy().as_ref(),
            "HEAD",
        ],
    );
    let nested = worktree.join("src");
    fs::create_dir_all(&nested).expect("mkdir nested");

    let old = env::current_dir().expect("cwd");
    let _reset = CwdReset(old);
    env::set_current_dir(&nested).expect("set cwd");

    let inferred = infer_workspace_from_current_git_worktree(&repo).expect("infer workspace");
    assert_eq!(inferred.0, "codex/worktree-compatibility");
    assert_eq!(
        inferred.1.canonicalize().expect("canonical inferred path"),
        worktree.canonicalize().expect("canonical worktree path")
    );
}

#[test]
fn test_infer_workspace_from_current_git_worktree_ignores_main_worktree() {
    let _cwd_guard = cwd_lock().lock().expect("lock cwd");
    let temp = TempDir::new().expect("tempdir");
    let repo = init_test_repo(temp.path());

    let old = env::current_dir().expect("cwd");
    let _reset = CwdReset(old);
    env::set_current_dir(&repo).expect("set cwd to repo root");

    assert!(infer_workspace_from_current_git_worktree(&repo).is_none());
}

#[test]
fn test_parse_git_worktree_porcelain() {
    let raw = "\
worktree /tmp/repo
HEAD 1111111111111111111111111111111111111111
branch refs/heads/main

worktree /tmp/codex
HEAD 2222222222222222222222222222222222222222
branch refs/heads/feature/test
";
    let entries = parse_git_worktree_porcelain(raw);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, PathBuf::from("/tmp/repo"));
    assert_eq!(entries[0].branch.as_deref(), Some("main"));
    assert_eq!(entries[1].path, PathBuf::from("/tmp/codex"));
    assert_eq!(entries[1].branch.as_deref(), Some("feature/test"));
}

#[test]
fn test_parse_git_worktree_porcelain_detached() {
    let raw = "\
worktree /tmp/repo
HEAD 1111111111111111111111111111111111111111

worktree /tmp/detached
HEAD 2222222222222222222222222222222222222222
detached
";
    let entries = parse_git_worktree_porcelain(raw);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].branch, None);
    assert_eq!(entries[1].branch, None);
}

#[test]
fn test_list_external_git_workspaces_excludes_main_and_local_worktrees() {
    let _cwd_guard = cwd_lock().lock().expect("lock cwd");
    let temp = TempDir::new().expect("tempdir");
    let repo = init_test_repo(temp.path());
    let local_worktrees = repo.join(".worktrees");
    fs::create_dir_all(&local_worktrees).expect("mkdir local worktrees");

    let local = local_worktrees.join("local");
    run_git_checked(
        &repo,
        &[
            "worktree",
            "add",
            "-b",
            "sir/local",
            local.to_string_lossy().as_ref(),
            "HEAD",
        ],
    );

    let external = temp
        .path()
        .join(".codex")
        .join("worktrees")
        .join("3ed7")
        .join("sir");
    fs::create_dir_all(external.parent().expect("external parent")).expect("mkdir external parent");
    run_git_checked(
        &repo,
        &[
            "worktree",
            "add",
            "-b",
            "codex/status-linked",
            external.to_string_lossy().as_ref(),
            "HEAD",
        ],
    );

    let linked = list_external_git_workspaces(&repo, &local_worktrees).expect("list linked");
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].name, "codex/status-linked");
    assert_eq!(
        linked[0]
            .path
            .canonicalize()
            .expect("canonical linked path"),
        external.canonicalize().expect("canonical external path")
    );
}

#[test]
fn test_parse_claude_stream_line_text_delta() {
    let line = r#"{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"hello"}}}"#;
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
    assert!(
        augmented
            .iter()
            .any(|arg| arg == "--include-partial-messages")
    );
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
    assert!(
        augmented
            .iter()
            .any(|arg| arg == "--include-partial-messages")
    );
}

#[test]
fn test_build_claude_args_includes_model() {
    let args = build_claude_args("hello", "sonnet");
    assert!(
        args.iter()
            .any(|arg| arg == "--dangerously-skip-permissions")
    );
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
    let parsed = parse_new_command_args(None, None, vec!["claude".to_string(), "-p".to_string()])
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
    assert!(
        err.to_string()
            .contains("workspace name is required unless --all-clean is set")
    );
}

#[test]
fn test_cmd_rm_rejects_name_with_all_clean() {
    let err = cmd_rm(Some("foo"), true).expect_err("expected invalid arg combination");
    assert!(
        err.to_string()
            .contains("cannot pass <name> with --all-clean")
    );
}

#[test]
fn test_parse_workspace_index() {
    assert_eq!(parse_workspace_index("1"), Some(1));
    assert_eq!(parse_workspace_index("#2"), Some(2));
    assert_eq!(parse_workspace_index("0"), None);
    assert_eq!(parse_workspace_index("abc"), None);
}

#[test]
fn test_resolve_workspace_for_rm_by_index() {
    let records = vec![
        WorkspaceRecord {
            name: "alpha".to_string(),
            path: PathBuf::from("/tmp/alpha"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Local,
        },
        WorkspaceRecord {
            name: "codex/one".to_string(),
            path: PathBuf::from("/tmp/codex/one"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Linked,
        },
    ];

    let resolved = resolve_workspace_for_rm(&records, "2").expect("resolve by index");
    assert_eq!(resolved.index, 2);
    assert_eq!(resolved.record.name, "codex/one");
    assert_eq!(resolved.record.source, WorkspaceSource::Linked);
}

#[test]
fn test_resolve_workspace_for_rm_by_name() {
    let records = vec![
        WorkspaceRecord {
            name: "alpha".to_string(),
            path: PathBuf::from("/tmp/alpha"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Local,
        },
        WorkspaceRecord {
            name: "codex/one".to_string(),
            path: PathBuf::from("/tmp/codex/one"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Linked,
        },
    ];

    let resolved = resolve_workspace_for_rm(&records, "codex/one").expect("resolve by name");
    assert_eq!(resolved.index, 2);
    assert_eq!(resolved.record.path, PathBuf::from("/tmp/codex/one"));
}

#[test]
fn test_resolve_workspace_for_rm_rejects_ambiguous_name() {
    let records = vec![
        WorkspaceRecord {
            name: "same".to_string(),
            path: PathBuf::from("/tmp/one"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Local,
        },
        WorkspaceRecord {
            name: "same".to_string(),
            path: PathBuf::from("/tmp/two"),
            backend: WorkspaceBackend::Git,
            source: WorkspaceSource::Linked,
        },
    ];

    let err = resolve_workspace_for_rm(&records, "same").expect_err("ambiguous");
    assert!(err.to_string().contains("matches multiple workspaces"));
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
