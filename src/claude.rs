use crate::config::Config;
use crate::process::{best_error_line, run_capture};
use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn auto_name_prompt(agent_command: &str) -> String {
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

pub(crate) fn run_claude_text(config: &Config, prompt: &str, cwd: &Path) -> Result<String> {
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

pub(crate) fn build_claude_text_args(prompt: &str, model: &str) -> Vec<String> {
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

pub(crate) fn parse_auto_name_response(raw: &str) -> Option<String> {
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

pub(crate) fn normalize_auto_name_candidate(candidate: &str) -> Option<String> {
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

pub(crate) fn new_init_prompt(workspace_path: &Path) -> String {
    format!(
        "You are in the repo root. Copy initialization data into workspace at:\n{}\n\nRequirements:\n- Copy .env into the workspace if present, but do not overwrite workspace .env if it already exists.\n- Copy target/ into the workspace if present.\n- Copy node_modules/ into the workspace if present.\n- Use copy-on-write on macOS when possible (cp -c). Otherwise use plain recursive copy (cp -R).\n- Never create symlinks.\n- Be conservative and avoid destructive actions.\n- Do not ask questions; execute directly and report what you did.",
        workspace_path.display()
    )
}

pub(crate) fn settle_prompt(
    name: &str,
    workspace_path: &Path,
    additional_prompt: Option<&str>,
) -> String {
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

pub(crate) fn run_claude(config: &Config, prompt: &str, cwd: &Path) -> Result<()> {
    let args = build_claude_args(prompt, &config.claude_model);
    run_claude_stream(&config.claude_bin, &args, Some(cwd))
        .with_context(|| format!("failed while running `{}`", config.claude_bin))
}

pub(crate) fn build_claude_args(prompt: &str, model: &str) -> Vec<String> {
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
pub(crate) enum ClaudeStreamLine {
    TextDelta(String),
    Error(String),
    OtherJson,
    NonJson(String),
}

pub(crate) fn parse_claude_stream_line(line: &str) -> ClaudeStreamLine {
    let parsed = match serde_json::from_str::<serde_json::Value>(line) {
        Ok(value) => value,
        Err(_) => return ClaudeStreamLine::NonJson(line.to_string()),
    };

    if parsed.get("type").and_then(serde_json::Value::as_str) == Some("stream_event")
        && parsed
            .pointer("/event/delta/type")
            .and_then(serde_json::Value::as_str)
            == Some("text_delta")
        && let Some(text) = parsed
            .pointer("/event/delta/text")
            .and_then(serde_json::Value::as_str)
    {
        return ClaudeStreamLine::TextDelta(text.to_string());
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

pub(crate) fn ensure_claude_streaming_args(args: &[String]) -> Vec<String> {
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

pub(crate) fn claude_output_format(args: &[String]) -> Option<String> {
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
