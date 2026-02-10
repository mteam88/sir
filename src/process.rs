use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

pub(crate) fn binary_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub(crate) struct CmdOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn run_capture(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<CmdOutput> {
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

pub(crate) fn run_capture_with_input(
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

pub(crate) fn run_stream(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<()> {
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

pub(crate) fn print_command_output(command: &str, stdout: &str, stderr: &str) {
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

pub(crate) fn first_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("unknown error")
        .to_string()
}

pub(crate) fn best_error_line(stderr: &str) -> String {
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

pub(crate) fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}
