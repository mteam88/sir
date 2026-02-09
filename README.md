# sir

Minimal workspace wrapper for `jj` + Claude CLI in a raw terminal workflow.

## What It Does

- Creates isolated workspaces under `repo/.worktrees/<name>/`
- Uses `jj workspace add` as the backend (default)
- Delegates initialization copy and settle/integration to Claude CLI with `--dangerously-skip-permissions`
- Runs agent commands directly in your current terminal (no zellij session management)

## Requirements

- `git`
- `jj` (if using `backend = "jj"`)
- Claude CLI (`claude`)

## Install

Build:

```bash
cargo build --release
```

Run from repo root:

```bash
./target/release/sir --help
```

Or install globally:

```bash
cargo install --path .
```

## Configuration

Config file lookup order:

1. `~/.config/sir/config.toml`
2. `~/.sir.toml`

Defaults:

```toml
backend = "jj"
claude_bin = "claude"
```

Example:

```toml
backend = "jj"
claude_bin = "claude"
```

## Commands

### `sir doctor`

Runs sanity checks and prints explicit remediation commands.

Checks include:

- inside a git repo
- `.worktrees/` exists (creates it if missing)
- `.worktrees/` is gitignored
- `jj` installed and workspace metadata available (for `backend = "jj"`)
- Claude CLI installed

### `sir spawn <name> <agent_cmd...>`

Creates/opens a workspace and then runs your agent command in that workspace in the current terminal.

Behavior:

- Ensures `.worktrees/`
- Creates workspace with:
  - `jj workspace add --name <name> -r main repo/.worktrees/<name>`
- Runs Claude init prompt from repo root to copy:
  - `.env` (if present, non-destructive)
  - `target/` (if present)
  - `node_modules/` (if present)
  - no symlinks
- Runs `<agent_cmd...>` with cwd set to the workspace

Examples:

```bash
sir spawn foo codex
sir spawn feature-a claude -p "fix failing tests"
```

### `sir status [--json]`

Stateless workspace listing from `.worktrees/` (excluding `_logs`, `_tmp`).

For each workspace, prints:

- name
- backend detection (`jj`, `git`, `unknown`)
- status summary (`jj st` or `git status -sb`)

Examples:

```bash
sir status
sir status --json
```

### `sir open <name>`

Opens an interactive shell in workspace `<name>`.

In non-interactive environments, it prints the workspace path instead of launching a shell.

Example:

```bash
sir open foo
```

### `sir settle [<name>]`

Delegates integration of a workspace back to `main` to Claude.

Behavior:

- Workspace resolution:
  - provided name: `repo/.worktrees/<name>`
  - omitted name: inferred from current directory when inside `.worktrees/<name>`
- Runs Claude in workspace with `--dangerously-skip-permissions`
- Prompt instructs Claude to:
  - inspect status/diff/log
  - produce clean commit(s) and strong commit messages
  - integrate/rebase onto latest `main`
  - resolve conflicts
  - update `.env` when example env files changed (without overwriting secrets)
- After Claude returns, prints post-checks:
  - `git status -sb` at repo root
  - `jj st` at repo root (best effort)

Examples:

```bash
sir settle foo
cd .worktrees/foo && sir settle
```

## Notes

- Workspace names cannot contain path separators and cannot be `_logs` or `_tmp`.
- `backend = "git"` is reserved for future backend support; current implementation only provisions spawn with `jj`.

## Development

Using `just`:

```bash
just build
just test
just clippy
just fmt
just run -- --help
```
