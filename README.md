# sir

Minimal workspace wrapper for `git worktree` + Claude CLI in a raw terminal workflow.

## What It Does

- Creates isolated workspaces under `repo/.worktrees/<name>/`
- Uses `git worktree` as the only backend
- Delegates initialization copy and settle/integration to Claude CLI with `--dangerously-skip-permissions`
- Uses Claude model `sonnet` by default for internal Claude tasks (`new` init + `settle`)
- Enables Claude streaming output (`stream-json` + partial messages) and renders text deltas live
- Runs agent commands directly in your current terminal

## Requirements

- `git`
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
claude_bin = "claude"
claude_model = "sonnet"
```

Example:

```toml
claude_bin = "claude"
claude_model = "sonnet"
```

## Commands

### `sir doctor`

Runs sanity checks and prints explicit remediation commands.

Checks include:

- inside a git repo
- `.worktrees/` exists (creates it if missing)
- `.worktrees/` is gitignored
- `git worktree` support (`git worktree list`)
- Claude CLI installed

### `sir new <name> <agent_cmd...>` (alias: `sir n`)

Creates/opens a workspace and then runs your agent command in that workspace in the current terminal.

Behavior:

- Ensures `.worktrees/`
- Creates new worktrees from `HEAD`
- Creates a worktree branch named `sir/<name>`:
  - if branch exists: `git worktree add repo/.worktrees/<name> sir/<name>`
  - else: `git worktree add -b sir/<name> repo/.worktrees/<name> HEAD`
- Newly created worktrees are seeded with current uncommitted changes from the source repo by default
  - applies tracked staged/unstaged diff from `HEAD`
  - copies untracked files (excluding ignored files)
  - if workspace already exists, seeding is skipped
- If an existing workspace looks incomplete or not git-backed, `sir` auto-recreates it before running the agent command
- Runs Claude init prompt from repo root to copy:
  - `.env` (if present, non-destructive)
  - `target/` (if present)
  - `node_modules/` (if present)
  - no symlinks
  - uses `--model sonnet` by default (configurable via `claude_model`)
- Runs `<agent_cmd...>` through `/bin/zsh` with cwd set to the workspace
- After the agent command exits, leaves you in an interactive `/bin/zsh` in that workspace

Examples:

```bash
sir new foo codex
sir n feature-a claude -p "fix failing tests"
```

### `sir status [--json]` (alias: `sir t`)

Stateless workspace listing from `.worktrees/` (excluding `_logs`, `_tmp`).

For each workspace, prints:

- name
- backend detection (`git` or `unknown`)
- status summary (`git status -sb`)

Examples:

```bash
sir status
sir t --json
```

### `sir open <name>`

Opens an interactive shell in workspace `<name>`.

In non-interactive environments, it prints the workspace path instead of launching a shell.

Example:

```bash
sir open foo
```

### `sir rm <name>`

Removes workspace `<name>`.

Behavior:

- resolves `repo/.worktrees/<name>`
- removes git-backed workspaces with `git worktree remove --force`
- if the workspace is non-git leftovers, deletes the directory directly

Example:

```bash
sir rm foo
```

### `sir settle [<name>]` (alias: `sir s`)

Delegates integration of a workspace back to `main` to Claude.

Behavior:

- Workspace resolution:
  - provided name: `repo/.worktrees/<name>`
  - omitted name: inferred from current directory when inside `.worktrees/<name>`
- Runs Claude in workspace with `--dangerously-skip-permissions`
- Uses `--model sonnet` by default (configurable via `claude_model`)
- Prompt instructs Claude to:
  - inspect status/diff/log with git
  - produce clean commit(s) and strong commit messages
  - integrate/rebase/merge onto latest `main`
  - resolve conflicts
  - update `.env` when example env files changed (without overwriting secrets)
- After Claude returns, prints post-check:
  - `git status -sb` at repo root

Examples:

```bash
sir settle foo
cd .worktrees/foo && sir settle
```

## Notes

- Workspace names cannot contain path separators and cannot be `_logs` or `_tmp`.
- `sir` is git-only.

## Development

Using `just`:

```bash
just build
just test
just clippy
just fmt
just run -- --help
```
