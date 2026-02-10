# sir — Minimal plan (git + Claude)

This document is a compact implementation plan/spec for the `sir` CLI.

## 0) Scope

### What `sir` does
- Creates/opens isolated workspaces under `repo/.worktrees/<name>/`.
- Uses `git worktree` as the backend.
- Uses Claude CLI for initialization copy and settle/merge, with Claude allowed to run commands via `--dangerously-skip-permissions`.

### What `sir` does not do
- No zellij/session management.
- No per-project config.
- No background daemons.

## 1) Conventions

### Directory layout (per repo, gitignored)
In repo root:
- `.worktrees/`
  - `<name>/` workspace directory created by `git worktree`
  - `_logs/` optional logs
  - `_tmp/` optional scratch

## 2) Global config

One global config file:
- `~/.config/sir/config.toml` (or `~/.sir.toml`)

Minimal fields:

```toml
claude_bin = "claude"
```

Defaults if missing:
- `claude_bin = "claude"`

## 3) CLI commands

### `sir doctor`
Checks:
- inside a git repo
- `.worktrees/` exists and is gitignored
- `git worktree` support (`git worktree list`)
- `claude` installed and callable

### `sir new <name> <agent_cmd...>`
Behavior:
1. Resolve repo root.
2. Ensure `.worktrees/` exists.
3. Workspace path: `repo/.worktrees/<name>/`.
4. Create worktree:
   - Resolve revision in order: `main`, current branch, `master`, `HEAD`.
   - Branch name: `sir/<name>`.
   - If branch exists: `git worktree add <path> sir/<name>`.
   - Else: `git worktree add -b sir/<name> <path> <revision>`.
5. Initialization copy via Claude from repo root:
   - copy `.env` if present (non-destructive)
   - copy `target/` and `node_modules/` if present
   - avoid symlinks
6. Run `<agent_cmd...>` in workspace cwd.

### `sir status [--json]`
Discovery:
- list directories under `.worktrees/` excluding `_logs`, `_tmp`

For each workspace:
- backend: `git` if `.git` exists, else `unknown`
- status summary: `git status -sb`

### `sir open <name>`
Open an interactive shell in the workspace (or print path in non-interactive mode).

### `sir rm <name>`
Behavior:
1. Resolve repo root.
2. Resolve workspace path `repo/.worktrees/<name>`.
3. Remove with `git worktree remove --force`.
4. If workspace is non-git leftovers, remove directory directly.

### `sir settle [<name>]`
Behavior:
1. Resolve repo root.
2. Resolve workspace path from `<name>` or current cwd.
3. Run Claude in workspace with `--dangerously-skip-permissions`.
4. Prompt Claude to:
   - inspect with git status/diff/log
   - produce clean commit(s) and strong messages
   - rebase/merge onto latest `main` and resolve conflicts
   - update `.env` from changed example env files without overwriting secrets
5. Post-check: print `git status -sb` in repo root.

## 4) Acceptance criteria

1. `sir doctor` produces actionable output on a fresh repo.
2. `sir new foo codex` creates `.worktrees/foo` as a git worktree and runs `codex` there.
3. `sir status` lists `foo` and shows git status.
4. `sir settle foo` integrates changes into `main` with a clean history.
