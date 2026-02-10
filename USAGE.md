# USAGE

This file documents the standard day-to-day workflow for `sir`.

## Prerequisites

- `git` installed
- Claude CLI installed (`claude`)
- Run commands from a git repository root
- `sir` uses Claude model `sonnet` by default for `new` init and `settle` (override via `claude_model` in config)

## Standard Workflow

1. Run health checks once per repo (or whenever setup changes):

```bash
sir doctor
```

2. Create a workspace and launch your agent inside it:

```bash
sir new <agent_cmd...>
# or: sir n <agent_cmd...>
# optional explicit name:
sir new --name <name> <agent_cmd...>
# or: sir n -n <name> <agent_cmd...>
# optional base revision:
sir new --from <revision> <agent_cmd...>
```

Example:

```bash
sir new codex
sir n claude -p "add retries to rpc client"
sir new --name feature-auth codex
sir new --from main codex
```

What this does:
- Creates/uses `.worktrees/<name>`
- By default, asks Claude to generate `<name>` from your command and falls back to a generated two-word name (for example `pink elephant`) when Claude returns `null`
- `--name` / `-n` lets you set `<name>` explicitly
- `--from <revision>` sets the base revision for new workspace branch creation (default is `HEAD`)
- Creates/uses a `sir/*` branch derived from `<name>` (whitespace normalized for branch safety)
- Seeds new workspace with current uncommitted changes from the source repo
- Runs your agent command in that workspace through your `$SHELL`
- Leaves you in a workspace `$SHELL` prompt after the agent command exits

3. Do your implementation work in the workspace:

```bash
cd .worktrees/<name>
git status -sb
```

4. Check all workspaces from repo root:

```bash
sir status
# or: sir t
```

`sir status` includes both `repo/.worktrees/*` and other linked git worktrees for the same repo (such as external Codex worktrees).

JSON output:

```bash
sir status --json
```

5. Re-open a workspace shell later:

```bash
sir open <name>
```

6. Remove a workspace when you are done with it:

```bash
sir rm <name>
# remove all workspaces with no unstaged/untracked changes:
sir rm --all-clean
```

7. Integrate workspace changes back to `main`:

```bash
sir settle <name>
# optional additional prompt:
sir settle <name> --prompt "<additional instruction>"
```

If you are already inside a linked worktree (`.worktrees/<name>` or an external linked path like `~/.codex/worktrees/<id>/<repo>`), you can omit the name:

```bash
sir settle
# convenience form:
sir settle "<additional instruction>"
```

When `sir settle` is run from inside a linked worktree, it opens a shell at the repo root after settle completes.
When `sir settle "<additional instruction>"` is run inside a workspace, the quoted argument is passed to Claude as additional settle guidance (if it does not match an existing workspace name).

## Typical End-to-End Example

```bash
sir doctor
sir new -n bugfix-42 codex
# ...make changes in .worktrees/bugfix-42...
sir t
sir settle bugfix-42
```

## Development Commands (this repo)

Use `just` targets for local development:

```bash
just build
just test
just clippy
just fmt
just run -- --help
```
