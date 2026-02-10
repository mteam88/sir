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
sir new <name> <agent_cmd...>
# or: sir n <name> <agent_cmd...>
```

Example:

```bash
sir new feature-auth codex
```

What this does:
- Creates/uses `.worktrees/<name>`
- Creates/uses branch `sir/<name>`
- Seeds new workspace with current uncommitted changes from the source repo
- Runs your agent command in that workspace through `/bin/zsh`
- Leaves you in a workspace `/bin/zsh` prompt after the agent command exits

3. Do your implementation work in the workspace:

```bash
cd .worktrees/<name>
git status -sb
```

4. Check all workspaces from repo root:

```bash
sir status
# or: sir s
```

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
```

7. Integrate workspace changes back to `main`:

```bash
sir settle <name>
```

If you are already inside `.worktrees/<name>`, you can omit the name:

```bash
sir settle
```

## Typical End-to-End Example

```bash
sir doctor
sir new bugfix-42 codex
# ...make changes in .worktrees/bugfix-42...
sir s
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
