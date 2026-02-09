# sir — Minimal plan (zellij + jj + Claude)

This document is the implementation plan/spec for the `sir` CLI. It is intentionally small and “wrapper-y”.

## 0) Scope

### What `sir` does
- Creates/opens isolated workspaces under `repo/.worktrees/<name>/`.
- Uses **jj workspaces** as the default backend.
- Uses **zellij** as the session manager.
- Uses **Claude CLI** for initialization copy and settle/merge, with Claude allowed to run commands itself via `--dangerously-skip-permissions`.

### What `sir` does not do
- No fine-grained controls for what gets copied or how.
- No per-project config.
- No command allowlists / stepwise execution loops.
- No background daemons.

---

## 1) Conventions

### Directory layout (per repo, gitignored)
In repo root:
- `.worktrees/` (gitignored)
  - `<name>/` workspace directory created by jj
  - `_logs/` optional logs (not required)
  - `_tmp/` optional scratch (avoid if possible)

### Zellij
- One session per repo: `sir-<repo_basename>`
- One tab per workspace: `<name>`
- Tab runs the agent command in that workspace (cwd = workspace path)

---

## 2) Global config (single file, simple)

No per-project config. One global config file:

- `~/.config/sir/config.toml` (or `~/.sir.toml`)

Minimal fields only:

```toml
backend = "jj"            # "jj" | "git" (future)
zellij_session_prefix = "sir"
claude_bin = "claude"
```

Defaults if missing:
- `backend = "jj"`
- `zellij_session_prefix = "sir"`
- `claude_bin = "claude"`

---

## 3) CLI commands

### `sir doctor`
Fast sanity check and printed remediation steps.

Checks:
- inside a git repo (repo root via `git rev-parse --show-toplevel`)
- `.worktrees/` exists and is gitignored
  - if missing: create it and print “add to .gitignore” guidance
- `jj` installed (if backend is `jj`)
- repo is jj-colocated (best effort check)
  - if not: print `jj git init --colocate`
- `zellij` installed
- `claude` installed and callable
- optional: detect if currently inside zellij (`$ZELLIJ`) and print small UX hints

Output: short checklist with OK/FAIL and exact commands to fix failures.

---

### `sir spawn <name> <agent_cmd...>`
Creates workspace and starts agent in zellij.

Behavior:
1) Resolve repo root.
2) Ensure `.worktrees/` exists (create if needed).
3) Workspace path: `repo/.worktrees/<name>/`.
4) Backend create:
   - JJ: `jj workspace add --name <name> -r main <path>`
5) Initialization copy via Claude (Claude runs commands itself):
   - run from repo root, pass target workspace path
   - prompt instructs Claude to:
     - copy `.env` into workspace if present
     - copy `target/` and `node_modules/` into workspace if present
     - use copy-on-write when possible (macOS `cp -c`), otherwise plain copy
     - never symlink
     - be conservative (avoid overwriting existing workspace `.env` unless missing)
6) Create/attach zellij session for this repo (name = `sir-<repo_basename>`).
7) Create a new tab named `<name>` and run `<agent_cmd...>` with cwd set to the workspace path.

Idempotency:
- If workspace exists, do not recreate; re-run init copy and (re)open/focus tab.
- If tab exists, focus it.

---

### `sir status [--json]`
Stateless listing.

Discovery:
- list directories under `.worktrees/` excluding `_logs`, `_tmp`.

For each `<name>`:
- determine backend:
  - if `.jj/` exists in workspace → jj
  - else if looks like git worktree → git (future)
- show:
  - name
  - backend
  - status summary:
    - jj: `jj st` (in that workspace dir)
    - git (future): `git status -sb`
  - zellij session exists? (yes/no)
  - tab exists? best effort; if zellij doesn’t expose tab listing reliably, show session only

Output:
- human table by default
- `--json` returns structured list for scripting

---

### `sir open <name>`
Focus zellij tab for `<name>` in the repo session, creating it if missing.

---

### `sir settle [<name>]`
Integrates a workspace back to `main` using Claude (fully delegated).

Behavior:
1) Resolve repo root.
2) Determine workspace path:
   - if `<name>` provided: `repo/.worktrees/<name>`
   - else: infer from current directory (must be inside `.worktrees/<name>`), otherwise error
3) Run Claude in the workspace directory with:
   - `--dangerously-skip-permissions`

Prompt requirements (Claude performs):
- inspect changes (jj status/diff/log)
- ensure changes are in a clean commit (or small commit stack) with a good commit message
- rebase/merge onto latest `main` and resolve conflicts
- integrate onto `main` in the colocated repo (or via jj primitives)
- update `.env` if `.env.example` (or similar) changed:
  - detect likely “example env” files automatically and apply new keys/defaults into `.env` without overwriting secrets
- leave repo in a sensible state: changes applied to `main` and workspace updated accordingly

After Claude returns, `sir` prints:
- Claude output
- a brief post-check:
  - `git status -sb` in repo root
  - optionally `jj st` in main workspace (if you treat repo root as “main” workspace)

No loops, no manual command orchestration.

---

## 4) Prompts (two small templates)

Store prompt templates in-binary (string literals) or as a single global template file (optional). Keep short, directive, backend-aware.

### Spawn init prompt (jj)
Key points:
- “You are in repo root. Copy into <workspace_path>.”
- “Use `cp -c` on macOS; otherwise `cp -R`.”
- “Copy `.env` if present; copy `target/` and `node_modules/` if present.”
- “Never symlink.”
- “Don’t ask questions; just do it.”

### Settle prompt (jj)
Key points:
- “You are in workspace <name>. Integrate into main.”
- “Use jj commands; repo is colocated with git.”
- “Resolve conflicts.”
- “Write an excellent commit message based on diff.”
- “If `.env.example` (or similar) changed, update `.env` accordingly.”

---

## 5) JJ backend minimalism (don’t overfit)

`sir` itself uses jj for only:
- `jj workspace add ...` (spawn)
- `jj st` (status)

Everything else (rebasing, squashing, conflict resolution, final integration) is delegated to Claude during `settle`.

This keeps coupling low and makes a later git-worktree backend basically:
- change spawn to `git worktree add ...`
- change status to `git status`
- adjust prompt templates to use git commands

---

## 6) Implementation notes (tiny, practical)

- Language: Rust or Go.
- Use simple process execution; stream stdout/stderr.
- Avoid maintaining any registry file. All discovery is filesystem + zellij presence.
- Repo-root detection: `git rev-parse --show-toplevel`.
- zellij: best-effort commands; keep `sir status` conservative if tab introspection is limited.
- For UX: if `$ZELLIJ` is set, create tabs; otherwise attach/create the repo session.

---

## 7) Acceptance criteria (v1)

1) `sir doctor` produces actionable output on a fresh repo.
2) `sir spawn foo codex`:
   - creates `.worktrees/foo`
   - initializes jj workspace
   - Claude copies `.env`, `target/`, `node_modules/` into workspace (no symlinks)
   - opens zellij session/tab and runs `codex` in that dir
3) `sir status` lists `foo` and shows jj status
4) `sir settle foo` results in:
   - changes integrated into `main`
   - a clean commit message generated
   - `.env` updated when example env changes
