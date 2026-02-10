use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "sir",
    version,
    about = "Small workspace wrapper for git worktrees + Claude in the raw terminal"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run sanity checks and print remediation commands.
    Doctor,
    /// Create/open a workspace and run an agent command in the current terminal.
    #[command(alias = "n")]
    New {
        /// Optional explicit workspace name. If omitted, name is generated automatically.
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Base revision used when creating a new workspace branch.
        #[arg(long)]
        from: Option<String>,
        /// Agent command to run in the workspace.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show discovered workspaces and status.
    #[command(alias = "t")]
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Open an interactive shell in the workspace.
    Open { name: String },
    /// Remove a workspace by name, or remove all clean workspaces.
    Rm {
        /// Workspace name or status index. Omit when using `--all-clean`.
        name: Option<String>,
        /// Remove all workspaces that have no unstaged or untracked changes.
        #[arg(long)]
        all_clean: bool,
    },
    /// Let Claude integrate a workspace back to main.
    #[command(alias = "s")]
    Settle {
        /// Optional workspace name. If omitted, inferred from cwd when inside a linked git worktree.
        name: Option<String>,
        /// Extra instructions appended to the settle Claude prompt.
        #[arg(short = 'p', long = "prompt")]
        prompt: Option<String>,
    },
}

#[derive(Debug)]
pub(crate) struct ParsedNewCommand {
    pub(crate) name: Option<String>,
    pub(crate) from: Option<String>,
    pub(crate) agent_cmd: Vec<String>,
}

pub(crate) fn parse_new_command_args(
    name: Option<String>,
    from: Option<String>,
    args: Vec<String>,
) -> Result<ParsedNewCommand> {
    if args.is_empty() {
        bail!("agent command must not be empty");
    }

    if let Some(name) = name {
        return Ok(ParsedNewCommand {
            name: Some(name),
            from,
            agent_cmd: args,
        });
    }

    Ok(ParsedNewCommand {
        name: None,
        from,
        agent_cmd: args,
    })
}
