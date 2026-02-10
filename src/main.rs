mod claude;
mod cli;
mod commands;
mod config;
mod constants;
mod git;
mod process;
mod shell;
mod ui;
mod workspace;
mod workspace_name;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config = config::Config::load()?;
    commands::run(cli.command, &config)
}

#[cfg(test)]
mod tests;
