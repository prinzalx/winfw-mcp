mod config;
mod paths;
mod rules;
mod store;

#[cfg(test)]
mod testutil;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Settings;
use crate::paths::DataPaths;
use crate::rules::RuleFile;

fn main() -> Result<()> {
    // Everything the tool owns lives under one directory, resolved before anything else reads
    // or writes a file.
    let paths = DataPaths::resolve()?;
    paths.ensure()?;

    // All state is read here, once. Later milestones keep the in-memory copy authoritative and
    // write every change straight back (PLAN.md section 2).
    let settings = Settings::load_or_create(&paths.config)?;
    let rules = RuleFile::load_or_create(&paths.rules)?;

    init_tracing(&settings);

    info!(root = %paths.root.display(), "data directory ready");
    info!(
        config = %paths.config.display(),
        rules_file = %paths.rules.display(),
        "files resolved",
    );
    info!(
        port = settings.port,
        learn_mode = settings.learn_mode,
        log_level = %settings.log_level,
        "settings loaded",
    );
    info!(count = rules.rule.len(), "rules loaded");

    Ok(())
}

/// Logging goes to stderr: stdout belongs to the MCP stdio transport.
fn init_tracing(settings: &Settings) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
