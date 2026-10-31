mod config;
mod paths;
mod rules;
mod store;
#[cfg(windows)]
mod wfp;

#[cfg(test)]
mod testutil;

use anyhow::{Result, bail};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Settings;
use crate::paths::DataPaths;
use crate::rules::RuleFile;

/// What the process should do with the live store.
///
/// This is deliberately the whole user interface until milestone 4 puts the web server in front of
/// it, but the two operations are the two the web UI will expose first as well.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// Push the loaded rules into the live store.
    #[default]
    Apply,
    /// Take our filters out of the live store again.
    Clear,
}

impl Command {
    /// Parse the arguments. An unknown argument is an error rather than a shrug, so a mistyped
    /// flag cannot silently install filters the user did not ask for.
    fn parse(args: &[String]) -> Result<Self> {
        match args {
            [] => Ok(Self::default()),
            [flag] if flag == "--clear" => Ok(Self::Clear),
            [flag] => bail!("unknown argument '{flag}'; expected --clear"),
            _ => bail!("too many arguments; expected at most one flag"),
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "winfw-mcp [ --clear ]\n\n    (no flag)  load the rules and install them in the live store\n    --clear   remove our filters from the live store\n\nReading and writing the store needs elevation."
        );
        return Ok(());
    }

    let command = Command::parse(&args)?;

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

    sync_store(&rules, command);

    Ok(())
}

/// Report what the live store holds, then carry out the command on it.
///
/// One engine handle serves both, because the handle is process-wide and a write has to be in
/// the same session as the reads around it.
///
/// Both halves degrade to a warning rather than a failed start. Reading and writing the store
/// need elevation, so an ordinary double-click on the executable reports the store as unreadable
/// and leaves the filters untouched; the web UI will show that state instead of an empty list.
#[cfg(windows)]
fn sync_store(rules: &RuleFile, command: Command) {
    let engine = match wfp::Engine::open() {
        Ok(engine) => engine,
        Err(error) => {
            warn!(reason = %format!("{error:#}"), "WFP unavailable");
            return;
        }
    };

    let inventory = engine.inventory();
    report("providers", &inventory.providers);
    report("sublayers", &inventory.sublayers);
    report("filters", &inventory.filters);

    let outcome = match command {
        Command::Apply => engine.apply(rules).map(|applied| {
            info!(
                removed = applied.removed,
                installed = applied.installed,
                "rules applied to WFP",
            );
        }),
        Command::Clear => engine.clear().map(|removed| {
            info!(removed, "our filters removed from WFP");
        }),
    };

    if let Err(error) = outcome {
        warn!(reason = %format!("{error:#}"), "WFP write refused");
    }
}

/// WFP grants read access per class, which is why one class failing says nothing about the others.
#[cfg(windows)]
fn report(category: &str, entries: &wfp::Entries) {
    match entries {
        Ok(names) => {
            info!(count = names.len(), category, "WFP store read");

            for name in names {
                debug!(category, entry = %name, "WFP entry");
            }
        }
        Err(error) => warn!(category, reason = %format!("{error:#}"), "WFP store unreadable"),
    }
}

/// The non-Windows variant exists only so the crate still builds for a doc tool.
#[cfg(not(windows))]
fn sync_store(_rules: &RuleFile, _command: Command) {}

/// Logging goes to stderr: stdout belongs to the MCP stdio transport.
fn init_tracing(settings: &Settings) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
