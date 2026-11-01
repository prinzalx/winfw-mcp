// A portable tool is started by double-click, and a console window belonging to a tray icon is in
// the way. Debug builds keep the console, because that is where the log goes while it is developed.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod device;
mod export;
mod instance;
mod learn;
mod mcp;
mod monitor;
mod paths;
mod rules;
mod server;
mod store;
mod tray;
#[cfg(windows)]
mod wfp;

#[cfg(test)]
mod testutil;

use std::sync::Arc;

use anyhow::{Result, bail};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{Policy, Settings};
use crate::paths::DataPaths;
use crate::rules::RuleFile;

/// What the process should do with the live store.
///
/// The two one-shot operations are the two the web UI exposes as well; `Serve` is the mode the
/// tool is meant to run in, and it keeps the process alive instead of applying and exiting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// Push the loaded rules into the live store.
    #[default]
    Apply,
    /// Take our filters out of the live store again.
    Clear,
    /// Run the web server until the process is stopped.
    Serve,
}

impl Command {
    /// Parse the arguments. An unknown argument is an error rather than a shrug, so a mistyped
    /// flag cannot silently install filters the user did not ask for.
    fn parse(args: &[String]) -> Result<Self> {
        match args {
            [] => Ok(Self::default()),
            [flag] if flag == "--clear" => Ok(Self::Clear),
            [flag] if flag == "--serve" => Ok(Self::Serve),
            [flag] => bail!("unknown argument '{flag}'; expected --clear or --serve"),
            _ => bail!("too many arguments; expected at most one flag"),
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "winfw-mcp [ --serve | --clear ]\n\n    (no flag)  load the rules and install them in the live store\n    --serve   run the web server until stopped\n    --clear   remove our filters from the live store\n\nReading and writing the store needs elevation."
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

    // A named profile is an ordinary rule file under `profiles\`; an empty name means the rules
    // of `rules.toml` itself, which is what a fresh install has.
    let active_rules = match settings.active_profile.as_str() {
        "" => paths.rules.clone(),
        name => paths.profile_file(name),
    };
    let rules = RuleFile::load_or_create(&active_rules)?;

    init_tracing(&settings);

    info!(root = %paths.root.display(), "data directory ready");
    info!(
        config = %paths.config.display(),
        rules_file = %active_rules.display(),
        profile = %settings.active_profile,
        "files resolved",
    );
    info!(
        port = settings.port,
        learn_mode = settings.learn_mode,
        log_level = %settings.log_level,
        "settings loaded",
    );
    info!(count = rules.rule.len(), "rules loaded");

    if command == Command::Serve {
        return serve(paths, settings, rules, active_rules);
    }

    // A one-shot run has no live monitor, but the applications a previous `--serve` run saw are on
    // disk, and those are what a wildcard rule has to be expanded against.
    let known = match command {
        Command::Apply => learn::Detector::load(&paths.learn)
            .map(|detector| detector.apps())
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    sync_store(&rules, command, &known, settings.default_policy);

    Ok(())
}

/// Run the web server: the state is already loaded, so the first request sees the same rules the
/// process read at startup.
///
/// The store work happens on the WFP worker thread, which is the thread that opens the engine
/// handle, because a WFP transaction belongs to a thread rather than to a handle.
fn serve(
    paths: DataPaths,
    settings: Settings,
    rules: RuleFile,
    active_rules: std::path::PathBuf,
) -> Result<()> {
    let port = settings.port;
    let active_name = settings.active_profile.clone();

    // A second double-click must not mean a second server: two listeners, two tray icons and two
    // processes rebuilding the one live store. Whoever loses the name opens the browser on the
    // winner and is done, which is why this happens before a port is bound or the store is touched.
    let Some(guard) = instance::claim(&paths)? else {
        let url = instance::running_url(&paths.root.join(instance::PORT_FILE), port);

        info!(url = %url, "another instance is serving");

        tray::open_url(&url);

        return Ok(());
    };

    // The rules and the detected applications are shared between the request threads and the
    // monitor's callbacks, which is what the locks are for.
    let rules = Arc::new(std::sync::Mutex::new(rules));
    let detector = Arc::new(learn::Detector::load(&paths.learn)?);

    // The worker is started before the monitor so a callback can hand the store a rebuild when an
    // application turns up that no filter knows about yet.
    let worker = Arc::new(server::WfpWorker::start());

    // The monitor is started before the listener so the first page load already has a feed, even
    // if it is empty. It is held by this scope, which is what keeps the subscription open.
    // The two settings that may change while the server runs live here, so the monitor's callbacks
    // and `POST /api/settings` read and write the same pair.
    let live = Arc::new(server::Live::new(
        settings.learn_mode,
        settings.default_policy,
    ));

    let events = Arc::new(monitor::EventLog::new());
    let _monitor = monitor::Monitor::start(
        Arc::clone(&events),
        Arc::clone(&detector),
        Arc::clone(&rules),
        Arc::clone(&live),
        worker.handle(),
        worker.owners(),
    );

    // Our filters persist across runs, so without this the store would keep whatever the previous
    // run left in it: a rule edited while the tool was stopped, or an application that appeared
    // since, would not be reflected until the next write. A refused store is a supported state.
    let startup_rules = rules.lock().expect("rules lock poisoned").clone();
    match worker.ask(server::StoreWork::Apply {
        rules: startup_rules,
        known: detector.apps(),
        policy: settings.default_policy,
    }) {
        Ok(outcome) => {
            info!(store = %outcome.describe(), "store rebuilt from the rules at startup")
        }
        Err(error) => {
            warn!(reason = %format!("{error:#}"), "could not rebuild the store at startup")
        }
    }

    // Taken before `paths` moves into the state.
    let logfile = paths.logs.join("winfw-mcp.log");

    let state = server::AppState::new(
        paths,
        settings,
        rules,
        detector,
        events,
        live,
        active_rules,
        active_name,
    );
    // Taken before `state` moves into the server, because `Quit` on the tray has to reach the same
    // flag the routes set.
    let running = state.stop_handle();

    let server = server::Server::bind(port, state, Arc::clone(&worker))?;

    let url = format!("http://{}", server.addr());

    info!(url = %url, "web UI ready");

    // Recorded only now, because a busy port makes the server fall forward and the port is not
    // known until the listener exists. A second process reads it to open the right URL.
    guard.set_port(server.addr().port());

    // Held by this scope for as long as the server runs, which is what takes the icon out of the
    // notification area again when the process is asked to stop.
    let _tray = tray::Tray::start(url.clone(), running);

    let tray_status = if _tray.added() {
        "tray icon added"
    } else {
        warn!("tray icon skipped");

        "tray icon skipped"
    };

    // The release binary has no console, so the startup lines and the outcome of adding the icon
    // are appended to the log in the data dir as well.
    log(
        &logfile,
        &format!(
            "{} {} serving {url}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ),
    );
    log(&logfile, &tray_status);

    server.serve()
}

/// Appends a line to the log file. Failure to write it cannot be reported anywhere, so it is
/// ignored.
fn log(path: &std::path::Path, message: &str) {
    use std::io::Write;

    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(&mut file, "{message}");
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
fn sync_store(rules: &RuleFile, command: Command, known: &[String], policy: Policy) {
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
        Command::Apply => engine.apply(rules, known, policy).map(|applied| {
            info!(
                removed = applied.removed,
                installed = applied.installed,
                "rules applied to WFP",
            );
        }),
        Command::Clear => engine.clear().map(|removed| {
            info!(removed, "our filters removed from WFP");
        }),
        // `serve` returns before `sync_store` is reached, so this only keeps the match honest.
        Command::Serve => Ok(()),
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
fn sync_store(_rules: &RuleFile, _command: Command, _known: &[String], _policy: Policy) {}

/// Logging goes to stderr: stdout belongs to the MCP stdio transport.
fn init_tracing(settings: &Settings) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
