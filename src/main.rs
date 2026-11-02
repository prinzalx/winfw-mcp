// A portable tool is started by double-click, and a console window belonging to a tray icon is in
// the way. Debug builds keep the console, because that is where the log goes while it is developed.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod device;
mod export;
mod instance;
mod learn;
mod log;
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
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
            [flag] => bail!("unknown argument '{flag}'; expected --clear or --serve (see --help)"),
            _ => bail!("too many arguments; expected at most one flag"),
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "winfw-mcp [ --serve | --clear ]\n\n    (no flag)      load the rules and install them in the live store\n    --serve        run the web server until the process is stopped\n    --clear        remove our filters from the live store\n    --help, -h     show this text\n    --version, -V  print the version\n\nReading and writing the store needs elevation."
        );

        return Ok(());
    }

    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("winfw-mcp {}", env!("CARGO_PKG_VERSION"));

        return Ok(());
    }

    let command = Command::parse(&args)?;

    // Everything the tool owns lives under one directory, resolved before anything else reads
    // or writes a file.
    let paths = DataPaths::resolve()?;
    paths.ensure()?;

    // Resolved before the subscriber, because the subscriber is what writes the file, and a
    // release build has no console: this file is the only place its lines survive.
    let logfile = paths.logs.join("winfw-mcp.log");

    // All state is read here, once. Later milestones keep the in-memory copy authoritative and
    // write every change straight back (PLAN.md section 2).
    let settings = Settings::load_or_create(&paths.config)?;

    // A named profile is an ordinary rule file under `profiles\`; an empty name means the rules
    // of `rules.toml` itself, which is what a fresh install has.
    let active_rules = match settings.active_profile.as_str() {
        "" => paths.rules.clone(),
        name => paths.profile_file(name),
    };
    // A rule file that does not exist yet is created with the two example rules, so the first
    // screen shows what a rule looks like instead of an empty table. A file a person has emptied
    // on purpose is not touched again, because it exists by then.
    let rules = if active_rules.is_file() {
        RuleFile::load_or_create(&active_rules)?
    } else {
        let examples = RuleFile::examples();
        examples.save(&active_rules)?;

        examples
    };

    let log_filter = init_tracing(&settings, &logfile);

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
        return serve(paths, settings, rules, active_rules, log_filter);
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
    log_filter: Option<LogFilterHandle>,
) -> Result<()> {
    let port = settings.port;
    let active_name = settings.active_profile.clone();

    // The secret a writing request has to carry. Generated here rather than read from a file, so a
    // page that is not ours cannot guess it (PLAN.md section 11).
    let token = server::session_token();

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
    // application turns up that no filter knows about yet. It is started after `live` because it is
    // the thread that honours the protection switch, and it has to see the same flag the routes
    // write.
    let live = Arc::new(server::Live::new(
        settings.learn_mode,
        settings.default_policy,
        settings.theme,
    ));
    let worker = Arc::new(server::WfpWorker::start(Arc::clone(&live)));

    // Captured before `settings` moves into the state: a volatile run takes its filters out
    // again when the server stops.
    let volatile = settings.volatile_filters;

    // The monitor is started before the listener so the first page load already has a feed, even
    // if it is empty. It is held by this scope, which is what keeps the subscription open.
    let events = Arc::new(monitor::EventLog::new());
    let _monitor = monitor::Monitor::start(
        Arc::clone(&events),
        Arc::clone(&detector),
        Arc::clone(&rules),
        Arc::clone(&live),
        worker.handle(),
        worker.owners(),
        settings.debug_show_loopback,
    );

    // Our filters persist across runs, so without this the store would keep whatever the previous
    // run left in it: a rule edited while the tool was stopped, or an application that appeared
    // since, would not be reflected until the next write. A refused store is a supported state.
    let startup_rules = rules.lock().expect("rules lock poisoned").clone();
    let startup = match worker.ask(server::StoreWork::Apply {
        rules: startup_rules,
        known: detector.apps(),
        policy: settings.default_policy,
    }) {
        Ok(outcome) => {
            info!(store = %outcome.describe(), "store rebuilt from the rules at startup");

            server::Startup::from_outcome(&outcome)
        }
        Err(error) => {
            let reason = format!("{error:#}");

            warn!(reason = %reason, "could not rebuild the store at startup");

            server::Startup::refused(reason)
        }
    };

    // What the file held when the tool last wrote it, which is the comparison the banner on the
    // page is drawn from. A missing stamp is a first run and has nothing to compare against.
    let rules_written =
        rules::read_stamp(&active_rules).or(rules::Fingerprint::of_file(&active_rules)?);

    let state = server::AppState::new(
        paths,
        settings,
        rules,
        detector,
        events,
        Arc::clone(&live),
        active_rules,
        active_name,
        startup,
        token.clone(),
        rules_written,
        log_filter,
    );
    // Taken before `state` moves into the server, because `Quit` on the tray has to reach the same
    // flag the routes set.
    let running = state.stop_handle();

    let server = server::Server::bind(port, state, Arc::clone(&worker))?;

    // The token rides in the URL the tray opens, which is the only way it reaches the browser
    // without ever being written to a file. A second instance opens the plain URL and the page
    // reads the token out of the first state body instead.
    let url = format!("http://{}", server.addr());
    let tray_url = format!("{url}/?token={token}");

    info!(url = %url, version = %env!("CARGO_PKG_VERSION"), "web UI ready");

    // Recorded only now, because a busy port makes the server fall forward and the port is not
    // known until the listener exists. A second process reads it to open the right URL.
    guard.set_port(server.addr().port());

    // Held by this scope for as long as the server runs, which is what takes the icon out of the
    // notification area again when the process is asked to stop.
    let _tray = tray::Tray::start(tray_url, running, Arc::clone(&live));

    if _tray.added() {
        info!("tray icon added");
    } else {
        warn!("tray icon skipped");
    }

    let outcome = server.serve();

    // A volatile run is a firewall only while the process runs: the filters go out with it, which
    // is the one difference from the persistent default. A killed process never gets here, and the
    // startup cleanup of the next run is what finds the leftovers then.
    if volatile {
        match worker.ask(server::StoreWork::Clear) {
            Ok(answer) => info!(
                store = answer.describe(),
                "volatile run: the filters went with the server"
            ),
            Err(error) => {
                warn!(reason = %format!("{error:#}"), "volatile run could not clear the store")
            }
        }
    }

    outcome
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
    let engine = match wfp::Engine::open_retrying() {
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

/// The filter `tracing` installed at startup, wrapped so a settings change can replace it.
///
/// The handle that may swap the filter `tracing` installed at startup, which is what makes
/// `log_level` a setting a running process honours. `tracing_subscriber::reload` is the type that
/// does this without a global of our own; the name `Registry` in it says what the layer is mounted
/// on, not that the server keeps a registry of its own.
pub type LogFilterHandle =
    tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>;

/// Logging goes to the log file in the data dir and to stderr: stdout belongs to the MCP stdio
/// transport.
///
/// A log file that will not open is reported on the console and the run continues with the console
/// alone. Refusing to start a firewall over a log would be the wrong way round.
///
/// The handle is what makes `log_level` changeable without a restart, and it is handed to the
/// caller rather than kept here because the state is the only place a request handler can reach.
/// `None` means no filter can be swapped, which is the case the tests run in: they never install a
/// subscriber, so there is nothing to reload.
fn init_tracing(settings: &Settings, logfile: &std::path::Path) -> Option<LogFilterHandle> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.log_level));

    let (reload, handle) = tracing_subscriber::reload::Layer::new(filter);

    match log::LogFile::open(logfile) {
        Ok(log) => {
            tracing_subscriber::registry()
                .with(reload)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(log)
                        // The same lines go to both halves of the tee, and escape codes in the file
                        // would be read by whoever opens it in an editor later.
                        .with_ansi(false),
                )
                .init();
        }
        Err(error) => {
            eprintln!("could not open {} for writing: {error}", logfile.display());

            tracing_subscriber::registry()
                .with(reload)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(false),
                )
                .init();
        }
    }

    Some(handle)
}
