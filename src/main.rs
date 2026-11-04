// A portable tool is started by double-click, and a console window belonging to a tray icon is in
// the way. Debug builds keep the console, because that is where the log goes while it is developed.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod device;
mod elevated;
mod export;
mod instance;
mod learn;
mod log;
mod mcp;
mod monitor;
mod paths;
mod profile_xml;
mod rules;
mod server;
mod store;
mod tray;
mod user;
#[cfg(windows)]
mod wfp;

#[cfg(test)]
mod testutil;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{Policy, Settings};
use crate::paths::DataPaths;
use crate::rules::RuleFile;

/// The URL the tray opens: the page, plus the session token in the fragment.
///
/// The fragment is the whole point. A query would arrive on the wire with the document request and
/// end up in the access log of anything in between, and the token would be one `curl` away from
/// any process of the same user.
fn tray_url(url: &str, token: &str) -> String {
    format!("{url}/#token={token}")
}

/// What the process should do with the live store.
///
/// A run that names no flag serves: a portable tool is started by double-click, and a double-click
/// that ends at once with nothing in the notification area reads as a broken program. The one-shot
/// operations are the ones the web UI exposes as well; `Serve` is the mode the tool is meant to run
/// in, and it keeps the process alive instead of applying and exiting.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
enum Command {
    /// Push the loaded rules into the live store.
    Apply,
    /// Take our filters out of the live store again.
    Clear,
    /// Run the web server until the process is stopped. This is what no arguments mean.
    #[default]
    Serve,
    /// Run the web server, but wait briefly for the instance that a relaunch is stopping.
    ///
    /// The elevated newcomer of an elevated relaunch starts while the unelevated process still
    /// holds the instance name, so it is given a few seconds before it counts as a second start.
    Takeover,
    /// Read a profile written by the C original into the active rule file.
    Import(PathBuf),
}

impl Command {
    /// Parse the arguments. An unknown argument is an error rather than a shrug, so a mistyped
    /// flag cannot silently install filters the user did not ask for.
    fn parse(args: &[String]) -> Result<Self> {
        match args {
            [] => Ok(Self::Serve),
            [flag] if flag == "--apply" => Ok(Self::Apply),
            [flag] if flag == "--clear" => Ok(Self::Clear),
            [flag] if flag == "--serve" => Ok(Self::Serve),
            [flag] if flag == "--takeover" => Ok(Self::Takeover),
            [flag, path] if flag == "--import" => Ok(Self::Import(PathBuf::from(path))),
            [flag] => bail!(
                "unknown argument '{flag}'; expected --serve, --apply, --clear or --import (see \
                 --help)"
            ),
            _ => bail!("too many arguments; expected at most one flag"),
        }
    }
}

/// Every parameter the process understands, and the shortest start that does something.
///
/// `--help` prints this. A release build has no console, so a double-click shows nothing of it; the
/// reader is whoever starts the tool from a shell, and for them this is the difference between a
/// tool that serves quietly and a tool they have to guess at.
fn usage() -> String {
    // One entry per line, joined afterwards, because the line continuation of a string literal
    // swallows the leading spaces that make a usage block readable.
    [
        "winfw-mcp [ --serve | --apply | --clear | --import <profile.xml> ]",
        "",
        "    (no flag)      same as --serve; this is what a double-click starts",
        "    --serve        run the web server until the process is stopped",
        "    --takeover     same, but wait briefly for an instance that is stopping (relaunch)",
        "    --apply        load the rules and install them in the live store",
        "    --clear        remove our filters from the live store",
        "    --import       read an exported profile into the active rule file, replacing it",
        "    --help, -h     show this text",
        "    --version, -V  print the version",
        "",
        "Reading and writing the store needs elevation. Without it no rule is installed and the",
        "page shows a store it cannot confirm.",
        "",
        "Start it with a double-click, or from a shell with:",
        "",
        "    winfw-mcp.exe",
    ]
    .join("\n")
        + "\n"
}

/// The text of the dialog that asks for an elevated start.
///
/// It names the downside of answering no, because the alternative is a tool that looks like it runs
/// while the firewall it is supposed to own stays untouched.
fn elevation_question() -> String {
    String::from(
        "winfw-mcp reads and writes the Windows Filtering Platform store, and that needs\n\
         administrator rights.\n\
         \n\
         Without them no rule is installed and the page shows a store it cannot confirm.\n\
         \n\
         Restart winfw-mcp as administrator now?",
    )
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", usage());

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

    // All state is read here, once. Later milestones keep the in-memory copy authoritative and write
    // every change straight back (PLAN.md section 2). The settings come first because the log level
    // is one of them, which makes them the only state read before a line can be written anywhere.
    let settings = Settings::load_or_create(&paths.config)?;

    // A named profile is an ordinary rule file under `profiles\`; an empty name means the rules
    // of `rules.toml` itself, which is what a fresh install has. Naming the file reads nothing.
    let active_rules = match settings.active_profile.as_str() {
        "" => paths.rules.clone(),
        name => paths.profile_file(name),
    };

    // The subscriber is installed before the rule file is read, so that a read which has something
    // to say about itself can say it. Until 0.67.0 the rules were read first, and the one warning
    // `RuleFile::load_or_create` knows — the file on disk did not parse, the previous generation
    // was taken instead — went into a vacuum: the page showed rules the file did not hold, and the
    // log held nothing about it.
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

    // Reading and writing the live store needs elevation, and a portable tool is started by
    // double-click, which is unelevated. An unelevated run used to limp along and log access-denied
    // warnings; now it asks for an elevated start with the same parameters and stops here, because
    // a firewall that cannot write its rules is not a firewall. An import only touches files and
    // is therefore not asked about.
    if !matches!(command, Command::Import(_)) && !elevated::is_elevated() {
        if elevated::ask_elevated(&elevation_question()) {
            match elevated::relaunch_elevated(&args) {
                Ok(()) => {
                    info!("asked the shell to restart as administrator; this run stops here");

                    return Ok(());
                }
                Err(error) => warn!(
                    reason = %format!("{error:#}"),
                    "the elevated restart was refused; continuing unelevated",
                ),
            }
        } else {
            warn!("running unelevated: no rule is installed and the page cannot confirm the store");
        }
    }

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

    info!(count = rules.rule.len(), "rules loaded");

    // Reading a profile from the C original replaces the rules of the active profile and stops
    // there: nothing is pushed to the live store, because the user is meant to look at the result
    // on the page before deciding whether it is worth installing.
    if let Command::Import(file) = &command {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("read the profile {}", file.display()))?;
        let import = profile_xml::parse(&text)
            .with_context(|| format!("read the profile {}", file.display()))?;

        import.rules.save(&active_rules)?;

        for note in &import.notes {
            warn!(note = %note, "left out of the import");
        }

        info!(
            file = %file.display(),
            rules = import.rules.rule.len(),
            notes = import.notes.len(),
            "profile imported",
        );

        return Ok(());
    }

    if matches!(command, Command::Serve | Command::Takeover) {
        let takeover = command == Command::Takeover;

        return serve(paths, settings, rules, active_rules, log_filter, takeover);
    }

    // A one-shot run has no live monitor, but the applications a previous `--serve` run saw are on
    // disk, and those are what a wildcard rule has to be expanded against.
    let known = match command {
        Command::Apply => learn::Detector::load(&paths.learn, "")
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
    takeover: bool,
) -> Result<()> {
    let port = settings.port;
    let active_name = settings.active_profile.clone();

    // The secret a writing request has to carry. Generated here rather than read from a file, so a
    // page that is not ours cannot guess it (PLAN.md section 11).
    let token = server::session_token();

    // A second double-click must not mean a second server: two listeners, two tray icons and two
    // processes rebuilding the one live store. Whoever loses the name is done, which is why this
    // happens before a port is bound or the store is touched. It does not open a browser: bringing
    // the running page to the front is the tray's job, and a process that ends here has no tray.
    // The newcomer of a relaunch is the one exception that waits for the name.
    let Some(guard) = (if takeover {
        instance::claim_takeover(&paths)?
    } else {
        instance::claim(&paths)?
    }) else {
        let url = instance::running_url(&paths.root.join(instance::PORT_FILE), port);

        warn!(url = %url, "another instance is serving; this start stops here");

        bail!("another instance is serving on {url}");
    };

    // The rules and the detected applications are shared between the request threads and the
    // monitor's callbacks, which is what the locks are for.
    let rules = Arc::new(std::sync::Mutex::new(rules));
    let detector = Arc::new(learn::Detector::load(&paths.learn, &active_name)?);

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

    // The token rides to the browser in the fragment of the URL the tray opens. A fragment is
    // never sent over the wire, so the secret appears in no request, no log and no response body:
    // a process on the same machine that reads `GET /api/state` with curl still does not know it.
    let url = format!("http://{}", server.addr());
    let tray_url = tray_url(&url, &token);

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
        // None of these three reaches `sync_store`: `serve` and `takeover` return into their own
        // loop, and an import stops after writing the rule file. The arms only keep the match
        // honest.
        Command::Serve | Command::Takeover | Command::Import(_) => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::{Command, tray_url};

    /// The single flag decides what the process does to the live store, so an unknown one has to
    /// be an error rather than the default: applying filters nobody asked for is not a harmless
    /// mistake, and it is the reason `parse` refuses instead of shrugging.
    #[test]
    fn the_one_flag_names_the_command() {
        assert_eq!(Command::parse(&[]).expect("no flag"), Command::Serve);
        assert_eq!(
            Command::parse(&["--apply".to_owned()]).expect("--apply"),
            Command::Apply,
        );
        assert_eq!(
            Command::parse(&["--serve".to_owned()]).expect("--serve"),
            Command::Serve,
        );
        assert_eq!(
            Command::parse(&["--takeover".to_owned()]).expect("--takeover"),
            Command::Takeover,
        );
        assert_eq!(
            Command::parse(&["--clear".to_owned()]).expect("--clear"),
            Command::Clear,
        );
        assert_eq!(
            Command::parse(&["--import".to_owned(), "profile.xml".to_owned()]).expect("--import"),
            Command::Import("profile.xml".into()),
        );
    }

    /// A double-click starts the tool, so the usage a reader reaches with `--help` has to name
    /// every flag and say what the bare start does. Both are decided here rather than left to the
    /// text alone.
    #[test]
    fn the_usage_names_the_flags_and_the_bare_start() {
        let text = super::usage();

        for flag in ["--serve", "--apply", "--clear", "--import", "--takeover"] {
            assert!(text.contains(flag), "the usage is missing {flag}");
        }

        assert!(
            text.contains("winfw-mcp.exe"),
            "the usage ends with the shortest start",
        );
        assert!(
            text.contains("same as --serve"),
            "no parameters must say that they serve, which is what a double-click does",
        );
    }

    /// The dialog is the whole argument for the elevated start, so the downside of answering no has
    /// to be in it: a person reading a dialog should not have to look anything up.
    #[test]
    fn the_elevation_question_names_the_downside() {
        let question = super::elevation_question();

        assert!(
            question.contains("no rule is installed"),
            "the question says what is lost: {question}",
        );
        assert!(
            question.contains("administrator"),
            "the question names what it asks for: {question}",
        );
    }

    #[test]
    fn an_argument_that_is_not_one_known_flag_is_refused() {
        let mistyped = Command::parse(&["--server".to_owned()])
            .expect_err("--serve is the flag, --server is not");
        assert!(mistyped.to_string().contains("--server"), "{mistyped}");

        let doubled = Command::parse(&["--serve".to_owned(), "--clear".to_owned()])
            .expect_err("two flags are not one command");
        assert!(doubled.to_string().contains("too many"), "{doubled}");

        let alone = Command::parse(&["--import".to_owned()]).expect_err("--import needs a file");
        assert!(alone.to_string().contains("--import"), "{alone}");
    }

    /// The token reaches the browser in the fragment and nowhere else, so the URL the tray opens
    /// has to carry it after the `#` — everything before that is what the server is asked for.
    #[test]
    fn the_tray_url_carries_the_token_in_the_fragment() {
        let url = tray_url("http://127.0.0.1:8788", "0f3a");

        assert_eq!(url, "http://127.0.0.1:8788/#token=0f3a");
        assert_eq!(
            url.split('#').next().expect("a fragment separator"),
            "http://127.0.0.1:8788/",
            "the part a browser sends is the page alone",
        );
    }
}
