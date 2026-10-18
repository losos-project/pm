//! `pmd`, the daemon binary.
//!
//! Today this is the worker half only: `pmd --worker --fd N` re-execs into
//! itself the way the real supervisor will, reads one job off the inherited
//! socket, runs it, and exits. See [`pm::daemon::worker`] for the protocol
//! and everything the worker actually does; there is no `zbus` code
//! anywhere in this task, and this binary does not yet own `org.pm1` or
//! bind a session bus name at all - that lands in a later task, once the
//! worker this one calls into is trustworthy on its own.
//!
//! `pmd --system` is the other daemon, unrelated to jobs: `org.pm1.System`
//! on the system bus, run as the `pm` user, which `pm system` asks to
//! administer the machine. See [`pm::system`].

use std::os::fd::RawFd;

use clap::Parser;
use miette::{IntoDiagnostic, WrapErr};
use nix::{sys::prctl, sys::signal::Signal, unistd::getppid};
use pm::daemon::worker;
use tracing_subscriber::EnvFilter;

/// `pmd`'s command line.
///
/// `--worker` and `--fd` travel together rather than as a subcommand,
/// matching the exact invocation
/// `docs/superpowers/specs/2026-09-18-dbus-daemon-design.md` names in
/// sections 3 and 6 (`pmd --worker --fd 3`): a future supervisor re-execs
/// `/proc/self/exe` with this literal argument shape, so there is no
/// version skew to reconcile between what it writes and what this parses.
#[derive(Parser)]
#[command(name = "pmd", version, about = "The pm daemon")]
struct Args {
    /// Run as a one-shot job worker, speaking the frame protocol on `--fd`.
    #[arg(long, requires = "fd")]
    worker: bool,
    /// The inherited socketpair file descriptor to speak the frame protocol
    /// on. Meaningless without `--worker`.
    #[arg(long)]
    fd: Option<RawFd>,
    /// Serve `org.pm1.System` on the system bus, as the `pm` user.
    #[arg(long, conflicts_with_all = ["worker", "fd"])]
    system: bool,
}

fn main() -> miette::Result<()> {
    // The system daemon is started by systemd, not forked by a supervisor, so
    // none of the worker's parent-death handling below applies to it.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--system")
    {
        let args = Args::parse();
        debug_assert!(args.system);
        // Its log is the journal's, which stamps each line itself.
        tracing_subscriber::fmt()
            .without_time()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
        return pm::system::daemon::serve();
    }

    // Before ANYTHING else - even argument parsing - see this module's docs
    // and design section 7, invariant 2: the window this closes is between
    // our parent's `fork` and this call, and every instruction that runs
    // first widens it.
    die_with_parent()?;

    // No subscriber here: the worker installs its own, at the level the job
    // asks for, once it has read the job (see `worker::run`).
    let args = Args::parse();
    match (args.worker, args.fd) {
        (true, Some(fd)) => worker::run(fd),
        _ => Err(miette::miette!(
            help = "the daemon service itself is a later task",
            "pmd currently only runs as `pmd --worker --fd <N>`"
        )),
    }
}

/// Arms `PR_SET_PDEATHSIG(SIGKILL)` and closes the race where our parent
/// died between its `fork()` and this call.
///
/// `PR_SET_PDEATHSIG` binds to the calling THREAD, so this has to run on
/// whatever thread ends up spawning and waiting on a hakoniwa container -
/// which, per [`pm::daemon::worker`]'s docs, is this process's main thread,
/// making `main`'s very first lines the only place this can correctly live.
///
/// Reads `getppid()` before and after arming the signal: if our parent
/// exited in that window, we have already been reparented (to init, or
/// whatever subreaper this pid namespace has) by the time the second read
/// runs, so the signal is now armed against a process that has no reason
/// to die. The daemon that was supposed to own this job is already gone,
/// so there is nothing left to build and, since we have not read a job
/// request yet, no `Completed` frame anyone is waiting on either - exiting
/// here is silent by construction, not silently wrong.
///
/// Returns `Ok(())` when it is safe to continue, or the error `main` should
/// exit with immediately, either because the parent already died or because
/// the syscalls themselves failed.
fn die_with_parent() -> miette::Result<()> {
    let before = getppid();
    prctl::set_pdeathsig(Signal::SIGKILL)
        .into_diagnostic()
        .wrap_err("cannot set PR_SET_PDEATHSIG")?;
    let after = getppid();
    if before != after {
        return Err(miette::miette!(
            "parent process exited before PDEATHSIG could be armed against it; exiting"
        ));
    }
    Ok(())
}
