use anyhow::{bail, Result};
use lurk_cli::{args::Args, Tracer};
use nix::unistd::{fork, ForkResult};
use std::io;

fn main() -> Result<()> {
    let command = String::from("/usr/bin/ls");

    let pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            return lurk_cli::run_tracee(&[command], &[], &None);
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(err) => bail!("fork() failed: {err}"),
    };

    let args = Args::default();
    let output = io::stdout();

    Tracer::new(pid, args, output)?.run_tracer()
}
