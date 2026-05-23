
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

// This is a really bad adding function, its purpose is to fail in this
// example.
#[allow(dead_code)]
fn bad_add(a: i32, b: i32) -> i32 {
    a - b
}

#[cfg(test)]
mod tests {
    use std::io::{self, IsTerminal, Write};
    use syscalls::Sysno;
    
    use anyhow::{Error, Result, bail};
    use nix::unistd::{fork, ForkResult};
    
    use lurk_cli::style::StyleConfig;
    use lurk_cli::args::{ArgCommand, Args};
    use lurk_cli::{run_tracee, Tracer};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    //use super::*;

    /*
    #[test]
    fn test_add() {
        assert_eq!(add(1, 2), 3);
    }

    #[test]
    fn test_bad_add() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        assert_eq!(bad_add(1, 2), 3);
    }
    */


    #[test]
    fn lurk_tracer_ls() -> Result<(), Error> {
        let command = [String::from("ls")];

        println!("TEST lurk_tracer_ls");

        // create Trace instance manually
        // fed it "ls"
        let config= Args::from({Args { 
            syscall_number: false, 
            attach: None, 
            no_abbrev: false, 
            string_limit: None, 
            file: None, 
            summary_only: false, 
            summary: false, 
            successful_only: false, 
            failed_only: false, 
            env: Vec::new(), 
            username: None, 
            follow_forks: true, 
            syscall_times: false, 
            expr: Vec::new(), 
            json: false, 
            collapse_exec_retries: false, 
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command, &config.env, &None),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        println!("TEST lurk_tracer_ls - tracer.run_tracer");

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer();

        println!("TEST lurk_tracer_ls - after tracer.run_tracer");

        // get tracer.syscall_infos.
        let syscalls = tracer.syscall_infos;

        // perform filters to find the 'fstat'
            let fstat_syscalls: Vec<&lurk_cli::syscall_info::SyscallInfo> = syscalls.iter().filter(|&si| si.syscall == Sysno::fstat).collect();

        assert!(fstat_syscalls.len() >= 1, "At least one call to fstat during call to ls");

        Ok(())
    }

    
    #[test]
    fn exec_tracer_cat() -> Result<(), Error> {
        let command = [String::from("cat"), String::from(".gitignore")];

        let mut style_config = StyleConfig::default();

        style_config.use_colors = io::stdout().is_terminal();


        let config= Args::from({Args { 
            syscall_number: false, 
            attach: None, 
            no_abbrev: false, 
            string_limit: None, 
            file: None, 
            summary_only: false, 
            summary: false, 
            successful_only: false, 
            failed_only: false, 
            env: Vec::new(), 
            username: None, 
            follow_forks: true, 
            syscall_times: false, 
            expr: Vec::new(), 
            json: false, 
            collapse_exec_retries: false,
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command, &config.env, &None),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer() ;

        // get tracer.syscall_infos.
        let syscalls = tracer.syscall_infos;

        // perform filters to find the 'fstat'
        let openat_syscalls = syscalls.iter()
            .filter(|&si| si.syscall == Sysno::openat);
            
        let mut output: Box<dyn Write> = Box::new(std::io::stdout());

        for syscall in openat_syscalls.clone() {
            let _ = syscall.write_syscall(style_config.clone(), None, true, false, &mut output);
        }

        assert!(openat_syscalls.clone().count() >= 1, "At least one call to openat during call to ls");

        /*
        let succesful_openat_syscalls = openat_syscalls.clone()
            // keep succesful open
            .filter(|&osi| match osi.result{
                lurk_cli::syscall_info::RetCode::Ok(_) => {true}
                lurk_cli::syscall_info::RetCode::Err(_) => {false}

                lurk_cli::syscall_info::RetCode::Address(_) => {false}
            });
        */

        let attempted_opened_filepaths = openat_syscalls.clone()
            .map(|osi| match osi.args.0.iter().nth(1) {
                Some(val) => match val {
                    lurk_cli::syscall_info::SyscallArg::Int(_) => None,
                    lurk_cli::syscall_info::SyscallArg::Str(s) => Some(s),
                    lurk_cli::syscall_info::SyscallArg::StrVec(_items, _) => None,
                    lurk_cli::syscall_info::SyscallArg::Addr(_) => None,
                },
                None => None
            });

        assert!(
            attempted_opened_filepaths.clone().any(|filepath| filepath.unwrap() == ".gitignore"),
            "'.gitignore' should be one of the filepath opened"
        );      

        println!("Files attempted to be opened (openat syscall)");
        
        for arg in attempted_opened_filepaths {
            match arg {
                Some(filepath) => println!("{}", filepath),
                None => println!("No [1] argument for openat")
            }
        }


        Ok(())
    }


}


