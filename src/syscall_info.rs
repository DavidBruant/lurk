use crate::arch::parse_args;
use crate::style::StyleConfig;
use im::HashMap;
use libc::{c_ulonglong, user_regs_struct};
use libc::{
    MAP_ANONYMOUS, MAP_FIXED, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE,
    MAP_SHARED, MAP_STACK, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE,
};
use nix::unistd::Pid;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow::{self, Borrowed, Owned};
use std::fmt::{Debug, Display};
use std::io;
use std::io::Write;
use std::os::fd::RawFd;
use std::time::Duration;
use syscalls::Sysno;

pub type FdToPathname = HashMap<RawFd, String>;

#[derive(Debug)]
pub struct SyscallInfo {
    pub typ: &'static str,
    pub pid: Pid,
    pub syscall: Sysno,
    pub args: SyscallArgs,
    pub result: RetCode,
    pub duration: Duration,
    pub fd_to_pathname: FdToPathname
}

impl SyscallInfo {
    pub fn new(
        pid: Pid,
        syscall: Sysno,
        ret_code: RetCode,
        registers: user_regs_struct,
        duration: Duration,
        fd_to_pathname: FdToPathname
    ) -> Self {
        Self {
            typ: "SYSCALL",
            pid,
            syscall,
            args: parse_args(pid, syscall, registers),
            result: ret_code,
            duration,
            fd_to_pathname
        }
    }

    pub fn write_syscall(
        &self,
        style: StyleConfig,
        string_limit: Option<usize>,
        show_syscall_num: bool,
        show_duration: bool,
        output: &mut dyn Write,
    ) -> anyhow::Result<()> {
        if style.use_colors {
            write!(output, "[{}] ", style.pid.apply_to(&self.pid.to_string()))?;
        } else {
            write!(output, "[{}] ", &self.pid)?;
        }
        if show_syscall_num {
            write!(output, "{:>3} ", self.syscall.id())?;
        }
        if style.use_colors {
            let styled = style.syscall.apply_to(self.syscall.to_string());
            write!(output, "{styled}(")
        } else {
            write!(output, "{}(", &self.syscall)
        }?;
        for (idx, arg) in self.args.0.iter().enumerate() {
            if idx > 0 {
                write!(output, ", ")?;
            }
            // Special-case a few syscalls for more readable output
            if self.syscall == Sysno::execve || self.syscall == Sysno::execveat {
                // execve(filename, argv, envp)
                match (idx, arg) {
                    // argv: show array (possibly truncated by `string_limit` via write)
                    (1, SyscallArg::StrVec(_, _)) => arg.write(output, string_limit)?,
                    // envp: summarize like strace: print original pointer and count
                    (2, SyscallArg::StrVec(vs, maybe_addr)) => {
                        if let Some(addr) = maybe_addr {
                            let count = if !vs.is_empty() {
                                vs.len()
                            } else {
                                // try a best-effort pointer-only count if the strings couldn't be read
                                crate::arch::read_string_array_count(self.pid, *addr as c_ulonglong)
                            };
                            write!(output, "{:#x} /* {} vars */", *addr, count)?
                        } else {
                            // fall back to printing the array
                            arg.write(output, string_limit)?;
                        }
                    }
                    // default
                    _ => arg.write(output, string_limit)?,
                }
            } else if self.syscall == Sysno::mmap {
                // mmap(addr, len, prot, flags, fd, offset)
                // produce symbolic prot and flags
                let parts = format_mmap_args(&self.args.0, string_limit);
                write!(
                    output,
                    "{}",
                    parts.get(idx).map(|s| s.as_str()).unwrap_or("")
                )?;
            } else {
                arg.write(output, string_limit)?;
            }
        }
        write!(output, ") = ")?;
        if self.syscall == Sysno::exit || self.syscall == Sysno::exit_group {
            write!(output, "?")?;
        } else {
            if style.use_colors {
                let style = style.from_ret_code(self.result);
                // TODO: it would be great if we can force termcolor to write
                //       the styling prefix and suffix into the formatter.
                //       This would allow us to use the same code for both cases,
                //       and avoid additional string alloc
                write!(output, "{}", style.apply_to(self.result.to_string()))
            } else {
                write!(output, "{}", self.result)
            }?;
            if show_duration {
                // TODO: add an option to control each syscall duration scaling, e.g. ms, us, ns
                write!(output, " <{:.6}ns>", self.duration.as_nanos())?;
            }
        }
        Ok(writeln!(output)?)
    }
}

impl Serialize for SyscallInfo {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("type", &self.typ)?;
        map.serialize_entry("pid", &self.pid.as_raw())?;
        map.serialize_entry("num", &self.syscall)?;
        map.serialize_entry("syscall", &self.syscall.to_string())?;
        map.serialize_entry("args", &self.args)?;
        match self.result {
            RetCode::Ok(value) => map.serialize_entry("success", &value)?,
            RetCode::Err(value) => map.serialize_entry("error", &value)?,
            RetCode::Address(value) => map.serialize_entry("result", &value)?,
        }
        map.serialize_entry("duration", &self.duration.as_secs_f64())?;
        map.end()
    }
}

#[derive(Debug)]
pub struct SyscallArgs(pub Vec<SyscallArg>);

impl Serialize for SyscallArgs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for arg in &self.0 {
            let value = match arg {
                SyscallArg::Int(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Str(v) => serde_json::to_value(v).unwrap(),
                SyscallArg::Addr(v) => Value::String(format!("{v:#x}")),
                SyscallArg::StrVec(vs, _addr) => serde_json::to_value(vs).unwrap(),
            };
            seq.serialize_element(&value)?;
        }
        seq.end()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum RetCode {
    Ok(i32),
    Err(i32),
    Address(usize),
}

impl RetCode {
    pub fn from_raw(ret_code: c_ulonglong) -> Self {
        let ret_i32 = ret_code as isize;
        // TODO: is this > or >= ?  Add a link to the docs.
        if ret_i32.abs() > 0x8000 {
            Self::Address(ret_code as usize)
        } else if ret_i32 < 0 {
            Self::Err(ret_i32 as i32)
        } else {
            Self::Ok(ret_i32 as i32)
        }
    }
}

impl Display for RetCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok(v) | Self::Err(v) => Display::fmt(v, f),
            Self::Address(v) => write!(f, "{v:#X}"),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum SyscallArg {
    Int(i64),
    Str(String),
    // store optional original pointer address for arrays so we can summarize like strace
    StrVec(Vec<String>, Option<usize>),
    Addr(usize),
}

impl SyscallArg {
    pub fn write(&self, f: &mut dyn Write, string_limit: Option<usize>) -> io::Result<()> {
        match self {
            Self::Int(v) => write!(f, "{v}"),
            Self::Str(v) => {
                let value: Value = match string_limit {
                    Some(width) => trim_str(v, width),
                    None => Borrowed(v.as_ref()),
                }
                .into();
                write!(f, "{value}")
            }
            Self::StrVec(vs, _addr) => {
                // format vector as JSON-like array, applying trimming to each element
                let mut parts = Vec::with_capacity(vs.len());
                for s in vs {
                    let trimmed = match string_limit {
                        Some(width) => trim_str(s, width).into_owned(),
                        None => s.clone(),
                    };
                    parts.push(serde_json::to_string(&trimmed).unwrap());
                }
                write!(f, "[{}]", parts.join(", "))
            }
            Self::Addr(v) => write!(f, "{v:#X}"),
        }
    }
}

fn trim_str(string: &str, limit: usize) -> Cow<'_, str> {
    match string.chars().as_str().get(..limit) {
        None => Borrowed(string),
        Some(s) => Owned(format!("{s}...")),
    }
}

fn format_prot(flags: i64) -> String {
    let mut parts = Vec::new();
    if flags & (PROT_READ as i64) != 0 {
        parts.push("PROT_READ");
    }
    if flags & (PROT_WRITE as i64) != 0 {
        parts.push("PROT_WRITE");
    }
    if flags & (PROT_EXEC as i64) != 0 {
        parts.push("PROT_EXEC");
    }
    if flags == (PROT_NONE as i64) {
        parts.push("PROT_NONE");
    }
    if parts.is_empty() {
        format!("{flags}")
    } else {
        parts.join("|")
    }
}

fn format_map_flags(flags: i64) -> String {
    let mut parts = Vec::new();
    if flags & (MAP_SHARED as i64) != 0 {
        parts.push("MAP_SHARED");
    }
    if flags & (MAP_PRIVATE as i64) != 0 {
        parts.push("MAP_PRIVATE");
    }
    if flags & (MAP_ANONYMOUS as i64) != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if flags & (MAP_FIXED as i64) != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & (MAP_STACK as i64) != 0 {
        parts.push("MAP_STACK");
    }
    if flags & (MAP_NORESERVE as i64) != 0 {
        parts.push("MAP_NORESERVE");
    }
    if flags & (MAP_LOCKED as i64) != 0 {
        parts.push("MAP_LOCKED");
    }
    if flags & (MAP_POPULATE as i64) != 0 {
        parts.push("MAP_POPULATE");
    }
    if flags & (MAP_NONBLOCK as i64) != 0 {
        parts.push("MAP_NONBLOCK");
    }
    if parts.is_empty() {
        format!("{flags}")
    } else {
        parts.join("|")
    }
}

fn format_mmap_args(args: &[SyscallArg], string_limit: Option<usize>) -> Vec<String> {
    // Expect 6 args: addr, len, prot, flags, fd, offset
    let mut out = vec![String::new(); args.len()];
    for (i, a) in args.iter().enumerate() {
        match (i, a) {
            (0, SyscallArg::Addr(addr)) => {
                if *addr == 0 {
                    out[i] = "NULL".to_string();
                } else {
                    out[i] = format!("{:#X}", addr);
                }
            }
            (1, SyscallArg::Int(len)) => out[i] = format!("{}", len),
            (2, SyscallArg::Int(prot)) => out[i] = format_prot(*prot),
            (3, SyscallArg::Int(flags)) => out[i] = format_map_flags(*flags),
            (4, SyscallArg::Int(fd)) => out[i] = format!("{}", fd),
            (5, SyscallArg::Int(off)) => out[i] = format!("{}", off),
            // fall back to default write for other or unexpected types
            (_, other) => {
                let mut buf = Vec::new();
                other.write(&mut buf, string_limit).ok();
                out[i] = String::from_utf8_lossy(&buf).to_string();
            }
        }
    }
    out
}
