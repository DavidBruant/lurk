use crate::syscall_info::{SyscallArg, SyscallArgs};
use byteorder::{LittleEndian, WriteBytesExt};
use libc::{c_long, c_ulonglong, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::unistd::Pid;
use std::ffi::c_void;
use syscalls::Sysno;

#[cfg(any(target_arch = "aarch64", feature = "aarch64"))]
pub mod aarch64;
// #[cfg(any(target_arch = "arm", feature = "arm"))]
// pub mod arm;
// #[cfg(any(target_arch = "mips", feature = "mips"))]
// pub mod mips;
// #[cfg(any(target_arch = "mips64", feature = "mips64"))]
// pub mod mips64;
// #[cfg(any(target_arch = "powerpc", feature = "powerpc"))]
// pub mod powerpc;
// #[cfg(any(target_arch = "powerpc64", feature = "powerpc64"))]
// pub mod powerpc64;
#[cfg(any(target_arch = "riscv64", feature = "riscv64"))]
pub mod riscv64;
// #[cfg(any(target_arch = "s390x", feature = "s390x"))]
// pub mod s390x;
// #[cfg(any(target_arch = "sparc", feature = "sparc"))]
// pub mod sparc;
// #[cfg(any(target_arch = "sparc64", feature = "sparc64"))]
// pub mod sparc64;
// #[cfg(any(target_arch = "x86", feature = "x86"))]
// pub mod x86;
#[cfg(any(target_arch = "x86_64", feature = "x86_64"))]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
// #[cfg(target_arch = "arm")]
// pub use arm::*;
// #[cfg(target_arch = "mips")]
// pub use mips::*;
// #[cfg(target_arch = "mips64")]
// pub use mips64::*;
// #[cfg(target_arch = "powerpc")]
// pub use powerpc::*;
// #[cfg(target_arch = "powerpc64")]
// pub use powerpc64::*;
#[cfg(target_arch = "riscv64")]
pub use riscv64::*;
// #[cfg(target_arch = "s390x")]
// pub use s390x::*;
// #[cfg(target_arch = "sparc")]
// pub use sparc::*;
// #[cfg(target_arch = "sparc64")]
// pub use sparc64::*;
// #[cfg(target_arch = "x86")]
// pub use x86::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[derive(Debug, Copy, Clone)]
pub enum SyscallArgType {
    // Integer can be used to represent int, fd and size_t
    Int,
    // String can be used to represent *buf
    Str,
    // Array of strings, e.g. argv or envp
    StrArray,
    // Address can be used to represent *statbuf
    Addr,
}

pub fn read_string(pid: Pid, address: c_ulonglong) -> String {
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let address = unsafe { (address as *mut c_void).offset(count) };

        let res: c_long = match ptrace::read(pid, address) {
            Ok(c_long) => c_long,
            Err(_) => {
                // If we can't read the memory at the address, return the pointer
                // as a hex string so callers can still see a useful value.
                return format!("{:#x}", address as usize);
            }
        };

        let mut bytes: Vec<u8> = vec![];
        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {res} as i64 LittleEndian: {err}");
        });
        for b in bytes {
            if b == 0 {
                break 'done;
            }
            string.push(b as char);
        }

        count += word_size;
    }

    string
}

pub fn ptrace_init_options(pid: Pid) -> nix::Result<()> {
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_TRACEEXEC,
    )
}

pub fn ptrace_init_options_fork(pid: Pid) -> nix::Result<()> {
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACEEXIT
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE,
    )
}

#[allow(clippy::cast_sign_loss)]
#[must_use]
// SAFTEY: In get_register_data we make sure that the syscall number will never be negative.
pub fn parse_args(pid: Pid, syscall: Sysno, registers: user_regs_struct) -> SyscallArgs {
    SYSCALLS
        .get(syscall.id() as usize)
        .and_then(|option| option.as_ref())
        .map_or_else(
            || SyscallArgs(vec![]),
            |(_, args)| {
                SyscallArgs(
                    args.iter()
                        .filter_map(Option::as_ref)
                        .enumerate()
                        .map(|(idx, arg_type)| map_arg(pid, registers, idx, *arg_type))
                        .collect(),
                )
            },
        )
}

fn map_arg(pid: Pid, registers: user_regs_struct, idx: usize, arg: SyscallArgType) -> SyscallArg {
    let value = get_arg_value(registers, idx);
    match arg {
        SyscallArgType::Int => SyscallArg::Int(value as i64),
        SyscallArgType::Str => SyscallArg::Str(read_string(pid, value)),
        SyscallArgType::StrArray => SyscallArg::StrVec(read_string_array(pid, value), Some(value as usize)),
        SyscallArgType::Addr => SyscallArg::Addr(value as usize),
    }
}

pub fn read_string_array(pid: Pid, address: c_ulonglong) -> Vec<String> {
    let mut vec = Vec::new();
    if address == 0 {
        return vec;
    }

    // pointer size on x86_64 is 8 bytes; read pointers until NULL
    let mut offset = 0isize;
    // safety limit to avoid infinite loops on corrupt pointers
    for _ in 0..1024 {
        let ptr_addr = unsafe { (address as *mut c_void).offset(offset) };
        let res: c_long = match ptrace::read(pid, ptr_addr) {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut bytes: Vec<u8> = vec![];

        bytes.write_i64::<LittleEndian>(res).ok();
        let mut ptr_value: c_ulonglong = 0;
        for (i, b) in bytes.iter().enumerate() {
            ptr_value |= c_ulonglong::from(*b) << (i * 8);
        }
        if ptr_value == 0 {
            break;
        }
        vec.push(read_string(pid, ptr_value));
        offset += std::mem::size_of::<c_ulonglong>() as isize;
    }

    vec
}

/// Count pointers in a NULL-terminated `char * const *` array without attempting
/// to dereference the strings. This is more robust when the tracee's memory
/// cannot be fully read, but the pointer array itself is accessible.
pub fn read_string_array_count(pid: Pid, address: c_ulonglong) -> usize {
    if address == 0 {
        return 0;
    }

    let mut count = 0usize;
    let mut offset = 0isize;
    for _ in 0..1024 {
        let ptr_addr = unsafe { (address as *mut c_void).offset(offset) };
        let res: c_long = match ptrace::read(pid, ptr_addr) {
            Ok(v) => v,
            Err(_) => break,
        };
        // reconstruct pointer value from bytes
        let mut bytes: Vec<u8> = vec![];
        bytes.write_i64::<LittleEndian>(res).ok();
        let mut ptr_value: c_ulonglong = 0;
        for (i, b) in bytes.iter().enumerate() {
            ptr_value |= c_ulonglong::from(*b) << (i * 8);
        }
        if ptr_value == 0 {
            break;
        }
        count += 1;
        offset += std::mem::size_of::<c_ulonglong>() as isize;
    }

    count
}

pub fn escape_to_string(buf: &Vec<u8>) -> String {
    let mut string = String::new();
    for c in buf {
        let code = *c;
        if (0x20..=0x7f).contains(&code) {
            if code == b'\\' {
                string.push_str("\\\\");
            } else {
                string.push(char::from(code));
            }
        } else {
            string.push_str(format!("\\{c:x}").as_str());
        }
    }
    string
}
