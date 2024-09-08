#![cfg_attr(not(test), no_std)]

extern crate alloc;

use axtype::get_user_str;
use fileops::iovec;
use axtype::{align_up_4k, is_aligned_4k};
use axhal::arch::sysno::*;
use axerrno::{linux_err_from, LinuxError, linux_err};
use axtype::FS_NAME_LEN;
use alloc::string::String;
use axhal::arch::fault_in_readable;

#[macro_use]
extern crate log;

const MAX_SYSCALL_ARGS: usize = 6;
pub type SyscallArgs = [usize; MAX_SYSCALL_ARGS];

pub fn do_syscall(args: SyscallArgs, sysno: usize) -> usize {
    match sysno {
        LINUX_SYSCALL_IOCTL => linux_syscall_ioctl(args),
        LINUX_SYSCALL_FCNTL => linux_syscall_fcntl(args),
        LINUX_SYSCALL_GETCWD => linux_syscall_getcwd(args),
        LINUX_SYSCALL_CHDIR => linux_syscall_chdir(args),
        LINUX_SYSCALL_FACCESSAT => linux_syscall_faccessat(args),
        LINUX_SYSCALL_MKNODAT => linux_syscall_mknodat(args),
        LINUX_SYSCALL_MKDIRAT => linux_syscall_mkdirat(args),
        LINUX_SYSCALL_UNLINKAT => linux_syscall_unlinkat(args),
        LINUX_SYSCALL_STATFS => linux_syscall_statfs(args),
        LINUX_SYSCALL_DUP => linux_syscall_dup(args),
        LINUX_SYSCALL_DUP3 => linux_syscall_dup3(args),
        LINUX_SYSCALL_OPENAT => linux_syscall_openat(args),
        LINUX_SYSCALL_CLOSE => linux_syscall_close(args),
        LINUX_SYSCALL_PIPE2 => linux_syscall_pipe2(args),
        LINUX_SYSCALL_LSEEK => linux_syscall_lseek(args),
        LINUX_SYSCALL_READ => linux_syscall_read(args),
        LINUX_SYSCALL_PREAD64 => linux_syscall_pread64(args),
        LINUX_SYSCALL_SENDFILE => linux_syscall_sendfile(args),
        LINUX_SYSCALL_WRITE => linux_syscall_write(args),
        LINUX_SYSCALL_WRITEV => linux_syscall_writev(args),
        LINUX_SYSCALL_READLINKAT => usize::MAX,
        LINUX_SYSCALL_UTIMENSAT => linux_syscall_utimensat(args),
        LINUX_SYSCALL_FTRUNCATE => linux_syscall_ftruncate(args),
        LINUX_SYSCALL_FSTATAT => linux_syscall_fstatat(args),
        LINUX_SYSCALL_UNAME => linux_syscall_uname(args),
        LINUX_SYSCALL_UMASK => linux_syscall_umask(args),
        LINUX_SYSCALL_BRK => linux_syscall_brk(args),
        LINUX_SYSCALL_RSEQ => linux_syscall_rseq(args),
        LINUX_SYSCALL_CLONE => linux_syscall_clone(args),
        LINUX_SYSCALL_EXECVE => linux_syscall_execve(args),
        LINUX_SYSCALL_MUNMAP => linux_syscall_munmap(args),
        LINUX_SYSCALL_MMAP => linux_syscall_mmap(args),
        LINUX_SYSCALL_MSYNC => linux_syscall_msync(args),
        LINUX_SYSCALL_MADVISE => linux_syscall_madvise(args),
        LINUX_SYSCALL_MPROTECT => linux_syscall_mprotect(args),
        LINUX_SYSCALL_SET_TID_ADDRESS => linux_syscall_set_tid_address(args),
        LINUX_SYSCALL_SET_ROBUST_LIST => linux_syscall_set_robust_list(args),
        LINUX_SYSCALL_WAIT4 => linux_syscall_wait4(args),
        LINUX_SYSCALL_PRLIMIT64 => linux_syscall_prlimit64(args),
        LINUX_SYSCALL_GETRANDOM => linux_syscall_getrandom(args),
        LINUX_SYSCALL_CLOCK_GETTIME => linux_syscall_clock_gettime(args),
        LINUX_SYSCALL_CLOCK_NANOSLEEP => linux_syscall_clock_nanosleep(args),
        LINUX_SYSCALL_RT_SIGPROCMASK => linux_syscall_rt_sigprocmask(args),
        LINUX_SYSCALL_RT_SIGACTION => linux_syscall_rt_sigaction(args),
        LINUX_SYSCALL_RT_SIGRETURN => linux_syscall_rt_sigreturn(args),
        LINUX_SYSCALL_GETTID => linux_syscall_gettid(args),
        LINUX_SYSCALL_GETPID => linux_syscall_getpid(args),
        LINUX_SYSCALL_SETUID => linux_syscall_setuid(args),
        LINUX_SYSCALL_SETGID => linux_syscall_setgid(args),
        LINUX_SYSCALL_SETRESUID => linux_syscall_setresuid(args),
        LINUX_SYSCALL_GETPPID => linux_syscall_getppid(args),
        LINUX_SYSCALL_GETGID => linux_syscall_getgid(args),
        LINUX_SYSCALL_GETEGID => linux_syscall_getegid(args),
        LINUX_SYSCALL_SETPGID => linux_syscall_setpgid(args),
        LINUX_SYSCALL_GETUID => linux_syscall_getuid(args),
        LINUX_SYSCALL_GETEUID => linux_syscall_geteuid(args),
        LINUX_SYSCALL_KILL => linux_syscall_kill(args),
        LINUX_SYSCALL_TGKILL => linux_syscall_tgkill(args),
        LINUX_SYSCALL_EXIT => linux_syscall_exit(args),
        LINUX_SYSCALL_EXIT_GROUP => linux_syscall_exit_group(args),
        LINUX_SYSCALL_FUTEX => linux_syscall_futex(args),
        LINUX_SYSCALL_FCHMOD => linux_syscall_fchmod(args),
        LINUX_SYSCALL_FCHMODAT => linux_syscall_fchmodat(args),
        LINUX_SYSCALL_FCHOWNAT => linux_syscall_fchownat(args),
        LINUX_SYSCALL_SCHED_GETAFFINITY => linux_syscall_sched_getaffinity(args),
        LINUX_SYSCALL_CAPGET => linux_syscall_capget(args),
        LINUX_SYSCALL_SETITIMER => linux_syscall_setitimer(args),
        LINUX_SYSCALL_MOUNT => linux_syscall_mount(args),
        LINUX_SYSCALL_SOCKET => linux_syscall_socket(args),
        #[cfg(target_arch = "riscv64")]
        LINUX_SYSCALL_GETDENTS64 => linux_syscall_getdents64(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_ACCESS => linux_syscall_access(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_ARCH_PRCTL => linux_syscall_arch_prctl(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_VFORK => linux_syscall_vfork(args),
        _ => panic!("Unsupported syscall: {}, {:#x}", sysno, sysno),
    }
}

fn linux_syscall_faccessat(args: SyscallArgs) -> usize {
    let [dfd, filename, mode, ..] = args;
    debug!(
        "linux_syscall_faccessat dfd {:#X} filename {:#X} mode {}",
        dfd, filename, mode
    );
    let filename = get_user_str(filename);
    fileops::faccessat(dfd, &filename)
}

fn linux_syscall_sched_getaffinity(args: SyscallArgs) -> usize {
    let [pid, cpu_set_size, mask, ..] = args;
    warn!("impl sched_getaffinity pid {} cpu_set_size {} mask {:#X}",
          pid, cpu_set_size, mask);
    0
}

fn linux_syscall_capget(args: SyscallArgs) -> usize {
    let [hdrp, datap, ..] = args;
    warn!("impl capget hdrp {} datap {}", hdrp, datap);
    0
}

fn linux_syscall_setitimer(args: SyscallArgs) -> usize {
    let [which, newval, oldval, ..] = args;
    warn!("impl setitimer which {} newval {} oldval {}", which, newval, oldval);
    0
}

fn linux_syscall_fchownat(args: SyscallArgs) -> usize {
    let [dfd, pathname, owner, group, flags, ..] = args;
    let pathname = get_user_str(pathname);
    warn!(
        "impl fchownat dfd {:#X} path {} owner:group {}:{} flags {:#X}",
        dfd, pathname, owner, group, flags
    );
    0
}

fn linux_syscall_fchmod(args: SyscallArgs) -> usize {
    let [fd, mode, ..] = args;
    warn!("impl fchmod fd {} mode {:#o}", fd, mode);
    0
}

fn linux_syscall_fchmodat(args: SyscallArgs) -> usize {
    let [dfd, pathname, mode, flags, ..] = args;
    let pathname = get_user_str(pathname);
    warn!(
        "impl fchmodat dfd {:#X} path {} mode {:#o} flags {:#X}",
        dfd, pathname, mode, flags
    );
    0
}

fn linux_syscall_mkdirat(args: SyscallArgs) -> usize {
    let [dfd, pathname, mode, ..] = args;
    let pathname = get_user_str(pathname);
    fileops::mkdirat(dfd, &pathname, mode)
}

fn linux_syscall_mknodat(args: SyscallArgs) -> usize {
    let [dfd, filename, mode, dev, ..] = args;
    let filename = get_user_str(filename);
    fileops::mknodat(dfd, &filename, mode, dev)
}

fn linux_syscall_unlinkat(args: SyscallArgs) -> usize {
    let [dfd, path, flags, ..] = args;
    let path = get_user_str(path);
    fileops::unlinkat(dfd, &path, flags)
}

fn linux_syscall_statfs(args: SyscallArgs) -> usize {
    let [path, buf, ..] = args;
    let path = get_user_str(path);
    fileops::statfs(&path, buf)
}

fn linux_syscall_openat(args: SyscallArgs) -> usize {
    let [dfd, filename, flags, mode, ..] = args;
    let filename = match getname(filename) {
        Ok(fname) => fname,
        Err(e) => {
            return e;
        },
    };
    if filename.len() > FS_NAME_LEN {
        return linux_err!(ENAMETOOLONG);
    }
    info!("filename: {} flags {:#o}\n", filename, flags);
    fileops::register_file(
        fileops::openat(dfd, &filename, flags, mode), flags
    )
}

fn linux_syscall_dup(args: SyscallArgs) -> usize {
    let [fd, ..] = args;
    fileops::dup(fd)
}

fn linux_syscall_dup3(args: SyscallArgs) -> usize {
    let [oldfd, newfd, flags, ..] = args;
    fileops::dup3(oldfd, newfd, flags)
}

fn linux_syscall_close(args: SyscallArgs) -> usize {
    let [fd, ..] = args;
    info!("linux_syscall_close [{:#x}] ...", fd);
    if let Err(e) = fileops::unregister_file(fd) {
        linux_err_from!(e)
    } else {
        0
    }
}

fn linux_syscall_pipe2(args: SyscallArgs) -> usize {
    let [fds, flags, ..] = args;

    if let Err(e) = fileops::pipe2(fds, flags) {
        linux_err_from!(e)
    } else {
        0
    }
}

fn linux_syscall_lseek(args: SyscallArgs) -> usize {
    let [fd, offset, whence, ..] = args;
    fileops::lseek(fd, offset, whence)
}

fn linux_syscall_read(args: SyscallArgs) -> usize {
    let [fd, buf, count, ..] = args;

    let err = axhal::arch::fault_in_writeable(buf, count);
    if err != 0 {
        return err;
    }

    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    fileops::read(fd, ubuf).unwrap_or_else(|e| {
        linux_err_from!(e)
    })
}

fn linux_syscall_pread64(args: SyscallArgs) -> usize {
    let [fd, buf, count, offset, ..] = args;
    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    fileops::pread64(fd, ubuf, offset).unwrap_or_else(|e| {
        linux_err_from!(e)
    })
}

fn linux_syscall_sendfile(args: SyscallArgs) -> usize {
    let [out_fd, in_fd, offset, count, ..] = args;
    fileops::sendfile(out_fd, in_fd, offset, count)
}

#[cfg(target_arch = "riscv64")]
fn linux_syscall_getdents64(args: SyscallArgs) -> usize {
    let [fd, dirp, count, ..] = args;
    fileops::getdents64(fd, dirp, count)
}

fn linux_syscall_write(args: SyscallArgs) -> usize {
    let [fd, buf, size, ..] = args;
    info!("write: {:#x}, {:#x}, {:#x}", fd, buf, size);

    if buf == 0 || size == 0 {
        return 0;
    }

    let err = axhal::arch::fault_in_readable(buf, size);
    if err != 0 {
        return err;
    }

    let ubuf = unsafe { core::slice::from_raw_parts(buf as *const u8, size) };
    fileops::write(fd, ubuf).unwrap_or_else(|e| {
        linux_err_from!(e)
    })
}

fn linux_syscall_writev(args: SyscallArgs) -> usize {
    let [fd, array, size, ..] = args;
    info!("writev: {:#x}, {:#x}, {:#x}", fd, array, size);

    let iov_array = unsafe { core::slice::from_raw_parts(array as *const iovec, size) };
    fileops::writev(fd, iov_array)
}

fn linux_syscall_fstatat(args: SyscallArgs) -> usize {
    let [dfd, path, statbuf, flags, ..] = args;
    fileops::fstatat(dfd, path, statbuf, flags)
}

fn linux_syscall_ftruncate(args: SyscallArgs) -> usize {
    let [fd, length, ..] = args;
    fileops::ftruncate(fd, length)
}

fn linux_syscall_utimensat(args: SyscallArgs) -> usize {
    let [dfd, filename, times, flags, ..] = args;
    let filename = get_user_str(filename);
    fileops::utimensat(dfd, &filename, times, flags)
}

#[cfg(target_arch = "x86_64")]
fn linux_syscall_access(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_access");
    0
}

fn linux_syscall_mmap(args: SyscallArgs) -> usize {
    let [va, len, prot, flags, fd, offset] = args;
    assert!(is_aligned_4k(va));
    info!(
        "###### mmap!!! {:#x} {:#x} prot {:#x} flags {:#x} {:#x} {:#x}",
        va, len, prot, flags, fd, offset
    );

    mmap::mmap(va, len, prot, flags, fd, offset)
        .unwrap_or_else(|e| {
            linux_err_from!(e)
        })
}

fn linux_syscall_munmap(args: SyscallArgs) -> usize {
    let [va, len, ..] = args;
    warn!("munmap!!! {:#x} {:#x}", va, len);
    mmap::munmap(va, len)
}

fn linux_syscall_msync(args: SyscallArgs) -> usize {
    let [va, len, flags, ..] = args;
    mmap::msync(va, len, flags)
}

fn linux_syscall_madvise(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_madvise");
    0
}

fn linux_syscall_ioctl(args: SyscallArgs) -> usize {
    let [fd, request, udata, ..] = args;
    fileops::ioctl(fd, request, udata)
}

fn linux_syscall_fcntl(args: SyscallArgs) -> usize {
    let [fd, cmd, udata, ..] = args;
    fileops::fcntl(fd, cmd, udata)
}

fn linux_syscall_getcwd(args: SyscallArgs) -> usize {
    let [buf, size, ..] = args;

    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size) };
    fileops::getcwd(ubuf)
}

fn linux_syscall_chdir(args: SyscallArgs) -> usize {
    let [pathname, ..] = args;
    let pathname = get_user_str(pathname);
    fileops::chdir(&pathname)
}

fn linux_syscall_mprotect(args: SyscallArgs) -> usize {
    let [va, len, prot, ..] = args;
    mmap::mprotect(va, len, prot)
}

fn linux_syscall_set_tid_address(args: SyscallArgs) -> usize {
    let [tidptr, ..] = args;
    fork::set_tid_address(tidptr)
}

fn linux_syscall_set_robust_list(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_set_robust_list");
    0
}

fn linux_syscall_prlimit64(args: SyscallArgs) -> usize {
    let [pid, resource, new_rlim, old_rlim, ..] = args;
    sys::prlimit64(pid, resource, new_rlim, old_rlim)
}

fn linux_syscall_wait4(args: SyscallArgs) -> usize {
    let [pid, wstatus, options, rusage, ..] = args;
    sys::wait4(pid, wstatus, options, rusage)
}

fn linux_syscall_getrandom(args: SyscallArgs) -> usize {
    let [buf, len, _flags, ..] = args;
    assert_eq!(len, 8);
    let r = axhal::misc::random() as u64;
    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    ubuf.copy_from_slice(&r.to_le_bytes());
    len
}

fn linux_syscall_clock_gettime(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_clock_gettime");
    0
}

fn linux_syscall_clock_nanosleep(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_clock_nanosleep");
    0
}

fn linux_syscall_rt_sigprocmask(args: SyscallArgs) -> usize {
    let [how, nset, oset, sigsetsize, ..] = args;
    signal::rt_sigprocmask(how, nset, oset, sigsetsize)
}

fn linux_syscall_rt_sigaction(args: SyscallArgs) -> usize {
    let [sig, act, oact, sigsetsize, ..] = args;
    signal::rt_sigaction(sig, act, oact, sigsetsize)
}

fn linux_syscall_rt_sigreturn(_args: SyscallArgs) -> usize {
    signal::rt_sigreturn()
}

fn linux_syscall_gettid(_args: SyscallArgs) -> usize {
    sys::gettid()
}

fn linux_syscall_getpid(_args: SyscallArgs) -> usize {
    sys::getpid()
}

fn linux_syscall_getppid(_args: SyscallArgs) -> usize {
    sys::getppid()
}

fn linux_syscall_setuid(args: SyscallArgs) -> usize {
    let uid = args[0];
    sys::setuid(uid)
}

fn linux_syscall_setresuid(args: SyscallArgs) -> usize {
    let [ruid, euid, suid, ..] = args;
    sys::setresuid(ruid, euid, suid)
}

fn linux_syscall_setgid(args: SyscallArgs) -> usize {
    let gid = args[0];
    sys::setgid(gid)
}

fn linux_syscall_getgid(_args: SyscallArgs) -> usize {
    sys::getgid()
}

fn linux_syscall_getegid(_args: SyscallArgs) -> usize {
    sys::getegid()
}

fn linux_syscall_geteuid(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_geteuid");
    0
}

fn linux_syscall_getuid(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_getuid");
    0
}

fn linux_syscall_setpgid(_args: SyscallArgs) -> usize {
    sys::setpgid()
}

fn linux_syscall_tgkill(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_tgkill");
    0
}

fn linux_syscall_kill(args: SyscallArgs) -> usize {
    let [pid, sig, ..] = args;
    signal::kill(pid, sig)
}

#[cfg(target_arch = "x86_64")]
fn linux_syscall_arch_prctl(args: SyscallArgs) -> usize {
    let [code, addr, ..] = args;
    sys::arch_prctl(code, addr)
}

const UTS_LEN: usize = 64;

#[repr(C)]
struct utsname {
    sysname: [u8; UTS_LEN + 1],
    nodename: [u8; UTS_LEN + 1],
    release: [u8; UTS_LEN + 1],
    version: [u8; UTS_LEN + 1],
    machine: [u8; UTS_LEN + 1],
    domainname: [u8; UTS_LEN + 1],
}

fn linux_syscall_uname(args: SyscallArgs) -> usize {
    let ptr = args[0];
    info!("uname: {:#x}", ptr);

    let uname = unsafe { (ptr as *mut utsname).as_mut().unwrap() };

    init_bytes_from_str(&mut uname.sysname[..], "Linux");
    init_bytes_from_str(&mut uname.nodename[..], "(none)");
    init_bytes_from_str(&mut uname.release[..], "5.15.135+");
    init_bytes_from_str(
        &mut uname.version[..],
        "#98 SMP Wed Jul 17 09:12:19 UTC 2024",
    );
    init_bytes_from_str(&mut uname.machine[..], "riscv64");
    init_bytes_from_str(&mut uname.domainname[..], "(none)");

    return 0;
}

fn linux_syscall_umask(args: SyscallArgs) -> usize {
    let mode = args[0] as u32;
    sys::do_umask(mode)
}

fn init_bytes_from_str(dst: &mut [u8], src: &str) {
    let src = src.as_bytes();
    let (left, right) = dst.split_at_mut(src.len());
    left.copy_from_slice(src);
    right.fill(0);
}

fn linux_syscall_brk(args: SyscallArgs) -> usize {
    let va = align_up_4k(args[0]);
    mmap::set_brk(va)
}

fn linux_syscall_rseq(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_rseq");
    0
}

fn linux_syscall_clone(args: SyscallArgs) -> usize {
    let [flags, newsp, ptid, tls, ctid, ..] = args;
    fork::sys_clone(flags, newsp, tls, ptid, ctid)
}

fn linux_syscall_execve(args: SyscallArgs) -> usize {
    let [path, argv, envp, ..] = args;
    let path = get_user_str(path);
    exec::execve(&path, argv, envp)
}

fn linux_syscall_exit(args: SyscallArgs) -> usize {
    let [exit_code, ..] = args;
    sys::exit(exit_code as u32)
}

fn linux_syscall_exit_group(args: SyscallArgs) -> usize {
    let [exit_code, ..] = args;
    sys::exit_group(exit_code as u32)
}

fn linux_syscall_futex(args: SyscallArgs) -> usize {
    let [uaddr, op, val, timeout_or_val2, uaddr2, val3, ..] = args;
    sys::do_futex(uaddr, op, val, timeout_or_val2, uaddr2, val3)
}

#[cfg(target_arch = "x86_64")]
fn linux_syscall_vfork(_args: SyscallArgs) -> usize {
    fork::sys_vfork()
}

fn linux_syscall_mount(_args: SyscallArgs) -> usize {
    // TODO: implement mount syscall
    0
}

fn linux_syscall_socket(_args: SyscallArgs) -> usize {
    error!("linux_syscall_socket: unimplemented!");
    linux_err!(EINVAL)
}

pub fn getname(filename: usize) -> Result<String, usize> {
    // Todo: check the full filename. Now just the first byte.
    let err = fault_in_readable(filename, 1);
    if err != 0 {
        return Err(err);
    }
    Ok(get_user_str(filename))
}

pub fn init() {
    info!("Initialize systemcalls ...");
}
