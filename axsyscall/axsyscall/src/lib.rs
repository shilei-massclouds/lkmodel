#![cfg_attr(not(test), no_std)]

extern crate alloc;

use axtype::get_user_str;
use fileops::iovec;
use axtype::{align_up_4k, is_aligned_4k};
use axhal::arch::sysno::*;
use axerrno::{linux_err_from, LinuxError};

#[macro_use]
extern crate log;

const MAX_SYSCALL_ARGS: usize = 6;
pub type SyscallArgs = [usize; MAX_SYSCALL_ARGS];

pub fn do_syscall(args: SyscallArgs, sysno: usize) -> usize {
    match sysno {
        LINUX_SYSCALL_IOCTL => linux_syscall_ioctl(args),
        LINUX_SYSCALL_GETCWD => linux_syscall_getcwd(args),
        LINUX_SYSCALL_CHDIR => linux_syscall_chdir(args),
        LINUX_SYSCALL_FACCESSAT => linux_syscall_faccessat(args),
        LINUX_SYSCALL_MKDIRAT => linux_syscall_mkdirat(args),
        LINUX_SYSCALL_UNLINKAT => linux_syscall_unlinkat(args),
        LINUX_SYSCALL_OPENAT => linux_syscall_openat(args),
        LINUX_SYSCALL_CLOSE => linux_syscall_close(args),
        LINUX_SYSCALL_LSEEK => linux_syscall_lseek(args),
        LINUX_SYSCALL_READ => linux_syscall_read(args),
        LINUX_SYSCALL_PREAD64 => linux_syscall_pread64(args),
        LINUX_SYSCALL_WRITE => linux_syscall_write(args),
        LINUX_SYSCALL_WRITEV => linux_syscall_writev(args),
        LINUX_SYSCALL_READLINKAT => usize::MAX,
        LINUX_SYSCALL_FTRUNCATE => linux_syscall_ftruncate(args),
        LINUX_SYSCALL_FSTATAT => linux_syscall_fstatat(args),
        LINUX_SYSCALL_UNAME => linux_syscall_uname(args),
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
        LINUX_SYSCALL_GETPPID => linux_syscall_getppid(args),
        LINUX_SYSCALL_GETGID => linux_syscall_getgid(args),
        LINUX_SYSCALL_SETPGID => linux_syscall_setpgid(args),
        LINUX_SYSCALL_GETEUID => linux_syscall_geteuid(args),
        LINUX_SYSCALL_KILL => linux_syscall_kill(args),
        LINUX_SYSCALL_TGKILL => linux_syscall_tgkill(args),
        LINUX_SYSCALL_EXIT => linux_syscall_exit(args),
        LINUX_SYSCALL_EXIT_GROUP => linux_syscall_exit_group(args),
        LINUX_SYSCALL_FCHMOD => linux_syscall_fchmod(args),
        LINUX_SYSCALL_FCHMODAT => linux_syscall_fchmodat(args),
        LINUX_SYSCALL_FCHOWNAT => linux_syscall_fchownat(args),
        LINUX_SYSCALL_SCHED_GETAFFINITY => linux_syscall_sched_getaffinity(args),
        LINUX_SYSCALL_CAPGET => linux_syscall_capget(args),
        LINUX_SYSCALL_SETITIMER => linux_syscall_setitimer(args),
        LINUX_SYSCALL_FCNTL => linux_syscall_fcntl(args),
        #[cfg(target_arch = "riscv64")]
        LINUX_SYSCALL_GETDENTS64 => linux_syscall_getdents64(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_ACCESS => linux_syscall_access(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_ARCH_PRCTL => linux_syscall_arch_prctl(args),
        #[cfg(target_arch = "x86_64")]
        LINUX_SYSCALL_VFORK => linux_syscall_vfork(args),
        LINUX_SYSCALL_GETUID => linux_syscall_getuid(args),
        _ => panic!("Unsupported syscall: {}, {:#x}", sysno, sysno),
    }
}

fn linux_syscall_faccessat(args: SyscallArgs) -> usize {
    let [dfd, filename, mode, ..] = args;
    info!(
        "linux_syscall_faccessat dfd {:#X} filename {:#X} mode {}",
        dfd, filename, mode
    );
    let filename = get_user_str(filename);
    warn!("filename: {}", filename);
    0
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

fn linux_syscall_unlinkat(args: SyscallArgs) -> usize {
    let [dfd, path, flags, ..] = args;
    let path = get_user_str(path);
    warn!(
        "impl unlinkat dfd {}, path {} flags {:#X}",
        dfd, path, flags
    );
    0
}

fn linux_syscall_openat(args: SyscallArgs) -> usize {
    let [dfd, filename, flags, mode, ..] = args;

    let filename = get_user_str(filename);
    info!("filename: {}\n", filename);
    fileops::register_file(fileops::openat(dfd, &filename, flags, mode))
}

fn linux_syscall_close(args: SyscallArgs) -> usize {
    let [fd, ..] = args;
    info!("linux_syscall_close [{}] ...", fd);
    fileops::unregister_file(fd);
    0
}

fn linux_syscall_lseek(args: SyscallArgs) -> usize {
    let [fd, offset, whence, ..] = args;
    fileops::lseek(fd, offset, whence)
}

fn linux_syscall_read(args: SyscallArgs) -> usize {
    let [fd, buf, count, ..] = args;

    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    fileops::read(fd, ubuf)
}

fn linux_syscall_pread64(args: SyscallArgs) -> usize {
    let [fd, buf, count, offset, ..] = args;

    let ubuf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    fileops::pread64(fd, ubuf, offset)
}

#[cfg(target_arch = "riscv64")]
fn linux_syscall_getdents64(args: SyscallArgs) -> usize {
    let [fd, _dirp, count, ..] = args;
    warn!("impl linux_syscall_getdents64 fd {}, count {}", fd, count);
    0
}

fn linux_syscall_write(args: SyscallArgs) -> usize {
    let [fd, buf, size, ..] = args;
    info!("write: {:#x}, {:#x}, {:#x}", fd, buf, size);

    let ubuf = unsafe { core::slice::from_raw_parts(buf as *const u8, size) };
    fileops::write(fd, ubuf)
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

#[cfg(target_arch = "x86_64")]
fn linux_syscall_access(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_access");
    0
}

fn linux_syscall_mmap(args: SyscallArgs) -> usize {
    let [va, len, prot, flags, fd, offset] = args;
    assert!(is_aligned_4k(va));
    info!(
        "###### mmap!!! va:{:#x} len:{:#x} prot:{:#x} flags:{:#x} fd:{:#x} offset:{:#x}",
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
    let [buf, len, flags, ..] = args;
    warn!(
        "impl linux_syscall_getrandom buf {:#X}, len {} flags {:#X}",
        buf, len, flags
    );
    0
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
    let [how, set, oldset, sigsetsize, ..] = args;
    warn!(
        "impl linux_syscall_rt_sigprocmask how {} set {:#X} oldset {:#X} size {} tid {}",
        how, set, oldset, sigsetsize, task::current().tid(),
    );
    0
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

fn linux_syscall_getgid(_args: SyscallArgs) -> usize {
    sys::getgid()
}

fn linux_syscall_geteuid(_args: SyscallArgs) -> usize {
    warn!("impl linux_syscall_geteuid");
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
    init_bytes_from_str(&mut uname.nodename[..], "host");
    init_bytes_from_str(&mut uname.domainname[..], "(none)");
    init_bytes_from_str(&mut uname.release[..], "5.9.0-rc4+");
    init_bytes_from_str(
        &mut uname.version[..],
        "#1337 SMP Fri Mar 4 09:36:42 CST 2022",
    );
    init_bytes_from_str(&mut uname.machine[..], "riscv64");

    return 0;
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

fn linux_syscall_getuid(args: SyscallArgs) -> usize {
    return 1;
}

fn linux_syscall_fcntl(args: SyscallArgs) -> usize {
    0
}

#[cfg(target_arch = "x86_64")]
fn linux_syscall_vfork(_args: SyscallArgs) -> usize {
    fork::sys_vfork()
}


pub fn init() {}
