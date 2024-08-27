///
/// Linux syscall
///

pub const LINUX_SYSCALL_READ: usize = 0x0;
pub const LINUX_SYSCALL_WRITE: usize = 0x1;
pub const LINUX_SYSCALL_CLOSE: usize = 0x3;
pub const LINUX_SYSCALL_LSEEK: usize = 8;
pub const LINUX_SYSCALL_MMAP: usize = 0x9;
pub const LINUX_SYSCALL_MPROTECT: usize = 0xa;
pub const LINUX_SYSCALL_BRK: usize = 0xc;
pub const LINUX_SYSCALL_ACCESS: usize = 0x15;
pub const LINUX_SYSCALL_EXIT: usize = 0x3c;
pub const LINUX_SYSCALL_UNAME: usize = 0x3f;
pub const LINUX_SYSCALL_PREAD64: usize = 17;
pub const LINUX_SYSCALL_DUP: usize = 32;
pub const LINUX_SYSCALL_DUP3: usize = 292;

pub const LINUX_SYSCALL_ARCH_PRCTL: usize = 0x9e;
pub const LINUX_SYSCALL_SET_TID_ADDRESS: usize = 0xda;
pub const LINUX_SYSCALL_CLOCK_GETTIME: usize = 0xe4;
pub const LINUX_SYSCALL_EXIT_GROUP: usize = 0xe7;
pub const LINUX_SYSCALL_OPENAT: usize = 0x101;
pub const LINUX_SYSCALL_FSTATAT: usize = 0x106;
pub const LINUX_SYSCALL_SET_ROBUST_LIST: usize = 0x111;
pub const LINUX_SYSCALL_PRLIMIT64: usize = 0x12e;
pub const LINUX_SYSCALL_GETRANDOM: usize = 0x13e;
pub const LINUX_SYSCALL_RSEQ: usize = 0x14e;

pub const LINUX_SYSCALL_IOCTL: usize = 16;
pub const LINUX_SYSCALL_FCNTL: usize = 72;
pub const LINUX_SYSCALL_FTRUNCATE: usize = 77;
pub const LINUX_SYSCALL_GETCWD: usize = 79;
pub const LINUX_SYSCALL_CHDIR: usize = 80;
pub const LINUX_SYSCALL_FACCESSAT: usize = 269;
pub const LINUX_SYSCALL_TGKILL: usize = 234;
pub const LINUX_SYSCALL_GETPID: usize = 39;
pub const LINUX_SYSCALL_GETPPID: usize = 110;
pub const LINUX_SYSCALL_GETGID: usize = 104;
pub const LINUX_SYSCALL_GETUID: usize = 102;
pub const LINUX_SYSCALL_GETEUID: usize = 107;
pub const LINUX_SYSCALL_GETEGID: usize = 108;
pub const LINUX_SYSCALL_GETTID: usize = 186;

pub const LINUX_SYSCALL_FCHMOD: usize = 91;
pub const LINUX_SYSCALL_FCHMODAT: usize = 268;
pub const LINUX_SYSCALL_FCHOWNAT: usize = 260;

pub const LINUX_SYSCALL_CAPGET: usize = 125;

//pub const LINUX_SYSCALL_GETDENTS64: usize = 0x3d;
pub const LINUX_SYSCALL_MKDIRAT: usize = 258;
pub const LINUX_SYSCALL_UNLINKAT: usize = 263;
pub const LINUX_SYSCALL_WRITEV: usize = 20;
pub const LINUX_SYSCALL_READLINKAT: usize = 267;
pub const LINUX_SYSCALL_MUNMAP: usize = 11;
pub const LINUX_SYSCALL_MSYNC: usize = 26;
pub const LINUX_SYSCALL_MADVISE: usize = 28;
pub const LINUX_SYSCALL_SENDFILE: usize = 40;

pub const LINUX_SYSCALL_RT_SIGACTION: usize = 13;
pub const LINUX_SYSCALL_RT_SIGPROCMASK: usize = 14;
pub const LINUX_SYSCALL_RT_SIGRETURN: usize = 15;
pub const LINUX_SYSCALL_CLONE: usize = 56;
pub const LINUX_SYSCALL_EXECVE: usize = 59;
pub const LINUX_SYSCALL_SCHED_GETAFFINITY: usize = 204;
pub const LINUX_SYSCALL_SETITIMER: usize = 38;
pub const LINUX_SYSCALL_WAIT4: usize = 61;
pub const LINUX_SYSCALL_KILL: usize = 62;
pub const LINUX_SYSCALL_SETPGID: usize = 109;
pub const LINUX_SYSCALL_VFORK: usize = 58;
pub const LINUX_SYSCALL_CLOCK_NANOSLEEP: usize = 230;
pub const LINUX_SYSCALL_MOUNT: usize = 165;
pub const LINUX_SYSCALL_FUTEX: usize = 202;
