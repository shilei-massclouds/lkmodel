///
/// Linux syscall
///

pub const LINUX_SYSCALL_GETCWD: usize = 0x11;
pub const LINUX_SYSCALL_DUP: usize = 0x17;
pub const LINUX_SYSCALL_FCNTL: usize = 0x19;
pub const LINUX_SYSCALL_IOCTL: usize = 0x1d;
pub const LINUX_SYSCALL_MKDIRAT: usize = 0x22;
pub const LINUX_SYSCALL_UNLINKAT: usize = 0x23;
pub const LINUX_SYSCALL_FTRUNCATE: usize = 0x2e;
pub const LINUX_SYSCALL_FACCESSAT: usize = 0x30;
pub const LINUX_SYSCALL_CHDIR: usize = 0x31;
pub const LINUX_SYSCALL_FCHMOD: usize = 0x34;
pub const LINUX_SYSCALL_FCHMODAT: usize = 0x35;
pub const LINUX_SYSCALL_FCHOWNAT: usize = 0x36;
pub const LINUX_SYSCALL_OPENAT: usize = 0x38;
pub const LINUX_SYSCALL_CLOSE: usize = 0x39;
pub const LINUX_SYSCALL_GETDENTS64: usize = 0x3d;
pub const LINUX_SYSCALL_LSEEK: usize = 0x3e;
pub const LINUX_SYSCALL_READ: usize = 0x3f;
pub const LINUX_SYSCALL_PREAD64: usize = 67;
pub const LINUX_SYSCALL_WRITE: usize = 0x40;
pub const LINUX_SYSCALL_WRITEV: usize = 0x42;
pub const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
pub const LINUX_SYSCALL_FSTATAT: usize = 0x4f;
pub const LINUX_SYSCALL_CAPGET: usize = 0x5a;
pub const LINUX_SYSCALL_EXIT: usize = 0x5d;
pub const LINUX_SYSCALL_EXIT_GROUP: usize = 0x5e;
pub const LINUX_SYSCALL_SETITIMER: usize = 0x67;
pub const LINUX_SYSCALL_TGKILL: usize = 0x83;
pub const LINUX_SYSCALL_RT_SIGRETURN: usize = 0x8b;
pub const LINUX_SYSCALL_SETPGID: usize = 0x9a;
pub const LINUX_SYSCALL_UNAME: usize = 0xa0;
pub const LINUX_SYSCALL_GETPID: usize = 0xac;
pub const LINUX_SYSCALL_GETPPID: usize = 0xad;
pub const LINUX_SYSCALL_GETUID: usize = 0xae;
pub const LINUX_SYSCALL_GETEUID: usize = 0xaf;
pub const LINUX_SYSCALL_GETGID: usize = 0xb0;
pub const LINUX_SYSCALL_GETEGID: usize = 0xb1;
pub const LINUX_SYSCALL_GETTID: usize = 0xb2;
pub const LINUX_SYSCALL_BRK: usize = 0xd6;
pub const LINUX_SYSCALL_MUNMAP: usize = 0xd7;
pub const LINUX_SYSCALL_CLONE: usize = 0xdc;
pub const LINUX_SYSCALL_EXECVE: usize = 0xdd;
pub const LINUX_SYSCALL_MMAP: usize = 0xde;
pub const LINUX_SYSCALL_MPROTECT: usize = 0xe2;
pub const LINUX_SYSCALL_MSYNC: usize = 0xe3;
pub const LINUX_SYSCALL_MADVISE: usize = 0xe9;
pub const LINUX_SYSCALL_WAIT4: usize = 0x104;
pub const LINUX_SYSCALL_PRLIMIT64: usize = 0x105;
pub const LINUX_SYSCALL_GETRANDOM: usize = 0x116;
pub const LINUX_SYSCALL_RSEQ: usize = 0x125;

pub const LINUX_SYSCALL_SET_TID_ADDRESS: usize = 0x60;
pub const LINUX_SYSCALL_SET_ROBUST_LIST: usize = 0x63;
pub const LINUX_SYSCALL_CLOCK_GETTIME: usize = 0x71;
pub const LINUX_SYSCALL_CLOCK_NANOSLEEP: usize = 0x73;
pub const LINUX_SYSCALL_SCHED_GETAFFINITY: usize = 0x7b;
pub const LINUX_SYSCALL_KILL: usize = 0x81;
pub const LINUX_SYSCALL_RT_SIGACTION: usize = 0x86;
pub const LINUX_SYSCALL_RT_SIGPROCMASK: usize = 0x87;

pub const LINUX_SYSCALL_MOUNT:usize = 0x28;
