#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

mod proc_ops;

use axerrno::AxResult;
use axerrno::{LinuxError, LinuxResult, linux_err, linux_err_from};
use axerrno::AxError::NotFound;
use axfile::api::create_dir;
use axfile::fops::File;
use axfile::fops::OpenOptions;
use mutex::Mutex;
use axtype::get_user_str;
use axio::SeekFrom;

pub type FileRef = Arc<Mutex<File>>;

// Special value used to indicate openat should use
// the current working directory.
pub const AT_FDCWD: usize = -100isize as usize;
pub const AT_EMPTY_PATH: usize = 0x1000;

const SEEK_SET: usize = 0;
const SEEK_CUR: usize = 1;
const SEEK_END: usize = 2;

const O_CREAT: usize = 0o100;

// dup
const F_DUPFD: usize = 0;

pub fn openat(dfd: usize, filename: &str, flags: usize, mode: usize) -> AxResult<File> {
    info!(
        "openat '{}' at dfd {:#X} flags {:#X} mode {:#X}",
        filename, dfd, flags, mode
    );

    let mut opts = OpenOptions::new();
    opts.read(true);
    if (flags & O_CREAT) != 0 {
        opts.write(true);
        opts.create(true);
        opts.truncate(true);
    }

    let current = task::current();
    let fs = current.fs.lock();

    let path = handle_path(dfd, filename);
    error!("openat path {}", path);
    File::open(&path, &opts, &fs).or_else(|e| {
        if e == NotFound {
            // Handle special filesystem, e.g., procfs, sysfs ..
            special_open(&path, &opts)
        } else {
            Err(e)
        }
    })
}

pub fn special_open(path: &str, opts: &OpenOptions) -> AxResult<File> {
    if path.starts_with("/proc") {
        return proc_ops::open(path, opts);
    }
    Err(NotFound)
}

pub fn register_file(file: AxResult<File>) -> usize {
    let file = match file {
        Ok(f) => f,
        Err(e) => {
            return linux_err_from!(e);
        }
    };
    let current = task::current();
    let fd = current.filetable.lock().insert(Arc::new(Mutex::new(file)));
    info!("openat fd {}", fd);
    fd
}

pub fn unregister_file(fd: usize) {
    let current = task::current();
    current.filetable.lock().remove(fd);
}

fn handle_path(dfd: usize, filename: &str) -> String {
    // Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd).
    if filename.starts_with("/") {
        return String::from(filename);
    }

    if dfd == AT_FDCWD {
        let cwd = _getcwd();
        if cwd == "/" {
            assert!(filename.starts_with("/"));
        } else {
            return cwd + filename;
        }
    }
    String::from(filename)
}

pub fn read(fd: usize, ubuf: &mut [u8]) -> usize {
    info!("read ... fd {}", fd);
    if fd == 0 {
        return read_from_stdio(ubuf);
    }

    let count = ubuf.len();
    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();

    let mut kbuf = vec![0u8; count];
    let mut pos = 0;
    while pos < count {
        let ret = file.lock().read(&mut kbuf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }

    info!(
        "linux_syscall_read: fd {}, count {}, ret {}",
        fd, count, pos
    );

    ubuf.copy_from_slice(&kbuf);
    pos
}

pub fn pread64(fd: usize, ubuf: &mut [u8], offset: usize) -> usize {
    info!("pread64: fd {} len {} offset {}", fd, ubuf.len(), offset);
    let pos = lseek(fd, offset, SEEK_SET);
    assert_eq!(pos, offset);
    read(fd, ubuf)
}

pub fn write(fd: usize, ubuf: &[u8]) -> usize {
    if fd == 1 || fd == 2 {
        return write_to_stdio(ubuf);
    }

    let count = ubuf.len();
    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();

    let mut kbuf = vec![0u8; count];
    kbuf.copy_from_slice(ubuf);

    let mut pos = 0;
    while pos < count {
        let ret = file.lock().write(&kbuf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    info!("write: fd {}, count {}, ret {}", fd, count, pos);
    pos
}

fn write_to_stdio(ubuf: &[u8]) -> usize {
    axhal::console::write_bytes(ubuf);
    ubuf.len()
}

fn read_from_stdio(ubuf: &mut [u8]) -> usize {
    assert!(ubuf.len() > 0);

    // try until we got something
    let mut index = 0;
    while index < ubuf.len() {
        if let Some(c) = axhal::console::getchar() {
            let c = if c == b'\r' { b'\n' } else { c };
            axhal::console::putchar(c);
            ubuf[index] = c;
            index += 1;
            if c == b'\n' {
                break;
            }
        } else {
            task::yield_now();
        }
    }
    index
}

#[derive(Debug)]
#[repr(C)]
pub struct iovec {
    iov_base: usize,
    iov_len: usize,
}

pub fn writev(fd: usize, iov_array: &[iovec]) -> usize {
    assert!(fd == 1 || fd == 2);
    for iov in iov_array {
        debug!("iov: {:#X} {:#X}", iov.iov_base, iov.iov_len);
        let bytes = unsafe { core::slice::from_raw_parts(iov.iov_base as *const _, iov.iov_len) };
        let s = String::from_utf8(bytes.into());
        error!("{}", s.unwrap());
    }
    iov_array.len()
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KernelStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub _pad0: u64,
    pub st_size: u64,
    pub st_blksize: u32,
    pub _pad1: u32,
    pub st_blocks: u64,
    pub st_atime_sec: isize,
    pub st_atime_nsec: isize,
    pub st_mtime_sec: isize,
    pub st_mtime_nsec: isize,
    pub st_ctime_sec: isize,
    pub st_ctime_nsec: isize,
}

pub fn fstat(fd: usize, statbuf_ptr: usize) -> usize {
    let statbuf = statbuf_ptr as *mut KernelStat;
    if fd == 1 {
        return fstatat_stdio(fd, 0, statbuf, 0);
    }
    assert!(fd > 2);

    let current = task::current();
    let filetable = current.filetable.lock();
    let file = match filetable.get_file(fd) {
        Some(f) => f,
        None => {
            return (-2isize) as usize;
        }
    };
    let locked_file = file.lock();
    let metadata = locked_file.get_attr().unwrap();
    let ino = locked_file.ino;
    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    let st_size = metadata.size();

    unsafe {
        *statbuf = KernelStat {
            st_ino: ino as u64,
            st_nlink: 1,
            st_mode,
            st_uid: 1000,
            st_gid: 1000,
            st_size: st_size,
            st_blocks: metadata.blocks() as _,
            st_blksize: 512,
            ..Default::default()
        };
    }
    0
}

pub fn fstatat(dfd: usize, path: usize, statbuf_ptr: usize, flags: usize) -> usize {
    let statbuf = statbuf_ptr as *mut KernelStat;

    if dfd == 1 {
        return fstatat_stdio(dfd, path, statbuf, flags);
    }
    assert!(dfd > 2);

    info!("fstatat dfd {:#x} flags {:#x}", dfd, flags);
    let (metadata, ino) = if (flags & AT_EMPTY_PATH) == 0 {
        let path = get_user_str(path);
        warn!("!!! NON-EMPTY for path: {}\n", path);
        match openat(dfd, &path, flags, 0) {
            Ok(file) => {
                (file.get_attr().unwrap(), file.ino)
            },
            Err(e) => {
                return linux_err_from!(e);
            }
        }
    } else {
        let current = task::current();
        let filetable = current.filetable.lock();
        let file = match filetable.get_file(dfd) {
            Some(f) => f,
            None => {
                return (-2isize) as usize;
            }
        };
        let locked_file = file.lock();
        (locked_file.get_attr().unwrap(), locked_file.ino)
    };

    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    let st_size = metadata.size();
    warn!("st_size: {}", st_size);

    unsafe {
        *statbuf = KernelStat {
            st_ino: ino as u64,
            st_nlink: 1,
            st_mode,
            st_uid: 1000,
            st_gid: 1000,
            st_size: st_size,
            st_blocks: metadata.blocks() as _,
            st_blksize: 512,
            ..Default::default()
        };
    }
    0
}

fn fstatat_stdio(_dfd: usize, _path: usize, statbuf: *mut KernelStat, _flags: usize) -> usize {
    // Todo: Handle stdin(0), stdout(1) and stderr(2)
    unsafe {
        *statbuf = KernelStat {
            st_mode: 0x2180,
            st_nlink: 1,
            st_blksize: 0x1000,
            st_ino: 0x2a,
            st_dev: 2,
            st_rdev: 0x500001,
            st_size: 0,
            st_blocks: 0,
            //st_uid: 1000,
            //st_gid: 1000,
            ..Default::default()
        };
    }
    return 0;
}

// IOCTL
const TCGETS: usize = 0x5401;

const NCCS: usize = 19;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
struct Termios {
    c_iflag: u32,     /* input mode flags */
    c_oflag: u32,     /* output mode flags */
    c_cflag: u32,     /* control mode flags */
    c_lflag: u32,     /* local mode flags */
    c_line: u8,       /* line discipline */
    c_cc: [u8; NCCS], /* control characters */
}

pub fn ioctl(fd: usize, request: usize, udata: usize) -> usize {
    info!(
        "linux_syscall_ioctl fd {}, request {:#X}, udata {:#X}",
        fd, request, udata
    );

    if fd != 0 && fd != 1 && fd != 2 {
        return usize::MAX;
    }

    assert!(fd == 0 || fd == 1 || fd == 2);
    if request != TCGETS {
        return usize::MAX;
    }
    assert_eq!(request, TCGETS);

    let cc: [u8; NCCS] = [
        0x3, 0x1c, 0x7f, 0x15, 0x4, 0x0, 0x1, 0x0, 0x11, 0x13, 0x1a, 0x0, 0x12, 0xf, 0x17, 0x16,
        0x0, 0x0, 0x0,
    ];

    let ubuf = udata as *mut Termios;
    unsafe {
        *ubuf = Termios {
            c_iflag: 0x500,
            c_oflag: 0x5,
            c_cflag: 0xcbd,
            c_lflag: 0x8a3b,
            c_line: 0,
            c_cc: cc,
        };
    }
    0
}

pub fn mkdirat(dfd: usize, pathname: &str, mode: usize) -> usize {
    info!(
        "mkdirat: dfd {:#X}, pathname {}, mode {:#X}",
        dfd, pathname, mode
    );
    assert_eq!(dfd, AT_FDCWD);

    let current = task::current();
    let fs = current.fs.lock();
    match create_dir(pathname, &fs) {
        Ok(()) => 0,
        Err(e) => linux_err_from!(e),
    }
}

pub fn getcwd(buf: &mut [u8]) -> usize {
    let cwd = _getcwd();
    info!("getcwd {}", cwd);
    let bytes = cwd.as_bytes();
    let count = bytes.len();
    buf[0..count].copy_from_slice(bytes);
    buf[count] = 0u8;
    count + 1
}

fn _getcwd() -> String {
    let current = task::current();
    let fs = current.fs.lock();
    fs.current_dir().expect("bad cwd")
}

pub fn chdir(path: &str) -> usize {
    let current = task::current();
    info!("===========> chdir: {}", path);
    let mut fs = current.fs.lock();
    match fs.set_current_dir(path) {
        Ok(()) => 0,
        Err(e) => linux_err_from!(e),
    }
}

pub fn lseek(fd: usize, offset: usize, whence: usize) -> usize {
    info!("lseek: fd: {} offset: {} whence: {}", fd, offset, whence);

    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();

    let pos = match whence {
        SEEK_SET => file.lock().seek(SeekFrom::Start(offset as u64)),
        SEEK_CUR => file.lock().seek(SeekFrom::Current(offset as i64)),
        SEEK_END => file.lock().seek(SeekFrom::End(offset as i64)),
        _ => return linux_err!(EINVAL),
    };

    if let Ok(pos) = pos {
        pos as usize
    } else {
        linux_err!(EINVAL)
    }
}

pub fn ftruncate(fd: usize, length: usize) -> usize {
    info!("ftruncate: fd: {} length: {}", fd, length);

    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();
    file.lock().truncate(length as u64).unwrap_or_else(|e| {
        panic!("ftruncate err: {:?}", e);
    });
    0
}

pub fn do_open(filename: &str, _flags: usize) -> LinuxResult<FileRef> {
    info!("do_open path {}", filename);

    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let file = File::open(filename, &opts, &fs)?;
    Ok(Arc::new(Mutex::new(file)))
}

pub fn fcntl(fd: usize, cmd: usize, udata: usize) -> usize {
    //assert_eq!(F_DUPFD, cmd);
    if cmd != F_DUPFD {
        warn!("implement fcntl cmd [{}]", cmd);
        return 0;
    }

    let cur = task::current();
    let mut locked_fdt = cur.filetable.lock();
    let new_fd = locked_fdt.alloc_fd(udata);
    //let file = locked_fdt.get_file(fd).unwrap();
    //locked_fdt.fd_install(new_fd, file.clone());
    //unimplemented!("fcntl: fd {}-{} cmd {} udata {}", fd, new_fd, cmd, udata);
    info!("fcntl: fd {}-{} cmd {} udata {}", fd, new_fd, cmd, udata);
    new_fd
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();
    info!("Initialize file ops ...");

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init(cpu_id, dtb_pa);
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);

    /*
    axmount::init(cpu_id, dtb_pa);
    let root_dir = axmount::init_root();
    task::current().fs.lock().init(root_dir);
    */
}
