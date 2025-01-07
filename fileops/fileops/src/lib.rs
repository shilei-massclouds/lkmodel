#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::format;
use core::slice;
use core::cmp::min;
use axtype::{S_IFMT, S_IFREG, S_IFIFO, S_IFCHR};
use axtype::RLIMIT_NOFILE;
use capability::Cap;
use pipefs::PipeNode;
use signal::force_sig_fault;
use axfs_vfs::VfsNodeRef;
use axmount::init_root;
use axfs_vfs::{FileSystemInfo, VfsNodeType, VfsNodeAttrValid, VfsNodeAttr};
use axfs_vfs::path::canonicalize;
use axtype::MAX_LOOP_NUMBER;
use block_loop::{LoopCtlDev, LoopDev};

use axerrno::AxResult;
use axerrno::{LinuxError, LinuxResult, linux_err, linux_err_from};
use axerrno::AxError::BrokenPipe;
use axfile::fops::File;
use axfile::fops::OpenOptions;
use mutex::Mutex;
use axtype::get_user_str;
use axio::SeekFrom;
use axtype::{O_CREAT, O_TRUNC, O_APPEND, O_WRONLY, O_RDWR, O_EXCL, O_NOFOLLOW};
use procfs::init_procfs;

use axtype::__O_TMPFILE;

pub type FileRef = Arc<Mutex<File>>;

// Special value used to indicate openat should use
// the current working directory.
pub const AT_FDCWD: usize       = -100isize as usize;
// Remove directory instead of unlinking file.
pub const AT_REMOVEDIR: usize   = 0x200;
pub const AT_EMPTY_PATH: usize  = 0x1000;

const BLOCK_SIZE: u32 = 4096;

const SEEK_SET: usize = 0;
const SEEK_CUR: usize = 1;
const SEEK_END: usize = 2;

// dup
const F_DUPFD: usize = 0;

pub fn openat(dfd: usize, filename: &str, flags: usize, mode: usize) -> AxResult<File> {
    info!(
        "openat '{}' at dfd {:#X} flags {:#o} mode {:#o}",
        filename, dfd, flags, mode
    );

    let mut opts = OpenOptions::new();
    opts.set_flags(flags as i32);
    opts.set_mode(mode as i32);
    opts.read(true);
    if (flags as i32 & O_CREAT) != 0 {
        opts.write(true);
        opts.truncate(true);
        if (flags as i32 & O_EXCL) != 0 {
            opts.create_new(true);
        } else {
            opts.create(true);
        }
    }
    if (flags as i32 & (O_WRONLY|O_RDWR|O_TRUNC|O_APPEND)) != 0 {
        opts.write(true);
    }
    if (flags as i32 & O_APPEND) != 0 {
        opts.append(true);
    }
    if (flags as i32 & O_TRUNC) != 0 {
        opts.truncate(true);
    }
    if (flags as i32 & O_WRONLY) != 0 {
        opts.read(false);
    }

    let current = task::current();
    let fs = current.fs.lock();

    let fsuid = current.fsuid();
    let fsgid = current.fsgid();

    let path = handle_path(dfd, filename);
    debug!("openat path {} flags", path);

    if (flags as i32 & __O_TMPFILE) != 0 {
        return do_tmpfile(&path, &opts, fsuid, fsgid);
    }

    File::open(&path, &opts, &fs, fsuid, fsgid)
}

fn do_tmpfile(path: &str, opts: &OpenOptions, uid: u32, gid: u32) -> AxResult<File> {
    let root = init_root();
    let (fs, _) = root.lookup_fs(path)?;
    let inode = fs.alloc_inode(VfsNodeType::File, uid, gid, opts.mode())?;
    let cap = Cap::SET_STAT | opts.into();
    Ok(File::new(inode, cap))
}

fn lookup_node(dfd: usize, filename: &str) -> AxResult<VfsNodeRef> {
    let current = task::current();
    let fs = current.fs.lock();
    let path = handle_path(dfd, filename);
    fs.lookup(None, &path, 0)
}

pub fn register_file(file: AxResult<File>, flags: usize) -> usize {
    let file = match file {
        Ok(f) => f,
        Err(e) => {
            debug!("register_file: err {}", linux_err_from!(e) as isize);
            return linux_err_from!(e);
        }
    };
    let current = task::current();
    let nofile = current.rlim[RLIMIT_NOFILE].rlim_cur;
    let fd = current.filetable
        .lock().insert(Arc::new(Mutex::new(file)), flags);
    info!("register fd {}", fd);
    if fd >= nofile as usize {
        return linux_err!(EMFILE);
    }
    fd
}

pub fn unregister_file(fd: usize) -> LinuxResult<Arc<Mutex<File>>> {
    let current = task::current();
    let mut locked_ftable = current.filetable.lock();
    debug!("unregister: fd {}", fd);
    locked_ftable.remove(fd).ok_or(LinuxError::EBADF)
}

fn handle_path(dfd: usize, filename: &str) -> String {
    // Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd).
    if filename.starts_with("/") {
        return String::from(filename);
    }

    if dfd == AT_FDCWD {
        let cwd = _getcwd();
        if cwd == "/" {
            let path = format!("/{}", filename);
            return canonicalize(&path);
        } else {
            return cwd + filename;
        }
    }
    String::from(filename)
}

pub fn read(fd: usize, ubuf: &mut [u8]) -> LinuxResult<usize> {
    info!("read ... fd {}", fd);

    let count = ubuf.len();
    let current = task::current();
    let file = current.filetable.lock().get_file(fd)
        .ok_or(LinuxError::EBADF)?;

    let mut kbuf = vec![0u8; count];
    let pos = file.lock().read(&mut kbuf)?;

    info!(
        "linux_syscall_read: fd {}, count {}, ret {}",
        fd, count, pos
    );

    ubuf.copy_from_slice(&kbuf);
    Ok(pos)
}

pub fn pread64(fd: usize, ubuf: &mut [u8], offset: usize) -> LinuxResult<usize> {
    info!("pread64: fd {} len {} offset {}", fd, ubuf.len(), offset);
    let pos = lseek(fd, offset, SEEK_SET);
    assert_eq!(pos, offset);
    read(fd, ubuf)
}

pub fn write(fd: usize, ubuf: &[u8]) -> LinuxResult<usize> {
    let count = ubuf.len();
    debug!("write: fd {}, count {} ..", fd as i32, count);

    let current = task::current();
    let file = current.filetable.lock().get_file(fd)
        .ok_or(LinuxError::EBADF)?;

    let mut kbuf = vec![0u8; count];
    kbuf.copy_from_slice(ubuf);

    let mut locked_file = file.lock();
    match locked_file.write(&kbuf) {
        Ok(pos) => Ok(pos),
        Err(BrokenPipe) => {
            let tid = current.tid();
            force_sig_fault(tid, task::SIGPIPE, 0, 0);
            Err(LinuxError::EPIPE)
        },
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct iovec {
    iov_base: usize,
    iov_len: usize,
}

pub fn writev(fd: usize, iov_array: &[iovec]) -> usize {
    error!("No implementation of writev!");
    assert!(fd == 1 || fd == 2);
    for iov in iov_array {
        debug!("iov: {:#X} {:#X}", iov.iov_base, iov.iov_len);
        let bytes = unsafe { core::slice::from_raw_parts(iov.iov_base as *const _, iov.iov_len) };
        let s = String::from_utf8(bytes.into());
        debug!("{}", s.unwrap());
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

pub fn faccessat(dfd: usize, path: &str) -> usize {
    match lookup_node(dfd, &path) {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            return linux_err_from!(e);
        }
    }
}

pub fn fchmodat(
    dfd: usize, filename: &str, mode: i32, _flags: usize
) -> LinuxResult<usize> {
    info!(
        "fchmodat dfd {:#X} {} mode {:#o}",
        dfd, filename, mode
    );

    let node = lookup_node(dfd, filename)?;
    let mut attr = VfsNodeAttr::default();
    let valid = VfsNodeAttrValid::ATTR_MODE;
    attr.set_mode(mode);
    node.set_attr(&attr, &valid)?;
    info!("attr {:?} valid {:#x}", node.get_attr()?, valid.bits());
    Ok(0)
}

pub fn fchmod(fd: usize, mode: i32) -> LinuxResult<usize> {
    info!("fchmod fd {:#x} mode {:#o}", fd, mode);
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = match filetable.get_file(fd) {
        Some(f) => f,
        None => {
            return Err(LinuxError::ENOENT);
        }
    };

    let mut attr = VfsNodeAttr::default();
    let valid = VfsNodeAttrValid::ATTR_MODE;
    attr.set_mode(mode);

    let locked_file = file.lock();
    locked_file.set_attr(&attr, &valid)?;
    Ok(0)
}

pub fn fchown(fd: usize, uid: u32, gid: u32) -> LinuxResult<usize> {
    info!("fchown fd {:#X} owner:group {}:{}", fd, uid, gid);
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = match filetable.get_file(fd) {
        Some(f) => f,
        None => {
            return Err(LinuxError::ENOENT);
        }
    };
    let locked_file = file.lock();
    let (attr, valid) = mk_attr(uid, gid);
    locked_file.set_attr(&attr, &valid)?;
    Ok(0)
}

pub fn fchownat(
    dfd: usize, filename: &str, uid: u32, gid: u32, flags: usize
) -> LinuxResult<usize> {
    info!(
        "fchownat dfd {:#X} {} owner:group {}:{} flags {:#X}",
        dfd, filename, uid, gid, flags
    );
    assert_eq!(flags, 0);

    let node = lookup_node(dfd, filename)?;
    let (attr, valid) = mk_attr(uid, gid);
    node.set_attr(&attr, &valid)?;
    info!("attr {:?} valid {:#x}", node.get_attr()?, valid.bits());
    Ok(0)
}

fn mk_attr(uid: u32, gid: u32) -> (VfsNodeAttr, VfsNodeAttrValid) {
    let mut attr = VfsNodeAttr::default();
    let mut valid = VfsNodeAttrValid::empty();
    if uid != u32::MAX {
        valid.insert(VfsNodeAttrValid::ATTR_UID);
        attr.set_uid(uid);
    }
    if gid != u32::MAX {
        valid.insert(VfsNodeAttrValid::ATTR_GID);
        attr.set_gid(gid);
    }
    (attr, valid)
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
    let ino = locked_file.get_ino();
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
        match lookup_node(dfd, &path) {
            Ok(node) => {
                (node.get_attr().unwrap(), node.get_ino())
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
                return linux_err!(ENOENT);
            }
        };
        let locked_file = file.lock();
        (locked_file.get_attr().unwrap(), locked_file.get_ino())
    };

    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let fsuid = metadata.uid();
    let fsgid = metadata.gid();
    let st_mode = ((ty as u32) << 12) | perm;
    let st_size = metadata.size();
    info!("st_mode {:#o} st_size: {}", st_mode, st_size);

    unsafe {
        *statbuf = KernelStat {
            st_ino: ino as u64,
            st_nlink: 1,
            st_mode,
            st_uid: fsuid,
            st_gid: fsgid,
            st_size: st_size,
            st_blocks: metadata.blocks() as _,
            // Todo: get real block_size from dev
            st_blksize: BLOCK_SIZE,
            st_rdev: metadata.rdev() as u64,
            ..Default::default()
        };
    }
    0
}

fn fstatat_stdio(_dfd: usize, path: usize, statbuf: *mut KernelStat, _flags: usize) -> usize {
    let path = get_user_str(path);
    assert_eq!(path, "");
    // Todo: Handle stdin(0), stdout(1) and stderr(2)
    unsafe {
        *statbuf = KernelStat {
            st_mode: 0x2180,
            st_nlink: 1,
            st_blksize: 0x1000,
            st_ino: 22,
            st_dev: 2,
            st_rdev: 0x501,
            st_size: 0,
            st_blocks: 0,
            //st_uid: 1000,
            //st_gid: 1000,
            ..Default::default()
        };
    }
    return 0;
}

pub fn ioctl(fd: usize, request: usize, udata: usize) -> LinuxResult<usize> {
    info!(
        "linux_syscall_ioctl fd {}, request {:#X}, udata {:#X}",
        fd, request, udata
    );


    let current = task::current();
    let file = current.filetable.lock()
        .get_file(fd).ok_or(LinuxError::EBADF)?;

    let ret = file.lock().ioctl(request, udata)?;
    Ok(ret)
}

pub fn mknodat(dfd: usize, filename: &str, mode: usize, dev: usize) -> usize {
    info!(
        "mknodat: dfd {:#x}, filename {}, mode {:#o}, dev {:#x}",
        dfd, filename, mode, dev
    );
    assert_eq!(dfd, AT_FDCWD);

    let path = handle_path(dfd, filename);
    debug!("mknodat: path {}", path);

    let current = task::current();
    let fs = current.fs.lock();

    let fsuid = current.fsuid();
    let fsgid = current.fsgid();

    let mode = mode as i32;
    match mode & S_IFMT {
        S_IFREG => {
            error!("create empty file!");
        },
        S_IFIFO => {
            fs.create_file(None, &path, VfsNodeType::Fifo, fsuid, fsgid, mode).unwrap();
        },
        S_IFCHR => {
            fs.create_file(None, &path, VfsNodeType::CharDevice, fsuid, fsgid, mode).unwrap();
        },
        _ => panic!("unknown mode {:#o}", mode & S_IFMT),
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
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    match fs.create_dir(None, pathname, fsuid, fsgid, mode as i32) {
        Ok(()) => 0,
        Err(e) => linux_err_from!(e),
    }
}

pub fn readlinkat(
    dfd: usize, filename: &str, buf: usize, size: usize
) -> LinuxResult<usize> {
    warn!("!!!TODO!!! readlinkat: dfd {:#x} filename {} bufsize {}", dfd, filename, size);
    let path = handle_path(dfd, filename);

    let current = task::current();
    let fs = current.fs.lock();
    let link = fs.lookup(None, &path, 0)?;

    if !link.get_attr()?.is_symlink() {
        return Err(LinuxError::EINVAL);
    }

    info!("link: type {:?}", link.get_attr()?.file_type());
    let ubuf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut _, size)
    };
    let ret = link.read_at(0, ubuf)?;
    Ok(ret)

    /*
    // Todo: Now just return linkfile's name itself.
    // Todo: Add readlink for each filesystem.
    let ubuf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut _, path.len())
    };
    ubuf.copy_from_slice(path.as_bytes());
    Ok(path.len())
    */
}

pub fn linkat(
    olddfd: usize, oldpath: &str,
    newdfd: usize, newpath: &str,
    flags: usize
) -> LinuxResult<usize> {
    info!("linkat: olddfd {:#x} newdfd {:#x}, oldpath {} newpath {} flags {}",
        olddfd, newdfd, oldpath, newpath, flags);
    let node = lookup_node(olddfd, oldpath)?;
    let newpath = handle_path(newdfd, newpath);

    let current = task::current();
    let fs = current.fs.lock();

    fs.create_link(None, &newpath, node)?;
    Ok(0)
}

pub fn symlinkat(target: &str, newdfd: usize, linkpath: &str) -> usize {
    info!("symlinkat: target {}, newdfd {:#x}, linkpath: {}",
        target, newdfd, linkpath);
    assert_eq!(newdfd, AT_FDCWD);
    let linkpath = handle_path(newdfd, linkpath);
    let current = task::current();
    let fs = current.fs.lock();
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    fs.create_symlink(None, &linkpath, target, fsuid, fsgid, 0o777).unwrap();
    0
}

pub fn unlinkat(dfd: usize, path: &str, flags: usize) -> usize {
    info!("unlinkat: dfd {:#X}, path {}, flags {:#x}", dfd, path, flags);
    assert_eq!(dfd, AT_FDCWD);
    if (flags & !AT_REMOVEDIR) != 0 {
        return linux_err!(EINVAL);
    }

    let current = task::current();
    let fs = current.fs.lock();
    // Todo: distinguish dir&file
    let ty = match filetype(path) {
        Ok(t) => t,
        Err(e) => {
            return linux_err_from!(e);
        }
    };
    if (flags & AT_REMOVEDIR) != 0 {
        if !ty.is_dir() {
            return linux_err!(ENOTDIR);
        }
        match fs.remove_dir(None, path) {
            Ok(()) => 0,
            Err(e) => linux_err_from!(e),
        }
    } else {
        if ty.is_dir() {
            return linux_err!(EISDIR);
        }
        match fs.remove_file(None, path) {
            Ok(()) => 0,
            Err(e) => linux_err_from!(e),
        }
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

pub fn fallocate(fd: usize, mode: usize, offset: usize, len: usize) -> LinuxResult<usize> {
    info!("fallocate: fd {} mode {:#o} offset {:#x}, len {:#x}",
        fd, mode, offset, len);
    assert_eq!(mode, 0);

    let len = offset + len;
    let current = task::current();
    let file = current.filetable.lock().get_file(fd)
        .ok_or(LinuxError::EBADF)?;
    file.lock().truncate(len as u64)?;
    Ok(0)
}

pub fn do_open(filename: &str, flags: i32) -> LinuxResult<FileRef> {
    debug!("do_open path {}", filename);

    let mut opts = OpenOptions::new();
    opts.read(true);
    if (flags & (O_WRONLY|O_RDWR|O_TRUNC|O_APPEND)) != 0 {
        opts.write(true);
    }

    let current = task::current();
    let fs = current.fs.lock();
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    let file = File::open(filename, &opts, &fs, fsuid, fsgid)?;
    Ok(Arc::new(Mutex::new(file)))
}

pub fn filetype(fname: &str) -> LinuxResult<VfsNodeType> {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    // Todo: replace File::open with lookup
    let node = fs.lookup(None, fname, O_NOFOLLOW);
    let metadata = node?.get_attr()?;
    Ok(metadata.file_type())
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
    debug!("fcntl: fd {}-{} cmd {} udata {}", fd, new_fd, cmd, udata);
    let file = locked_fdt.get_file(fd).unwrap();
    locked_fdt.fd_install(new_fd, file.clone());
    new_fd
}

pub fn dup(fd: usize) -> usize {
    info!("dup [{:#x}] ...", fd);
    let cur = task::current();
    let mut locked_fdt = cur.filetable.lock();
    let new_fd = locked_fdt.alloc_fd(fd);
    let file = locked_fdt.get_file(fd).unwrap();
    locked_fdt.fd_install(new_fd, file.clone());
    new_fd
}

pub fn dup3(oldfd: usize, newfd: usize, flags: usize) -> usize {
    assert_eq!(flags, 0);
    info!("dup3 [{:#x}, {:#x}, {:#x}] ...", oldfd, newfd, flags);
    let cur = task::current();
    let mut locked_fdt = cur.filetable.lock();
    let file = locked_fdt.get_file(oldfd).unwrap();
    locked_fdt.fd_install(newfd, file.clone());
    newfd
}

pub fn getdents64(fd: usize, dirp: usize, count: usize) -> usize {
    info!("getdents64 fd {}...", fd);
    let current = task::current();
    let file = current.filetable.lock().get_file(fd).unwrap();
    let mut locked_file = file.lock();

    let mut kbuf = vec![0u8; count];
    let ret = locked_file.getdents(&mut kbuf[..]).unwrap();

    let ubuf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(dirp as *mut _, count)
    };
    ubuf.copy_from_slice(&kbuf);
    info!("getdents64 ret {}...", ret);
    ret
}

pub fn sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> usize {
    info!("sendfile outfd {} infd {} offset {} count {:#x}",
        out_fd, in_fd, offset, count);

    let current = task::current();
    let out_file = current.filetable.lock().get_file(out_fd).unwrap();
    let in_file = current.filetable.lock().get_file(in_fd).unwrap();
    let count = min(file_size(in_file.clone()).unwrap(), count);

    let mut pos = 0;
    while pos < count {
        let size = min(count, 4096);
        let mut kbuf = vec![0u8; size];
        let ret = in_file.lock().read(&mut kbuf).unwrap();
        if ret == 0 {
            return 0;
        }
        assert_eq!(ret, size);

        let ret = out_file.lock().write(&mut kbuf).unwrap();
        assert_eq!(ret, size);

        pos += size;
    }
    pos
}

pub fn statfs(path: &str, buf: usize) -> usize {
    info!("statfs: path {}...", path);
    let current = task::current();
    let fs = current.fs.lock();
    let path = fs.absolute_path(path).unwrap();
    let root = init_root();
    let statbuf = buf as *mut FileSystemInfo;
    unsafe {
        *statbuf = root.statfs(&path).unwrap();
    }
    0
}

pub fn utimensat(dfd: usize, filename: &str, times: usize, flags: usize) -> usize {
    let path = handle_path(dfd, filename);
    error!("utimensat: dfd {:#x} path {} times {} flags {}",
        dfd, path, times, flags);
    error!("utimensat: unimplemented yet!");
    0
}

pub fn pipe2(fds: usize, flags: usize) -> LinuxResult {
    debug!("pipe2: fds {:#x} flags {:#x}", fds, flags);
    let current = task::current();
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    let node = Arc::new(PipeNode::init_pipe_node(fsuid, fsgid));
    let rfile = File::new(node.clone(), Cap::READ);
    let wfile = File::new(node.clone(), Cap::WRITE);
    let rfd = register_file(Ok(rfile), 0) as i32;
    let wfd = register_file(Ok(wfile), 0) as i32;
    assert!(rfd > 0);
    assert!(wfd > 0);
    let fds = fds as *mut i32;
    let fds = unsafe { slice::from_raw_parts_mut(fds, 2) };
    fds[0] = rfd;
    fds[1] = wfd;
    debug!("pipe2 ok! fd0 {:#x} fd1 {:#x}", fds[0], fds[1]);
    Ok(())
}

pub fn mount(fsname: &str, dir: &str, fstype: &str, flags: usize, data: usize) -> LinuxResult<usize> {
    info!("mount: name {} dir {} ty {} flags {:#x} data {:#x}",
        fsname, dir, fstype, flags, data);

    // TODO: Now only handle procfs. Handle other filesystems in future.
    if fstype == "proc" {
        assert_eq!(dir, "/proc");
        assert_eq!(fsname, "proc");
        let uid = 0;
        let gid = 0;
        let mode = 0o777;
        let current = task::current();
        let fs = current.fs.lock();
        let root = fs.root_dir().expect("bad root");
        root.mount(dir, init_procfs(uid, gid, mode).unwrap(), uid, gid)?;
    }
    Ok(0)
}

fn file_size(file: FileRef) -> LinuxResult<usize> {
    let metadata = file.lock().get_attr()?;
    Ok(metadata.size() as usize)
}

// Open /dev/console, for stdin/stdout/stderr, this should never fail
pub fn console_on_rootfs() -> LinuxResult {
    let mut opts = OpenOptions::new();
    opts.read(true);
    opts.write(true);

    let current = task::current();
    let fs = current.fs.lock();
    let console = File::open("/dev/console", &opts, &fs, 0, 0)
        .expect("bad /dev/console");
    let console = Arc::new(Mutex::new(console));

    let stdin = current.filetable.lock().insert(console.clone(), 0);
    info!("Register stdin: fd[{}]", stdin);
    let stdout = current.filetable.lock().insert(console.clone(), 0);
    info!("Register stdout: fd[{}]", stdout);
    let stderr = current.filetable.lock().insert(console.clone(), 0);
    info!("Register stderr: fd[{}]", stderr);
    Ok(())
}

pub fn loop_init() -> LinuxResult {
    let loop_ctl = LoopCtlDev::new();

    let current = task::current();
    let fs = current.fs.lock();
    fs.create_link(None, "/dev/loop-control", Arc::new(loop_ctl))?;

    for i in 0..MAX_LOOP_NUMBER {
        let name = format!("/dev/loop{}", i);
        let loop_dev = LoopDev::new(i);
        fs.create_link(None, &name, Arc::new(loop_dev))?;
    }
    Ok(())
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();
    info!("Initialize file ops ...");

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init();
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);

    /*
    axmount::init(cpu_id, dtb_pa);
    let root_dir = axmount::init_root();
    task::current().fs.lock().init(root_dir);
    */
}
