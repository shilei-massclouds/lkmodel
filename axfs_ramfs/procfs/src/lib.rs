//! Proc filesystem.
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;

mod dir;
mod file;

pub use self::dir::DirNode;
pub use self::file::{FileNode, SymLinkNode};

use core::mem;
use core::ptr::copy_nonoverlapping;
use core::cmp::min;
use alloc::string::ToString;
use alloc::format;
use alloc::sync::Arc;
use alloc::string::String;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult, FileSystemInfo};
use axfs_vfs::{VfsError, VfsNodeType, VfsNodeOps};
use axfs_vfs::DT_;
use axfs_vfs::LinuxDirent64;
use spin::once::Once;
use axtype::PAGE_SIZE;
use mm::{VM_READ, VM_WRITE, VM_EXEC, VM_MAYSHARE};
use axfile::fops::File;
use axfile::fops::OpenOptions;
use axerrno::AxError::{NotConnected, NotFound};
use axerrno::ax_err;
use axtype::split_path;

const PROC_SUPER_MAGIC: u64 = 0x9fa0;

/// A Proc filesystem that implements [`axfs_vfs::VfsOps`].
pub struct ProcFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl ProcFileSystem {
    /// Create a new instance.
    pub fn new(uid: u32, gid: u32, mode: i32) -> Self {
        Self {
            parent: Once::new(),
            root: DirNode::new(None, uid, gid, mode, Some(lookup_root), None, ""),
        }
    }

    /// Returns the root directory node in [`Arc<DirNode>`](DirNode).
    pub fn root_dir_node(&self) -> Arc<DirNode> {
        self.root.clone()
    }
}

impl VfsOps for ProcFileSystem {
    fn mount(&self, _path: &str, mount_point: VfsNodeRef) -> VfsResult {
        if let Some(parent) = mount_point.parent() {
            self.root.set_parent(Some(self.parent.call_once(|| parent)));
        } else {
            self.root.set_parent(None);
        }
        Ok(())
    }

    fn root_dir(&self) -> VfsNodeRef {
        self.root.clone()
    }

    fn statfs(&self) -> VfsResult<FileSystemInfo> {
        let info = FileSystemInfo {
            f_type: PROC_SUPER_MAGIC,
            f_bsize: PAGE_SIZE as u64,
            ..Default::default()
        };
        Ok(info)
    }

    fn alloc_inode(&self, ty: VfsNodeType, uid: u32, gid: u32, mode: i32) -> VfsResult<VfsNodeRef> {
        match ty {
            VfsNodeType::File => Ok(Arc::new(FileNode::new(None, "", uid, gid, mode))),
            _ => return Err(VfsError::Unsupported),
        }
    }
}

impl Default for ProcFileSystem {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

pub fn init_procfs(uid: u32, gid: u32, mode: i32) -> VfsResult<Arc<ProcFileSystem>> {
    let fs = ProcFileSystem::new(uid, gid, mode);
    let root = fs.root_dir();
    let _ = root.create_child("sys", VfsNodeType::Dir, uid, gid, mode)?;

    //
    // Group '/proc/self'
    //
    let d_self = root.create_child("self", VfsNodeType::Dir, uid, gid, mode)?;

    let f_status = FileNode::new(Some(read_status), "", uid, gid, mode);
    d_self.link_child("status", Arc::new(f_status))?;

    let f_maps = FileNode::new(Some(read_maps), "", uid, gid, mode);
    d_self.link_child("maps", Arc::new(f_maps))?;

    let f_pagemap = FileNode::new(Some(read_pagemap), "", uid, gid, mode);
    d_self.link_child("pagemap", Arc::new(f_pagemap))?;

    let d_fd = DirNode::new(Some(Arc::downgrade(&d_self)), uid, gid, mode, Some(lookup_self_fd), None, "self/fd");
    d_self.link_child("fd", d_fd)?;

    let d_fd_table = DirNode::new(Some(Arc::downgrade(&d_self)), uid, gid, mode, Some(lookup_fd_table), None, "");
    d_self.link_child("_fd", d_fd_table)?;

    //
    // Group '/proc/mounts'
    //
    let f_mounts = FileNode::new(Some(read_mounts), "", uid, gid, mode);
    root.link_child("mounts", Arc::new(f_mounts))?;

    // Group /proc/meminfo
    let f_meminfo = FileNode::new(Some(read_meminfo), "", uid, gid, mode);
    root.link_child("meminfo", Arc::new(f_meminfo))?;

    Ok(Arc::new(fs))
}

fn lookup_root(parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    let (name, rest) = split_path(path);
    error!("lookup_root: path {} name {} rest {:?}", path, name, rest);
    if let Some(node) = parent.children.read().get(name).cloned() {
        return Ok(node);
    }

    // TODO: Handle '/proc/stat'
    if name.starts_with("stat") {
        return ax_err!(NotFound);
    }

    if name.parse::<usize>().is_ok() {
        let parent = Arc::downgrade(&parent);
        let node = DirNode::new(Some(parent), 0, 0, 0o600, Some(lookup_task), None, name);
        return Ok(node);
    }

    panic!("path: {}; name {}; ?digit {:?}", path, name, name.parse::<usize>());
}

fn lookup_self_fd(_parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    assert_eq!(name, "self/fd");
    error!("lookup_self_fd: name {} path {}", name, path);
    let node = SymLinkNode::new(0, 0);
    let linkto = format!("/proc/self/_fd/{}", path);
    node.write_at(0, linkto.as_bytes())?;
    Ok(Arc::new(node))
}

fn lookup_fd_table(_parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    error!("lookup_fd_table: name {} path {}", name, path);
    let fd = path.parse::<usize>().map_err(|_| {
        NotConnected
    })?;
    info!("fd: {}", fd);
    let current = task::current();
    let file = current.filetable.lock().get_file(fd)
        .ok_or(NotConnected)?;
    let node = file.lock().get_node()?;
    info!("lookup_fd_table: fd {}", fd);
    Ok(node)
}

fn lookup_task(parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    error!("lookup_task: name {} path {}", name, path);
    if path == "stat" {
        return lookup_thread(parent, name, path, _flags);
    }
    assert!(path.starts_with("task"));
    let parent = Arc::downgrade(&parent);
    let node = DirNode::new(Some(parent), 0, 0, 0o600, Some(lookup_child), Some(getdents_child), name);
    return Ok(node);
}

fn getdents_child(parent: Arc<DirNode>, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
    error!("getdents {}", parent.get_arg());

    if offset != 0 {
        log::error!("NOTICE! check offset[{}]!", offset);
        return Ok(0);
    }

    static mut INO_SEQ: u64 = 0;

    let pid = parent.get_arg().parse::<usize>()?;
    let task = task::get_task(pid).ok_or(VfsError::NotFound)?;

    let mut count = 0;
    for sibling in task.sched_info.siblings.lock().iter() {
        debug!("sibling [{}]", sibling);
        let mut name: String = sibling.to_string();
        name.push('\0');
        let name_len = name.len();
        info!("name:{:?} [{}] {}", name.as_bytes(), name_len, name.len());

        let entry_size = mem::size_of::<LinuxDirent64>() + name_len;
        info!("entry_size : {}", entry_size);

        if count + entry_size > buf.len() {
            error!("buf for dirents overflow!");
            return Ok(count as usize);
        }

        let dirent: &mut LinuxDirent64 = unsafe {
            mem::transmute(buf.as_mut_ptr().offset(count as isize))
        };
        dirent.d_ino = unsafe { INO_SEQ += 1; INO_SEQ };
        dirent.d_off = (count + entry_size) as i64;
        dirent.d_reclen = entry_size as u16;
        dirent.d_type = DT_::DIR as u8;

        unsafe {
            copy_nonoverlapping(
                name.as_ptr(),
                dirent.d_name.as_mut_ptr(),
                name_len
            )
        };

        count += entry_size;
    }
    Ok(count)
}

fn lookup_child(parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    error!("lookup_child: name {} path {}", name, path);
    let (child, rest) = split_path(path);
    error!("lookup_child: child {} rest {:?}", child, rest);
    let parent = Arc::downgrade(&parent);
    let node = DirNode::new(Some(parent), 0, 0, 0o600, Some(lookup_thread), None, child);
    return Ok(node);
}

fn lookup_thread(parent: Arc<DirNode>, name: &str, path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
    error!("lookup_thread: name {} path {}", name, path);
    let node = match path {
        "stat" => FileNode::new(Some(read_stat), name, 0, 0, 0o600),
        _ => panic!("bad subpath {}", path),
    };
    return Ok(Arc::new(node));
}

fn read_stat(_offset: usize, buf: &mut [u8], arg: &str) -> VfsResult<usize> {
    error!("read_stat: arg {}", arg);
    let pid = arg.parse::<usize>()?;
    let task = task::get_task(pid).ok_or(NotFound)?;
    error!("read_task: pid {} {}", pid, task.linux_state());
    let src = format!("{} (unknown) {}", pid, task.linux_state());
    buf[..src.len()].copy_from_slice(src.as_bytes());
    Ok(buf.len())
}

fn read_meminfo(offset: usize, buf: &mut [u8], _arg: &str) -> VfsResult<usize> {
    let src = "MemAvailable: 100000 kB\nSwapFree: 100000 kB\n\0";
    let src = src.as_bytes();
    let src: &[u8] = &src[offset..];
    buf[..src.len()].copy_from_slice(src);
    Ok(buf.len())
}

fn read_status(offset: usize, buf: &mut [u8], _arg: &str) -> VfsResult<usize> {
    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let src = format!("VmLck:\t       {} kB\n\0",
        locked_mm.locked_vm << 2);
    let src = src.as_bytes();
    let src: &[u8] = &src[offset..];
    buf[..src.len()].copy_from_slice(src);
    Ok(buf.len())
}

fn read_maps(offset: usize, buf: &mut [u8], _arg: &str) -> VfsResult<usize> {
    let mm = task::current().mm();
    let locked_mm = mm.lock();

    let mut src = String::from("");
    locked_mm.vmas.values().for_each(|vma| {
        let r = if (vma.vm_flags & VM_READ) != 0 { "r" } else { "-" };
        let w = if (vma.vm_flags & VM_WRITE) != 0 { "w" } else { "-" };
        let x = if (vma.vm_flags & VM_EXEC) != 0 { "x" } else { "-" };
        let s = if (vma.vm_flags & VM_MAYSHARE) != 0 { "s" } else { "p" };
        let flags = format!("{}{}{}{}", r, w, x, s);

        src += format!("{:x}-{:x} {} {:x} 00:00 0 []\n",
                vma.vm_start, vma.vm_end,
                flags,
                vma.vm_pgoff,
            ).as_str();
    });

    let src = src.as_bytes();
    if offset >= src.len() {
        return Ok(0);
    }
    let src = &src[offset..];
    error!("offset: {} {}", offset, buf.len());
    let min_size = min(src.len(), buf.len());
    buf[..min_size].copy_from_slice(&src[..min_size]);
    return Ok(buf.len());
}

fn read_pagemap(offset: usize, buf: &mut [u8], _arg: &str) -> VfsResult<usize> {
    assert!(buf.len() == 8);
    let va = (offset >> 3) << 12;

    let mm = task::current().mm();
    let locked_mm = mm.lock();
    if locked_mm.mapped.get(&va).is_some() {
        // Todo: fill pagemap with:
        // Bits 0-54  page frame number (PFN) if present
        // Bits 0-4   swap type if swapped
        // Bits 5-54  swap offset if swapped
        // Bit  55    pte is soft-dirty
        // Bit  56    page exclusively mapped
        // Bit  57    pte is uffd-wp write-protected
        // Bits 58-60 zero
        // Bit  61    page is file-page or shared-anon
        // Bit  62    page swapped
        // Bit  63    page present
        let pm: u64 = 1 << 63;
        buf.copy_from_slice(&pm.to_le_bytes());
    }
    Ok(buf.len())
}

fn read_mounts(offset: usize, buf: &mut [u8], arg: &str) -> VfsResult<usize> {
    // Todo: handle offset properly!
    if offset != 0 {
        return Ok(0);
    }
    kernel_read("/etc/fstab", buf, arg)
}

fn kernel_read(filename: &str, buf: &mut [u8], _arg: &str) -> VfsResult<usize> {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    let mut file = File::open(filename, &opts, &fs, fsuid, fsgid)?;
    file.read(buf)
}
