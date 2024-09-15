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
pub use self::file::FileNode;

use core::cmp::min;
use alloc::format;
use alloc::sync::Arc;
use alloc::string::String;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult, FileSystemInfo};
use axfs_vfs::{VfsError, VfsNodeType};
use spin::once::Once;
use axtype::PAGE_SIZE;
use mm::{VM_READ, VM_WRITE, VM_EXEC, VM_MAYSHARE};
use axfile::fops::File;
use axfile::fops::OpenOptions;

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
            root: DirNode::new(None, uid, gid, mode),
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
            VfsNodeType::File => Ok(Arc::new(FileNode::new(None, uid, gid, mode))),
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

    let f_status = FileNode::new(Some(read_status), uid, gid, mode);
    d_self.link_child("status", Arc::new(f_status))?;

    let f_maps = FileNode::new(Some(read_maps), uid, gid, mode);
    d_self.link_child("maps", Arc::new(f_maps))?;

    let f_pagemap = FileNode::new(Some(read_pagemap), uid, gid, mode);
    d_self.link_child("pagemap", Arc::new(f_pagemap))?;

    //
    // Group '/proc/mounts'
    //
    let f_mounts = FileNode::new(Some(read_mounts), uid, gid, mode);
    root.link_child("mounts", Arc::new(f_mounts))?;

    // Group /proc/meminfo
    let f_meminfo = FileNode::new(Some(read_meminfo), uid, gid, mode);
    root.link_child("meminfo", Arc::new(f_meminfo))?;

    Ok(Arc::new(fs))
}

fn read_meminfo(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
    let src = "MemAvailable: 100000 kB\nSwapFree: 100000 kB\n\0";
    let src = src.as_bytes();
    let src: &[u8] = &src[offset..];
    buf[..src.len()].copy_from_slice(src);
    Ok(buf.len())
}

fn read_status(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let src = format!("VmLck:\t       {} kB\n\0",
        locked_mm.locked_vm << 2);
    let src = src.as_bytes();
    let src: &[u8] = &src[offset..];
    buf[..src.len()].copy_from_slice(src);
    Ok(buf.len())
}

fn read_maps(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
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

fn read_pagemap(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
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

fn read_mounts(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
    // Todo: handle offset properly!
    if offset != 0 {
        return Ok(0);
    }
    kernel_read("/etc/fstab", buf)
}

fn kernel_read(filename: &str, buf: &mut [u8]) -> VfsResult<usize> {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let fsuid = current.fsuid();
    let fsgid = current.fsgid();
    let mut file = File::open(filename, &opts, &fs, fsuid, fsgid)?;
    file.read(buf)
}
