/// Todo: Extract proc_ops as standalone component.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::format;
use axfs_vfs::VfsNodeOps;
use axfs_vfs::VfsNodeAttr;
use axfs_vfs::VfsNodePerm;
use axfs_vfs::VfsResult;
use axfs_vfs::VfsNodeType;
use axerrno::AxResult;
use axerrno::AxError::NotFound;
use axfile::fops::File;
use crate::OpenOptions;
use mm::{VM_READ, VM_WRITE, VM_EXEC, VM_MAYSHARE};
use core::cmp::min;
use axfs_vfs::alloc_ino;

struct ProcNode {
    path: String,
    ino: usize,
}

impl ProcNode {
    pub fn new(path: String) -> Self {
        Self {
            path,
            ino: alloc_ino(),
        }
    }
}

impl VfsNodeOps for ProcNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        error!("VfsNode get_attr: {}", self.path);
        let perm = VfsNodePerm::from_bits_truncate(0o755);
        Ok(VfsNodeAttr::new(perm, VfsNodeType::File, 0, 0, 0, 0))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let offset: usize = offset as usize;
        match self.path.as_str() {
            "/proc/self/status" => {
                let mm = task::current().mm();
                let locked_mm = mm.lock();
                let src = format!("VmLck:\t       {} kB\n\0",
                    locked_mm.locked_vm << 2);
                let src = src.as_bytes();
                let src = &src[offset..];
                buf[..src.len()].copy_from_slice(src);
                return Ok(buf.len());
            },
            "/proc/self/maps" => {
                handle_maps(offset, buf)
            },
            "/proc/self/pagemap" => {
                handle_pagemap(offset, buf)
            },
            _ => unimplemented!("openat path {}", self.path),
        }
    }
}

fn handle_pagemap(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
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

fn handle_maps(offset: usize, buf: &mut [u8]) -> VfsResult<usize> {
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

pub fn open(path: &str, opts: &OpenOptions) -> AxResult<File> {
    if path == "/proc/stat" {
        return Err(NotFound);
    }
    if path.ends_with("oom_score_adj") {
        return Err(NotFound);
    }

    // Todo: handle self and [pid]
    let node = Arc::new(ProcNode::new(String::from(path)));
    Ok(File::new(node, opts.into()))
}
