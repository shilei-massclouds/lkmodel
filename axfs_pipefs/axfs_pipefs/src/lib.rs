//! PIPE filesystem 
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod file;


pub use self::file::FifoNode;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use lazy_init::LazyInit;
use axfs_vfs::FileSystemInfo;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};
use core::sync::atomic::{AtomicUsize,Ordering};

static NEXT_INO: AtomicUsize = AtomicUsize::new(0);

fn alloc_ino() -> usize {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

static PIPE_FS: LazyInit<Arc<PipeFileSystem>> = LazyInit::new();

pub struct PipeFileSystem{
    fifo_mp: BTreeMap<usize,Arc<FifoNode>>, // ino -> node for fifo but not pipe
    filesystem_info: FileSystemInfo,
}

impl PipeFileSystem {
    pub fn new() -> Self {
        Self {
            fifo_mp: BTreeMap::new(),
            filesystem_info: FileSystemInfo {
                f_type: 0,
                f_bsize: 4096,
                ..Default::default()
            },
        }
    }
}

/// A PieFileSystem filesystem that implements [`axfs_vfs::VfsOps`].
impl VfsOps for PipeFileSystem {
    fn mount(&self, _path: &str, _mount_point: VfsNodeRef) -> VfsResult {
        Ok(())
    }

    fn root_dir(&self) -> VfsNodeRef {
        unimplemented!()
    }

    fn statfs(&self) -> VfsResult<FileSystemInfo> {
        Ok(self.filesystem_info)
    }
}

impl Default for PipeFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

pub fn init() {
    PIPE_FS.init_by(Arc::new(PipeFileSystem::new()));
}

pub fn is_pipe(ino: usize) -> bool {
    !PIPE_FS.fifo_mp.contains_key(&ino)
}

pub fn get_fifo_inode() -> VfsNodeRef {
    unimplemented!()
}

pub fn get_pipe_inode() -> VfsNodeRef {
    Arc::new(FifoNode::new(alloc_ino()))
}