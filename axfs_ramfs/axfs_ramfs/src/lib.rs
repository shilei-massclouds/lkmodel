//! RAM filesystem used by [ArceOS](https://github.com/rcore-os/arceos).
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;

mod dir;
mod file;

#[cfg(test)]
mod tests;

pub use self::dir::DirNode;
pub use self::file::FileNode;

use alloc::sync::Arc;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult, FileSystemInfo};
use spin::once::Once;
use axtype::PAGE_SIZE;

const RAMFS_MAGIC: u64 = 0x858458f6;

/// A RAM filesystem that implements [`axfs_vfs::VfsOps`].
pub struct RamFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl RamFileSystem {
    /// Create a new instance.
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            parent: Once::new(),
            root: DirNode::new(None, uid, gid),
        }
    }

    /// Returns the root directory node in [`Arc<DirNode>`](DirNode).
    pub fn root_dir_node(&self) -> Arc<DirNode> {
        self.root.clone()
    }
}

impl VfsOps for RamFileSystem {
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
            f_type: RAMFS_MAGIC,
            f_bsize: PAGE_SIZE as u64,
            ..Default::default()
        };
        Ok(info)
    }
}

impl Default for RamFileSystem {
    fn default() -> Self {
        Self::new(0, 0)
    }
}
