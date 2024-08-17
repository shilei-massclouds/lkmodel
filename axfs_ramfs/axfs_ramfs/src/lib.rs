//! RAM filesystem used by [ArceOS](https://github.com/rcore-os/arceos).
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod dir;
mod file;

#[cfg(test)]
mod tests;

pub use self::dir::DirNode;
pub use self::file::FileNode;

use alloc::sync::Arc;
use axfs_vfs::FileSystemInfo;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};
use spin::once::Once;

const RAMFS_MAGIC: u64 = 0x858458f6;

/// A RAM filesystem that implements [`axfs_vfs::VfsOps`].
pub struct RamFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
    filesystem_info: FileSystemInfo,
}

impl RamFileSystem {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            parent: Once::new(),
            root: DirNode::new(None),
            // TODO: implement left field
            filesystem_info: FileSystemInfo {
                f_type: RAMFS_MAGIC,
                f_bsize: 4096,
                ..Default::default()
            },
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
        Ok(self.filesystem_info.clone())
    }
}

impl Default for RamFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
