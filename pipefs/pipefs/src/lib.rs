//! Pipe filesystem.
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

mod file;

pub use self::file::PipeNode;

/*
pub use self::dir::DirNode;
pub use self::file::FileNode;

use alloc::sync::Arc;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};
use spin::once::Once;

/// A Pipe filesystem that implements [`axfs_vfs::VfsOps`].
pub struct PipeFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl PipeFileSystem {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            parent: Once::new(),
            root: DirNode::new(None),
        }
    }

    /// Returns the root directory node in [`Arc<DirNode>`](DirNode).
    pub fn root_dir_node(&self) -> Arc<DirNode> {
        self.root.clone()
    }
}

impl VfsOps for PipeFileSystem {
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
}

impl Default for PipeFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
*/
