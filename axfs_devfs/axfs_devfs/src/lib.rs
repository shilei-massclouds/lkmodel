//! Device filesystem used by [ArceOS](https://github.com/rcore-os/arceos).
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;
#[macro_use]
extern crate log;

mod dir;
mod null;
mod zero;
mod console;

#[cfg(test)]
mod tests;

pub use self::dir::DirNode;
pub use self::null::NullDev;
pub use self::zero::ZeroDev;
pub use self::console::ConsoleDev;

use alloc::sync::Arc;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};
use spin::once::Once;

/// A device filesystem that implements [`axfs_vfs::VfsOps`].
pub struct DeviceFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl DeviceFileSystem {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            parent: Once::new(),
            root: DirNode::new(None, 0, 0),
        }
    }

    /// Create a subdirectory at the root directory.
    pub fn mkdir(&self, name: &str, uid: u32, gid: u32) -> Arc<DirNode> {
        self.root.mkdir(name, uid, gid)
    }

    /// Add a node to the root directory.
    ///
    /// The node must implement [`axfs_vfs::VfsNodeOps`], and be wrapped in [`Arc`].
    pub fn add(&self, name: &str, node: VfsNodeRef) {
        self.root.add(name, node);
    }
}

impl VfsOps for DeviceFileSystem {
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

impl Default for DeviceFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
