use core::ops::Bound;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec;
use alloc::collections::BTreeMap;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use spin::RwLock;
use axtype::{PAGE_SIZE, PAGE_SHIFT};

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
/// Content stores pages in btreemap:
/// {page_index => content_in_page}
pub struct FileNode {
    content: RwLock<Vec<u8>>,
}

impl FileNode {
    pub(super) const fn new() -> Self {
        Self {
            content: RwLock::new(Vec::new()),
        }
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_file(self.size() as u64, 0))
    }

    fn read_at(&self, _pos: u64, buf: &mut [u8]) -> VfsResult<usize> {
        unimplemented!("read_at");
    }

    fn write_at(&self, _pos: u64, buf: &[u8]) -> VfsResult<usize> {
        unimplemented!("write_at");
    }

    impl_vfs_non_dir_default! {}
}
