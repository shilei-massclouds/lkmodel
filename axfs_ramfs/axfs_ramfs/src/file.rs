use alloc::vec::Vec;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use spin::RwLock;

pub struct NodeInner {
    content: Vec<u8>,
    node_attr: VfsNodeAttr,
}

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    inner: RwLock<NodeInner>,
}

impl FileNode {
    pub(super) const fn new() -> Self {
        Self {
            inner: RwLock::new(NodeInner {
                content: Vec::new(),
                node_attr: VfsNodeAttr::new(axfs_vfs::VfsNodePerm::from_bits_truncate(0o1644),axfs_vfs::VfsNodeType::File,0, 0),
            }),
        }
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let mut inner = self.inner.write();
        inner.node_attr.size = inner.content.len() as u64;
        Ok(inner.node_attr.clone())
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let mut inner = self.inner.write();
        if size < inner.content.len() as u64 {
            inner.content.truncate(size as _);
        } else {
            inner.content.resize(size as _, 0);
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let inner = self.inner.read();
        let start = inner.content.len().min(offset as usize);
        let end = inner.content.len().min(offset as usize + buf.len());
        let src = &inner.content[start..end];
        buf[..src.len()].copy_from_slice(src);
        Ok(src.len())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let offset = offset as usize;
        let mut inner = self.inner.write();
        if offset + buf.len() > inner.content.len() {
            inner.content.resize(offset + buf.len(), 0);
        }
        let dst = &mut inner.content[offset..offset + buf.len()];
        dst.copy_from_slice(&buf[..dst.len()]);
        Ok(buf.len())
    }

    impl_vfs_non_dir_default! {}
}

/// The Fifo file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FifoNode {
    inner: RwLock<NodeInner>, // use 2 st to pseudo implement VecDeque
}

impl FifoNode {
    pub(super) const fn new() -> Self {
        Self {
            inner: RwLock::new(NodeInner {
                content: Vec::new(),
                node_attr: VfsNodeAttr::new(axfs_vfs::VfsNodePerm::from_bits_truncate(0o1644),axfs_vfs::VfsNodeType::Fifo,0, 0),
            }),
        }
    }
}

impl VfsNodeOps for FifoNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let mut inner = self.inner.write();
        inner.node_attr.size = inner.content.len() as u64;
        Ok(inner.node_attr.clone())
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let mut inner = self.inner.write();
        if inner.content.len() == 0  {
            return Err(axfs_vfs::VfsError::WouldBlock);
        }
        let size = buf.len().min(inner.content.len());
        let content: Vec<u8> = inner.content.drain(0..size).collect();
        buf[..size].copy_from_slice(&content);
        Ok(size)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let mut inner = self.inner.write();
        inner.content.extend_from_slice(buf);
        Ok(buf.len())
    }

    impl_vfs_non_dir_default! {}
}
