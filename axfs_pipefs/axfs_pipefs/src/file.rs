use alloc::vec::Vec;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use spin::RwLock;


pub struct NodeInner {
    content: Vec<u8>,
    i_readcount: usize,
    ino: usize,
    node_attr: VfsNodeAttr,
}

/// The Fifo file node in the Pipe filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FifoNode {
    inner: RwLock<NodeInner>, // use 2 st to pseudo implement VecDeque
}

impl FifoNode {
    pub(super) const fn new(ino:usize) -> Self {
        Self {
            inner: RwLock::new(NodeInner {
                content: Vec::new(),
                ino,
                i_readcount: 0,
                node_attr: VfsNodeAttr::new(axfs_vfs::VfsNodePerm::from_bits_truncate(0o1644),axfs_vfs::VfsNodeType::Fifo,0, 0),
            }),
        }
    }
}

impl VfsNodeOps for FifoNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let mut inner = self.inner.write();
        inner.node_attr.size = inner.content.len() as u64;
        Ok(inner.node_attr)
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
        if inner.content.len() != 0  {
            return Err(axfs_vfs::VfsError::WouldBlock);
        }
        inner.content.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn i_readcount(&self) ->  VfsResult<usize> {
        let inner = self.inner.read();
        Ok(inner.i_readcount)
    }

    fn i_readcount_inc(&self) ->  VfsResult {
        let mut inner = self.inner.write();
        inner.i_readcount += 1;
        Ok(())
    }

    fn i_readcount_dec(&self) ->  VfsResult {
        let mut inner = self.inner.write();
        inner.i_readcount -= 1;
        Ok(())
    }

    fn get_ino(&self) -> VfsResult<usize> {
        let inner = self.inner.read();
        Ok(inner.ino)
    }

    impl_vfs_non_dir_default! {}
}