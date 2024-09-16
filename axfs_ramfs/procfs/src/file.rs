use alloc::vec::Vec;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use spin::RwLock;
use axfs_vfs::alloc_ino;

pub type ReadOp = fn(usize, &mut [u8]) -> VfsResult<usize>;

/// The symlink node in the RAM filesystem.
pub struct SymLinkNode {
    buf: RwLock<Vec<u8>>,
    ino: usize,
    uid: u32,
    gid: u32,
}

impl SymLinkNode {
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            buf: RwLock::new(Vec::new()),
            ino: alloc_ino(),
            uid,
            gid,
        }
    }
}

impl VfsNodeOps for SymLinkNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_symlink(0, 0, self.uid, self.gid))
    }

    fn write_at(&self, pos: u64, buf: &[u8]) -> VfsResult<usize> {
        assert_eq!(pos, 0);
        info!("symlink: {:?}", buf);
        let mut wbuf = self.buf.write();
        for i in 0..buf.len() {
            wbuf.push(buf[i]);
        }
        debug!("===> symlink: {:?} {}", wbuf, wbuf.len());
        Ok(wbuf.len())
    }

    fn read_at(&self, pos: u64, buf: &mut [u8]) -> VfsResult<usize> {
        assert_eq!(pos, 0);
        let rbuf = self.buf.read();
        assert!(buf.len() >= rbuf.len());
        error!("sysmlink:read_at: rbuf len {}", rbuf.len());
        buf[0..rbuf.len()].copy_from_slice(&rbuf);
        Ok(rbuf.len())
    }

    impl_vfs_non_dir_default! {}
}

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
/// Content stores pages in btreemap:
/// {page_index => content_in_page}
pub struct FileNode {
    read_op: ReadOp,
    ino: usize,
    uid: RwLock<u32>,
    gid: RwLock<u32>,
    mode: i32,
}

impl FileNode {
    pub(super) fn new(read_op: Option<ReadOp>, uid: u32, gid: u32, mode: i32) -> Self {
        Self {
            read_op: read_op.unwrap_or(read_op_dummy),
            ino: alloc_ino(),
            uid: RwLock::new(uid),
            gid: RwLock::new(gid),
            mode,
        }
    }
}

impl VfsNodeOps for FileNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_file(0, 0,
            *self.uid.read(), *self.gid.read(), self.mode))
    }

    /*
    fn set_attr(&self, attr: &VfsNodeAttr, valid: &VfsNodeAttrValid) -> VfsResult {
        if valid.contains(VfsNodeAttrValid::ATTR_UID) {
            *self.uid.write() = attr.uid();
        }
        if valid.contains(VfsNodeAttrValid::ATTR_GID) {
            *self.gid.write() = attr.gid();
        }
        Ok(())
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let size = size as usize;
        let index = size >> PAGE_SHIFT;
        let offset = size % PAGE_SIZE;
        if size < self.size() {
            debug!("truncate size: {} < {}", size, self.size());
            let mut remove_keys = vec![];
            {
                let content = self.content.read();
                let mut lower = content.lower_bound(Bound::Excluded(&index));
                loop {
                    if let Some(index) = lower.key() {
                        remove_keys.push(*index);
                    } else {
                        break;
                    }
                    lower.move_next();
                }
            }
            for key in remove_keys {
                let mut content = self.content.write();
                content.remove(&key);
            }
        }

        self.index.store(index, Ordering::Relaxed);
        self.offset.store(offset, Ordering::Relaxed);
        Ok(())
    }
    */

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        error!("read_at offset {}, buf.len {}", offset, buf.len());
        (self.read_op)(offset as usize, buf)
    }

    /*
    fn write_at(&self, pos: u64, buf: &[u8]) -> VfsResult<usize> {
        let mut pos = pos as usize;
        let end = pos + buf.len();
        debug!("write_at pos {}, buf.len {} end {}...", pos, buf.len(), end);

        let mut buf_pos = 0;
        while pos < end {
            let index = pos >> PAGE_SHIFT;
            let offset = pos % PAGE_SIZE;
            let size = min(PAGE_SIZE - offset, end - pos);

            if self.content.read().get(&index).is_none() {
                self.content.write().insert(index, [0u8; PAGE_SIZE]);
            }

            let mut content = self.content.write();
            let page = content.get_mut(&index).unwrap();
            page[offset..offset+size].copy_from_slice(&buf[buf_pos..buf_pos+size]);
            pos += size;
            buf_pos += size;

            if pos > self.size() {
                self.set_size(pos);
            }
        }
        debug!("write_at: ret {} ok!", buf.len());
        Ok(buf.len())
    }
    */

    impl_vfs_non_dir_default! {}
}

fn read_op_dummy(_: usize, _: &mut [u8]) -> VfsResult<usize> {
    unreachable!();
}
