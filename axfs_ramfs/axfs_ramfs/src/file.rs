use core::ops::Bound;
use core::cmp::min;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use alloc::vec;
use alloc::collections::VecDeque;
use alloc::collections::BTreeMap;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult, VfsError};
use spin::RwLock;
use axtype::{PAGE_SIZE, PAGE_SHIFT};
use axtype::{O_WRONLY, O_RDWR, O_NONBLOCK};
use axfs_vfs::alloc_ino;

const PIPE_CAPACITY: usize = 16 * PAGE_SIZE;

/// The pipe node in the RAM filesystem.
pub struct PipeNode {
    buf: RwLock<VecDeque<u8>>,
    readers: AtomicUsize,
    writers: AtomicUsize,
    read_nonblock: AtomicBool,
    write_nonblock: AtomicBool,
    read_ready: AtomicBool,
    write_ready: AtomicBool,
    ino: usize,
    uid: u32,
    gid: u32,
}

impl PipeNode {
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            buf: RwLock::new(VecDeque::new()),
            readers: AtomicUsize::new(0),
            writers: AtomicUsize::new(0),
            read_nonblock: AtomicBool::new(false),
            write_nonblock: AtomicBool::new(false),
            read_ready: AtomicBool::new(false),
            write_ready: AtomicBool::new(false),
            ino: alloc_ino(),
            uid,
            gid,
        }
    }

    pub fn init_pipe_node(uid: u32, gid: u32) -> Self {
        let node = PipeNode::new(uid, gid);
        let _ = node.readers.fetch_add(1, Ordering::Relaxed);
        let _ = node.writers.fetch_add(1, Ordering::Relaxed);
        node.read_ready.store(true, Ordering::Relaxed);
        node.write_ready.store(true, Ordering::Relaxed);
        node
    }

    fn open_for_read(&self, block: bool) -> VfsResult {
        info!("open_for_read ...");
        let _ = self.readers.fetch_add(1, Ordering::Relaxed);
        if self.read_nonblock.load(Ordering::Relaxed) {
            return Ok(());
        }
        if !block {
            self.read_nonblock.store(true, Ordering::Relaxed);
            return Ok(());
        }

        while self.writers.load(Ordering::Relaxed) == 0 {
            run_queue::yield_now();
        }
        self.read_ready.store(true, Ordering::Relaxed);
        info!("open_for_read ok!");
        Ok(())
    }

    fn open_for_write(&self, block: bool) -> VfsResult {
        info!("open_for_write ...");
        let _ = self.writers.fetch_add(1, Ordering::Relaxed);
        if self.write_nonblock.load(Ordering::Relaxed) {
            if self.readers.load(Ordering::Relaxed) == 0 {
                return Err(VfsError::NoDevOrAddr);
            }
            return Ok(());
        }
        if !block {
            if self.readers.load(Ordering::Relaxed) == 0 {
                return Err(VfsError::NoDevOrAddr);
            }
            self.write_nonblock.store(true, Ordering::Relaxed);
            return Ok(());
        }

        while self.readers.load(Ordering::Relaxed) == 0 {
            run_queue::yield_now();
        }
        self.write_ready.store(true, Ordering::Relaxed);
        info!("open_for_write ok!");
        Ok(())
    }
}

impl VfsNodeOps for PipeNode {
    fn open(&self, flags: i32) -> VfsResult {
        assert!((flags & O_RDWR) == 0);

        let block = (flags & O_NONBLOCK) == 0;
        info!("pipe opened! mode {:#o} block {}", flags, block);
        if (flags & O_WRONLY) != 0 {
            self.open_for_write(block)
        } else {
            self.open_for_read(block)
        }
    }

    fn release(&self) -> VfsResult {
        // Todo: move this action to file level.
        let r = self.readers.fetch_sub(1, Ordering::Relaxed);
        let w = self.writers.fetch_sub(1, Ordering::Relaxed);
        info!("---> pipe release! r {}, w {}", r, w);
        Ok(())
    }

    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_pipe(0, 0, self.uid, self.gid))
    }

    fn read_at(&self, pos: u64, buf: &mut [u8]) -> VfsResult<usize> {
        info!("read_at: pos {} buf {} ..", pos, buf.len());
        if !self.read_nonblock.load(Ordering::Relaxed) {
            while !self.write_ready.load(Ordering::Relaxed) {
                run_queue::yield_now();
            }
        }
        while self.buf.read().is_empty() {
            if self.read_nonblock.load(Ordering::Relaxed) {
                return Err(VfsError::WouldBlock);
            }
            let writers = self.writers.load(Ordering::Relaxed);
            if writers == 0 {
                return Ok(0);
            }
            info!("read_at WouldBlock! writers {}", writers);
            run_queue::yield_now();
        }
        let size = min(buf.len(), self.buf.read().len());
        let src = &mut self.buf.write();
        for i in 0..size {
            buf[i] = src.pop_front().unwrap();
        }
        return Ok(size);
    }

    fn write_at(&self, pos: u64, buf: &[u8]) -> VfsResult<usize> {
        info!("write_at: pos {} buf {} ..", pos, buf.len());
        if !self.write_nonblock.load(Ordering::Relaxed) {
            while !self.read_ready.load(Ordering::Relaxed) {
                run_queue::yield_now();
            }
            let readers = self.readers.load(Ordering::Relaxed);
            info!("writer_at: BlockMode readers {}", readers);
            if readers == 0 {
                return Err(VfsError::BrokenPipe);
            }
        }

        while self.buf.read().len() >= PIPE_CAPACITY {
            if self.write_nonblock.load(Ordering::Relaxed) {
                return Err(VfsError::WouldBlock);
            }
            let readers = self.readers.load(Ordering::Relaxed);
            info!("writer_at: WouldBlock! readers {}", readers);
            run_queue::yield_now();
        }
        assert_eq!(pos, 0);
        for i in 0..buf.len() {
            self.buf.write().push_back(buf[i]);
        }
        Ok(buf.len())
    }

    impl_vfs_non_dir_default! {}
}

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
/// Content stores pages in btreemap:
/// {page_index => content_in_page}
pub struct FileNode {
    content: RwLock<BTreeMap::<usize, [u8; PAGE_SIZE]>>,
    index: AtomicUsize,
    offset: AtomicUsize,
    ino: usize,
    uid: u32,
    gid: u32,
    mode: i32,
}

impl FileNode {
    pub(super) fn new(uid: u32, gid: u32, mode: i32) -> Self {
        Self {
            content: RwLock::new(BTreeMap::new()),
            index: AtomicUsize::new(0),
            offset: AtomicUsize::new(0),
            ino: alloc_ino(),
            uid,
            gid,
            mode,
        }
    }

    fn size(&self) -> usize {
        let index = self.index.load(Ordering::Relaxed);
        let offset = self.offset.load(Ordering::Relaxed);
        (index << PAGE_SHIFT) + offset
    }

    fn set_size(&self, newsize: usize) {
        let index = newsize >> PAGE_SHIFT;
        let offset = newsize % PAGE_SIZE;
        self.index.store(index, Ordering::Relaxed);
        self.offset.store(offset, Ordering::Relaxed);
    }
}

impl VfsNodeOps for FileNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_file(self.size() as u64, 0, self.uid, self.gid, self.mode))
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

    fn read_at(&self, pos: u64, buf: &mut [u8]) -> VfsResult<usize> {
        debug!("read_at pos {}, buf.len {}, total: {}", pos, buf.len(), self.size());
        let mut pos = pos as usize;
        let start = pos as usize;
        let end = min(pos + buf.len(), self.size());

        let mut buf_pos = 0;
        while pos < end {
            let index = pos >> PAGE_SHIFT;
            let offset = pos % PAGE_SIZE;
            let size = min(PAGE_SIZE - offset, end - pos);
            if let Some(page) = self.content.read().get(&index) {
                let src = &page[offset..offset+size];
                buf[buf_pos..buf_pos+size].copy_from_slice(src);
            } else {
                buf[buf_pos..buf_pos+size].fill(0);
            }
            pos += size;
            buf_pos += size;
        }
        Ok(end - start)
    }

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

    impl_vfs_non_dir_default! {}
}
