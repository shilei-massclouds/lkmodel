use core::ops::Bound;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec;
use alloc::collections::VecDeque;
use alloc::collections::BTreeMap;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use spin::RwLock;
use axtype::{PAGE_SIZE, PAGE_SHIFT};
use axtype::{O_RDONLY, O_WRONLY};

/// The pipe node in the RAM filesystem.
pub struct PipeNode {
    buf: RwLock<VecDeque<u8>>,
    readers: AtomicUsize,
    writers: AtomicUsize,
}

impl PipeNode {
    pub(super) const fn new() -> Self {
        Self {
            buf: RwLock::new(VecDeque::new()),
            readers: AtomicUsize::new(0),
            writers: AtomicUsize::new(0),
        }
    }

    fn open_for_read(&self) -> VfsResult {
        let _ = self.readers.fetch_add(1, Ordering::Relaxed);
        while self.writers.load(Ordering::Relaxed) == 0 {
            run_queue::yield_now();
        }
        error!("open_for_read ok!");
        Ok(())
    }

    fn open_for_write(&self) -> VfsResult {
        let _ =  self.writers.fetch_add(1, Ordering::Relaxed);
        while self.readers.load(Ordering::Relaxed) == 0 {
            run_queue::yield_now();
        }
        error!("open_for_write ok!");
        Ok(())
    }
}

impl VfsNodeOps for PipeNode {
    fn open(&self, mode: i32) -> VfsResult {
        error!("pipe opened! mode {:#o}, {}", mode, O_RDONLY);
        match mode {
            O_RDONLY => {
                self.open_for_read()
            },
            O_WRONLY => {
                self.open_for_write()
            },
            _ => panic!("bad mode {:#o}", mode),
        }
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_pipe(0, 0))
    }

    fn read_at(&self, pos: u64, buf: &mut [u8]) -> VfsResult<usize> {
        assert_eq!(pos, 0);
        while self.buf.read().len() == 0 {
            error!("WouldBlock!");
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
}

impl FileNode {
    pub(super) const fn new() -> Self {
        Self {
            content: RwLock::new(BTreeMap::new()),
            index: AtomicUsize::new(0),
            offset: AtomicUsize::new(0),
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
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_file(self.size() as u64, 0))
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
