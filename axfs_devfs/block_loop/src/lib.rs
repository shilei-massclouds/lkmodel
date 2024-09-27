#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate log;
extern crate alloc;

use alloc::sync::Arc;
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult};
use spinpreempt::SpinLock;
use mutex::Mutex;
use axfs_vfs::VfsError;
use axtype::MAX_LOOP_NUMBER;
use axerrno::AxError;
use spin::RwLock;
use axfile::fops::File;
use axtype::MAJOR_LOOP;

pub type FileRef = Arc<Mutex<File>>;

/* /dev/loop-control interface */
//const LOOP_CTL_ADD:     usize = 0x4C80;
//const LOOP_CTL_REMOVE:  usize = 0x4C81;
const LOOP_CTL_GET_FREE:usize = 0x4C82;

const LOOP_SET_FD:      usize = 0x4C00;
const LOOP_SET_STATUS:  usize = 0x4C02;

/// A device behaves like `/dev/loop-control`.
pub struct LoopCtlDev {
    slots: SpinLock<[bool; MAX_LOOP_NUMBER]>,
}

impl LoopCtlDev {
    pub fn new() -> Self {
        Self {
            slots: SpinLock::new([false; MAX_LOOP_NUMBER])
        }
    }

    fn loop_control_get_free(&self) -> VfsResult<usize> {
        let mut slots = self.slots.lock();
        for i in 0..MAX_LOOP_NUMBER {
            if !slots[i] {
                slots[i] = true;
                return Ok(i);
            }
        }
        return Err(VfsError::NoDevOrAddr);
    }
}

impl VfsNodeOps for LoopCtlDev {
    fn get_ino(&self) -> usize {
        0
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new(
            VfsNodePerm::default_file(),
            VfsNodeType::CharDevice,
            0,
            0,
            0,
            0,
        ))
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        unimplemented!("read_at");
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        unimplemented!("write_at");
    }

    fn truncate(&self, _size: u64) -> VfsResult {
        unimplemented!("truncate");
    }

    fn ioctl(&self, req: usize, _data: usize) -> VfsResult<usize> {
        assert_eq!(req, LOOP_CTL_GET_FREE);
        self.loop_control_get_free()
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}

struct LoopInfo {
    pub file: Option<FileRef>,
}

impl LoopInfo {
    pub fn new() -> Self {
        Self {
            file: None,
        }
    }
}

/// A device behaves like `/dev/loop0`.
pub struct LoopDev {
    index: usize,
    info: RwLock<LoopInfo>,
}

impl LoopDev {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            info: RwLock::new(LoopInfo::new()),
        }
    }

    fn set_fd(&self, fd: usize) -> VfsResult {
        let current = task::current();
        let file = current.filetable.lock()
            .get_file(fd)
            .ok_or(AxError::NotFound)?;
        error!("block size : {:#x}", file.lock().get_attr().unwrap().size());
        self.info.write().file = Some(file.clone());
        Ok(())
    }
}

impl VfsNodeOps for LoopDev {
    fn get_ino(&self) -> usize {
        0
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let mut attr = VfsNodeAttr::new(
            VfsNodePerm::default_file(),
            VfsNodeType::BlockDevice,
            0,
            0,
            0,
            0,
        );
        attr.set_rdev(MAJOR_LOOP, self.index as u32);
        Ok(attr)
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        unimplemented!("read_at");
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        error!("write_at: offset {} buf {:#x}", offset, buf.len());
        let ret = if let Some(ref file) = self.info.read().file {
            file.lock().write_at(offset, buf)?
        } else {
            panic!("no file!");
        };
        Ok(ret)
    }

    fn truncate(&self, size: u64) -> VfsResult {
        warn!("truncate: size {}", size);
        Ok(())
    }

    fn ioctl(&self, req: usize, data: usize) -> VfsResult<usize> {
        match req {
            LOOP_SET_FD => {
                self.set_fd(data)?;
            },
            LOOP_SET_STATUS => {
                // TODO: Just ignore it.
            },
            0x80081272 => {
                // TODO: temporarily skip it.
            },
            _ => unimplemented!("ioctl: unknown req {:#x}", req),
        }
        Ok(0)
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}
