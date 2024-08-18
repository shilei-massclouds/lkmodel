#![no_std]
#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_array_assume_init)]

#[macro_use]
extern crate log;
extern crate alloc;

mod fs;
mod mounts;

use axdriver::{prelude::*, AxDeviceContainer};
use alloc::sync::Arc;
use lazy_init::LazyInit;
use axfs_vfs::VfsOps;
use axfs_vfs::RootDirectory;

cfg_if::cfg_if! {
    if #[cfg(feature = "myfs")] { // override the default filesystem
        type FsType = Arc<RamFileSystem>;
    } else if #[cfg(feature = "fatfs")] {
        use crate::fs::fatfs::FatFileSystem;
        type FsType = Arc<FatFileSystem>;
    } else {
        use ext2fs::Ext2Fs;
        type FsType = Arc<Ext2Fs>;
    }
}

/// Initializes filesystems by block devices.
pub fn init_filesystems(mut blk_devs: AxDeviceContainer<AxBlockDevice>, _need_fmt: bool) -> FsType {
    info!("Initialize filesystems...");

    let dev = blk_devs.take_one().expect("No block device found!");
    info!("  use block device 0: {:?}", dev.device_name());
    let disk = axdriver::Disk::new(dev);

    cfg_if::cfg_if! {
        if #[cfg(feature = "myfs")] { // override the default filesystem
            let main_fs = fs::myfs::new_myfs(disk);
        } else if #[cfg(feature = "fatfs")] {
            static FAT_FS: LazyInit<Arc<fs::fatfs::FatFileSystem>> = LazyInit::new();
            FAT_FS.init_by(Arc::new(fs::fatfs::FatFileSystem::new(disk, _need_fmt)));
            FAT_FS.init();
            let main_fs = FAT_FS.clone();
        } else {
            let main_fs = Ext2Fs::init(disk);
        }
    }

    main_fs
}

pub fn init_rootfs(main_fs: Arc<dyn VfsOps>) -> Arc<RootDirectory> {
    let mut root_dir = RootDirectory::new(main_fs);

    #[cfg(feature = "devfs")]
    root_dir
        .mount("/dev", mounts::devfs())
        .expect("failed to mount devfs at /dev");

    root_dir
        .mount("/dev/shm", mounts::ramfs())
        .expect("failed to mount ramfs at /dev/shm");

    #[cfg(feature = "ramfs")]
    root_dir
        .mount("/tmp", mounts::ramfs())
        .expect("failed to mount ramfs at /tmp");

    // Mount another ramfs as procfs
    #[cfg(feature = "procfs")]
    root_dir // should not fail
        .mount("/proc", mounts::procfs().unwrap())
        .expect("fail to mount procfs at /proc");

    // Mount another ramfs as sysfs
    #[cfg(feature = "sysfs")]
    root_dir // should not fail
        .mount("/sys", mounts::sysfs().unwrap())
        .expect("fail to mount sysfs at /sys");

    Arc::new(root_dir)
}

pub fn init(_cpu_id: usize, _dtb_pa: usize) {
    axconfig::init_once!();

    let all_devices = axdriver::init_drivers2();
    let main_fs = init_filesystems(all_devices.block, false);
    INIT_ROOT.init_by(init_rootfs(main_fs));
}

pub fn init_root() -> Arc<RootDirectory> {
    INIT_ROOT.clone()
}

static INIT_ROOT: LazyInit<Arc<RootDirectory>> = LazyInit::new();
