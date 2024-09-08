use alloc::sync::Arc;
use axfs_vfs::{VfsNodeType, VfsOps, VfsResult};

use crate::fs;

#[cfg(feature = "devfs")]
pub(crate) fn devfs() -> Arc<fs::devfs::DeviceFileSystem> {
    let uid = 0;
    let gid = 0;
    let null = fs::devfs::NullDev;
    let zero = fs::devfs::ZeroDev;
    let console = fs::devfs::ConsoleDev;
    let bar = fs::devfs::ZeroDev;
    let devfs = fs::devfs::DeviceFileSystem::new();
    let foo_dir = devfs.mkdir("foo", uid, gid);
    devfs.add("null", Arc::new(null));
    devfs.add("zero", Arc::new(zero));
    devfs.add("console", Arc::new(console));
    foo_dir.add("bar", Arc::new(bar));
    devfs.mkdir("shm", uid, gid);
    Arc::new(devfs)
}

#[cfg(feature = "ramfs")]
pub(crate) fn ramfs() -> Arc<fs::ramfs::RamFileSystem> {
    let uid = 0;
    let gid = 0;
    Arc::new(fs::ramfs::RamFileSystem::new(uid, gid))
}

#[cfg(feature = "procfs")]
pub(crate) fn procfs() -> VfsResult<Arc<fs::ramfs::RamFileSystem>> {
    let uid = 0;
    let gid = 0;
    let mode = 0o777;
    let procfs = fs::ramfs::RamFileSystem::new(uid, gid);
    let proc_root = procfs.root_dir();

    // Create /proc/sys/net/core/somaxconn
    proc_root.create("sys", VfsNodeType::Dir, uid, gid, mode)?;
    proc_root.create("sys/net", VfsNodeType::Dir, uid, gid, mode)?;
    proc_root.create("sys/net/core", VfsNodeType::Dir, uid, gid, mode)?;
    proc_root.create("sys/net/core/somaxconn", VfsNodeType::File, uid, gid, mode)?;
    let file_somaxconn = proc_root.clone().lookup("./sys/net/core/somaxconn")?;
    file_somaxconn.write_at(0, b"4096\n")?;

    // Create /proc/sys/vm/overcommit_memory
    proc_root.create("sys/vm", VfsNodeType::Dir, uid, gid, mode)?;
    proc_root.create("sys/vm/overcommit_memory", VfsNodeType::File, uid, gid, mode)?;
    let file_over = proc_root.clone().lookup("./sys/vm/overcommit_memory")?;
    file_over.write_at(0, b"0\n")?;

    // Create /proc/self/stat
    proc_root.create("self", VfsNodeType::Dir, uid, gid, mode)?;
    proc_root.create("self/stat", VfsNodeType::File, uid, gid, mode)?;

    // Create /proc/meminfo
    proc_root.create("meminfo", VfsNodeType::File, uid, gid, mode)?;
    let file_meminfo = proc_root.clone().lookup("./meminfo")?;
    file_meminfo.write_at(0, b"MemAvailable: 100000 kB\nSwapFree: 100000 kB\n")?;

    Ok(Arc::new(procfs))
}

#[cfg(feature = "sysfs")]
pub(crate) fn sysfs() -> VfsResult<Arc<fs::ramfs::RamFileSystem>> {
    let uid = 0;
    let gid = 0;
    let mode = 0o777;
    let sysfs = fs::ramfs::RamFileSystem::new(uid, gid);
    let sys_root = sysfs.root_dir();

    // Create /sys/kernel/mm/transparent_hugepage/enabled
    sys_root.create("kernel", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("kernel/mm", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("kernel/mm/transparent_hugepage", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("kernel/mm/transparent_hugepage/enabled", VfsNodeType::File, uid, gid, mode)?;
    let file_hp = sys_root
        .clone()
        .lookup("./kernel/mm/transparent_hugepage/enabled")?;
    file_hp.write_at(0, b"always [madvise] never\n")?;

    // Create /sys/devices/system/clocksource/clocksource0/current_clocksource
    sys_root.create("devices", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("devices/system", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("devices/system/clocksource", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create("devices/system/clocksource/clocksource0", VfsNodeType::Dir, uid, gid, mode)?;
    sys_root.create(
        "devices/system/clocksource/clocksource0/current_clocksource",
        VfsNodeType::File, uid, gid, mode
    )?;
    let file_cc = sys_root
        .clone()
        .lookup("devices/system/clocksource/clocksource0/current_clocksource")?;
    file_cc.write_at(0, b"tsc\n")?;

    Ok(Arc::new(sysfs))
}
