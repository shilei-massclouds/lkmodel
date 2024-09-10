//! Virtual filesystem interfaces used by [ArceOS](https://github.com/rcore-os/arceos).
//!
//! A filesystem is a set of files and directories (symbol links are not
//! supported currently), collectively referred to as **nodes**, which are
//! conceptually similar to [inodes] in Linux. A file system needs to implement
//! the [`VfsOps`] trait, its files and directories need to implement the
//! [`VfsNodeOps`] trait.
//!
//! The [`VfsOps`] trait provides the following operations on a filesystem:
//!
//! - [`mount()`](VfsOps::mount): Do something when the filesystem is mounted.
//! - [`umount()`](VfsOps::umount): Do something when the filesystem is unmounted.
//! - [`format()`](VfsOps::format): Format the filesystem.
//! - [`statfs()`](VfsOps::statfs): Get the attributes of the filesystem.
//! - [`root_dir()`](VfsOps::root_dir): Get root directory of the filesystem.
//!
//! The [`VfsNodeOps`] trait provides the following operations on a file or a
//! directory:
//!
//! | Operation | Description | file/directory |
//! | --- | --- | --- |
//! | [`open()`](VfsNodeOps::open) | Do something when the node is opened | both |
//! | [`release()`](VfsNodeOps::release) | Do something when the node is closed | both |
//! | [`get_attr()`](VfsNodeOps::get_attr) | Get the attributes of the node | both |
//! | [`read_at()`](VfsNodeOps::read_at) | Read data from the file | file |
//! | [`write_at()`](VfsNodeOps::write_at) | Write data to the file | file |
//! | [`fsync()`](VfsNodeOps::fsync) | Synchronize the file data to disk | file |
//! | [`truncate()`](VfsNodeOps::truncate) | Truncate the file | file |
//! | [`parent()`](VfsNodeOps::parent) | Get the parent directory | directory |
//! | [`lookup()`](VfsNodeOps::lookup) | Lookup the node with the given path | directory |
//! | [`create()`](VfsNodeOps::create) | Create a new node with the given path | directory |
//! | [`remove()`](VfsNodeOps::remove) | Remove the node with the given path | directory |
//! | [`read_dir()`](VfsNodeOps::read_dir) | Read directory entries | directory |
//!
//! [inodes]: https://en.wikipedia.org/wiki/Inode

#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod macros;
mod structs;

pub mod path;

use alloc::{sync::Arc, vec::Vec};
use axerrno::{ax_err, AxError, AxResult};
use core::sync::atomic::{AtomicUsize, Ordering};

pub use self::structs::{VfsDirEntry, VfsNodeAttr, VfsNodePerm, VfsNodeType};
pub use self::structs::{VfsNodeAttrValid, FileSystemInfo, DT_, LinuxDirent64};

pub type FileType = VfsNodeType;

/// A wrapper of [`Arc<dyn VfsNodeOps>`].
pub type VfsNodeRef = Arc<dyn VfsNodeOps>;

/// Alias of [`AxError`].
pub type VfsError = AxError;

/// Alias of [`AxResult`].
pub type VfsResult<T = ()> = AxResult<T>;

static NEXT_INO: AtomicUsize = AtomicUsize::new(0);

pub fn alloc_ino() -> usize {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// Filesystem operations.
pub trait VfsOps: Send + Sync {
    /// Do something when the filesystem is mounted.
    fn mount(&self, _path: &str, _mount_point: VfsNodeRef) -> VfsResult {
        Ok(())
    }

    /// Do something when the filesystem is unmounted.
    fn umount(&self) -> VfsResult {
        Ok(())
    }

    /// Format the filesystem.
    fn format(&self) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Get the attributes of the filesystem.
    fn statfs(&self) -> VfsResult<FileSystemInfo> {
        ax_err!(Unsupported)
    }

    /// Get the root directory of the filesystem.
    fn root_dir(&self) -> VfsNodeRef;
}

/// Node (file/directory) operations.
pub trait VfsNodeOps: Send + Sync {
    /// Do something when the node is opened.
    fn open(&self, _mode: i32) -> VfsResult {
        Ok(())
    }

    /// Do something when the node is closed.
    fn release(&self) -> VfsResult {
        Ok(())
    }

    /// Get the attributes of the node.
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        ax_err!(Unsupported)
    }

    /// Set the attributes of the node.
    fn set_attr(&self, _attr: &VfsNodeAttr, _valid: &VfsNodeAttrValid) -> VfsResult {
        ax_err!(Unsupported)
    }

    // file operations:

    /// Get dir entries from dir node.
    fn getdents(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        ax_err!(InvalidInput)
    }

    /// Read data from the file at the given offset.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        ax_err!(InvalidInput)
    }

    /// Write data to the file at the given offset.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        ax_err!(InvalidInput)
    }

    /// Flush the file, synchronize the data to disk.
    fn fsync(&self) -> VfsResult {
        ax_err!(InvalidInput)
    }

    /// Truncate the file to the given size.
    fn truncate(&self, _size: u64) -> VfsResult {
        ax_err!(InvalidInput)
    }

    // directory operations:

    /// Get the parent directory of this directory.
    ///
    /// Return `None` if the node is a file.
    fn parent(&self) -> Option<VfsNodeRef> {
        None
    }

    /// Lookup the node with given `path` in the directory.
    ///
    /// Return the node if found.
    fn lookup(self: Arc<Self>, _path: &str, _flags: i32) -> VfsResult<VfsNodeRef> {
        ax_err!(Unsupported)
    }

    /// Create a hardlink with the given `path` and node
    fn link(&self, _path: &str, _node: VfsNodeRef) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Create a symlink with the given `path` and `target`
    fn symlink(&self, _path: &str, _target: &str, _uid: u32, _gid: u32, _mode: i32) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Create a new node with the given `path` in the directory
    ///
    /// Return [`Ok(())`](Ok) if it already exists.
    fn create(&self, _path: &str, _ty: VfsNodeType, _uid: u32, _gid: u32, _mode: i32) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Remove the node with the given `path` in the directory.
    fn remove(&self, _path: &str) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Read directory entries into `dirents`, starting from `start_idx`.
    fn read_dir(&self, _start_idx: usize, _dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        ax_err!(Unsupported)
    }

    /// Renames or moves existing file or directory.
    fn rename(&self, _src_path: &str, _dst_path: &str) -> VfsResult {
        ax_err!(Unsupported)
    }

    /// Convert `&self` to [`&dyn Any`][1] that can use
    /// [`Any::downcast_ref`][2].
    ///
    /// [1]: core::any::Any
    /// [2]: core::any::Any#method.downcast_ref
    fn as_any(&self) -> &dyn core::any::Any {
        unimplemented!()
    }

    /// Get inode number
    fn get_ino(&self) -> usize;
}

#[doc(hidden)]
pub mod __priv {
    pub use alloc::sync::Arc;
    pub use axerrno::ax_err;
}

pub struct MountPoint {
    path: &'static str,
    fs: Arc<dyn VfsOps>,
}

impl MountPoint {
    pub fn new(path: &'static str, fs: Arc<dyn VfsOps>) -> Self {
        Self { path, fs }
    }
}

impl Drop for MountPoint {
    fn drop(&mut self) {
        self.fs.umount().ok();
    }
}

pub struct RootDirectory {
    main_fs: Arc<dyn VfsOps>,
    mounts: Vec<MountPoint>,
}

impl VfsNodeOps for RootDirectory {
    impl_vfs_dir_default! {}

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        self.main_fs.root_dir().get_attr()
    }

    fn lookup(self: Arc<Self>, path: &str, flags: i32) -> VfsResult<VfsNodeRef> {
        self.lookup_mounted_fs(path, |fs, rest_path| fs.root_dir().lookup(rest_path, flags))
    }

    fn link(&self, path: &str, node: VfsNodeRef) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                Ok(()) // already exists
            } else {
                fs.root_dir().link(rest_path, node)
            }
        })
    }

    fn symlink(&self, path: &str, target: &str, uid: u32, gid: u32, mode: i32) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                Ok(()) // already exists
            } else {
                fs.root_dir().symlink(rest_path, target, uid, gid, mode)
            }
        })
    }

    fn create(&self, path: &str, ty: VfsNodeType, uid: u32, gid: u32, mode: i32) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                Ok(()) // already exists
            } else {
                fs.root_dir().create(rest_path, ty, uid, gid, mode)
            }
        })
    }

    fn remove(&self, path: &str) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                ax_err!(PermissionDenied) // cannot remove mount points
            } else {
                fs.root_dir().remove(rest_path)
            }
        })
    }

    fn rename(&self, src_path: &str, dst_path: &str) -> VfsResult {
        self.lookup_mounted_fs(src_path, |fs, rest_path| {
            if rest_path.is_empty() {
                ax_err!(PermissionDenied) // cannot rename mount points
            } else {
                fs.root_dir().rename(rest_path, dst_path)
            }
        })
    }

    fn get_ino(&self) -> usize {
        alloc_ino()
    }
}

impl RootDirectory {
    pub const fn new(main_fs: Arc<dyn VfsOps>) -> Self {
        Self {
            main_fs,
            mounts: Vec::new(),
        }
    }

    pub fn mount(&mut self, path: &'static str, fs: Arc<dyn VfsOps>, uid: u32, gid: u32) -> AxResult {
        info!("============== mount ...");
        if path == "/" {
            return ax_err!(InvalidInput, "cannot mount root filesystem");
        }
        if !path.starts_with('/') {
            return ax_err!(InvalidInput, "mount path must start with '/'");
        }
        if self.mounts.iter().any(|mp| mp.path == path) {
            return ax_err!(InvalidInput, "mount point already exists");
        }
        // create the mount point in the main filesystem if it does not exist
        self.main_fs.root_dir().create(path, FileType::Dir, uid, gid, 0o777)?;
        fs.mount(path, self.main_fs.root_dir().lookup(path, 0)?)?;
        self.mounts.push(MountPoint::new(path, fs));
        Ok(())
    }

    pub fn _umount(&mut self, path: &str) {
        self.mounts.retain(|mp| mp.path != path);
    }

    pub fn contains(&self, path: &str) -> bool {
        self.mounts.iter().any(|mp| mp.path == path)
    }

    pub fn statfs(&self, path: &str) -> AxResult<FileSystemInfo> {
        self.lookup_mounted_fs(path, |fs, _| {
            fs.statfs()
        })
    }

    fn lookup_mounted_fs<F, T>(&self, path: &str, f: F) -> AxResult<T>
    where
        F: FnOnce(Arc<dyn VfsOps>, &str) -> AxResult<T>,
    {
        debug!("lookup at root: {}", path);
        let path = path.trim_matches('/');
        if let Some(rest) = path.strip_prefix("./") {
            return self.lookup_mounted_fs(rest, f);
        }

        let mut idx = 0;
        let mut max_len = 0;

        // Find the filesystem that has the longest mounted path match
        // TODO: more efficient, e.g. trie
        for (i, mp) in self.mounts.iter().enumerate() {
            // skip the first '/'
            if path.starts_with(&mp.path[1..]) && mp.path.len() - 1 > max_len {
                max_len = mp.path.len() - 1;
                idx = i;
            }
        }

        if max_len == 0 {
            f(self.main_fs.clone(), path) // not matched any mount point
        } else {
            f(self.mounts[idx].fs.clone(), &path[max_len..]) // matched at `idx`
        }
    }
}
