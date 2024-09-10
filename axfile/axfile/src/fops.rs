//! Low-level filesystem operations.

use axerrno::{ax_err, ax_err_type, AxResult};
use axfs_vfs::{VfsError, VfsNodeRef, VfsNodeType};
use axio::SeekFrom;
use capability::{Cap, WithCap};
use core::fmt;
use fstree::FsStruct;
use alloc::collections::BTreeMap;
use axtype::{O_DIRECTORY, O_NOATIME};

#[cfg(feature = "myfs")]
pub use crate::dev::Disk;
#[cfg(feature = "myfs")]
pub use crate::fs::myfs::MyFileSystemIf;

/// Alias of [`axfs_vfs::VfsNodeType`].
pub type FileType = axfs_vfs::VfsNodeType;
/// Alias of [`axfs_vfs::VfsDirEntry`].
pub type DirEntry = axfs_vfs::VfsDirEntry;
/// Alias of [`axfs_vfs::VfsNodeAttr`].
pub type FileAttr = axfs_vfs::VfsNodeAttr;
/// Alias of [`axfs_vfs::VfsNodeAttrValid`].
pub type FileAttrValid = axfs_vfs::VfsNodeAttrValid;
/// Alias of [`axfs_vfs::VfsNodePerm`].
pub type FilePerm = axfs_vfs::VfsNodePerm;

/// An opened file object, with open permissions and a cursor.
pub struct File {
    node: WithCap<VfsNodeRef>,
    is_append: bool,
    offset: u64,
    pub shared_map: BTreeMap<usize, usize>,
}

/*
type OpenOp = fn(u32) -> u32;
type ReadOp = fn(u32, u32) -> u32;

pub struct FileOperations {
    open: OpenOp,
    read: ReadOp,
}

const PIPE_FOPS: FileOperations = FileOperations {
    open: fifo_open,
    read: pipe_read,
};

fn fifo_open(a: u32) -> u32 {
    0
}

fn pipe_read(a: u32, b: u32) -> u32 {
    0
}
*/

/// An opened directory object, with open permissions and a cursor for
/// [`read_dir`](Directory::read_dir).
pub struct Directory {
    node: WithCap<VfsNodeRef>,
    entry_idx: usize,
}

/// Options and flags which can be used to configure how a file is opened.
#[derive(Clone)]
pub struct OpenOptions {
    // generic
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    // system-specific
    _custom_flags: i32,
    _mode: i32,
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    pub const fn new() -> Self {
        Self {
            // generic
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            // system-specific
            _custom_flags: 0,
            _mode: 0o666,
        }
    }
    pub fn set_flags(&mut self, flags: i32) {
        self._custom_flags = flags;
    }
    pub fn set_mode(&mut self, mode: i32) {
        self._mode = mode;
    }
    /// Sets the option for read access.
    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    /// Sets the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    /// Sets the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    /// Sets the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    const fn is_valid(&self) -> bool {
        if !self.read && !self.write && !self.append {
            return false;
        }
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return false;
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return false;
                }
            }
        }
        true
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { self.node.access_unchecked().release().ok() };
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        unsafe { self.node.access_unchecked().release().ok() };
    }
}

impl fmt::Debug for OpenOptions {
    #[allow(unused_assignments)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = false;
        macro_rules! fmt_opt {
            ($field: ident, $label: literal) => {
                if self.$field {
                    if written {
                        write!(f, " | ")?;
                    }
                    write!(f, $label)?;
                    written = true;
                }
            };
        }
        fmt_opt!(read, "READ");
        fmt_opt!(write, "WRITE");
        fmt_opt!(append, "APPEND");
        fmt_opt!(truncate, "TRUNC");
        fmt_opt!(create, "CREATE");
        fmt_opt!(create_new, "CREATE_NEW");
        Ok(())
    }
}

impl From<&OpenOptions> for Cap {
    fn from(opts: &OpenOptions) -> Cap {
        let mut cap = Cap::empty();
        if opts.read {
            cap |= Cap::READ;
        }
        if opts.write | opts.append {
            cap |= Cap::WRITE;
        }
        cap
    }
}

fn perm_to_cap(perm: FilePerm) -> Cap {
    let mut cap = Cap::empty();
    if perm.owner_readable() {
        cap |= Cap::READ;
    }
    if perm.owner_writable() {
        cap |= Cap::WRITE;
    }
    if perm.owner_executable() {
        cap |= Cap::EXECUTE;
    }
    cap
}

impl File {
    pub fn new(node: VfsNodeRef, cap: Cap) -> Self {
        Self {
            node: WithCap::new(node, cap),
            is_append: false,
            offset: 0,
            shared_map: BTreeMap::new(),
        }
    }

    pub fn get_ino(&self) -> usize {
        self.node.access(Cap::empty()).unwrap().get_ino()
    }

    fn _open_at(dir: Option<&VfsNodeRef>, path: &str, opts: &OpenOptions, fs: &FsStruct, uid: u32, gid: u32) -> AxResult<Self> {
        info!("open file: {} {:?} flags {:#o}", path, opts, opts._custom_flags);
        if !opts.is_valid() {
            return ax_err!(InvalidInput);
        }

        let node_option = fs.lookup(dir, path, opts._custom_flags);
        let node = if opts.create || opts.create_new {
            info!("create: opts.mode {} {:#o}", path, opts._mode);
            match node_option {
                Ok(node) => {
                    // already exists
                    if opts.create_new {
                        return ax_err!(AlreadyExists);
                    }
                    node
                }
                // not exists, create new
                Err(VfsError::NotFound) => fs.create_file(dir, path, VfsNodeType::File, uid, gid, opts._mode)?,
                Err(e) => return Err(e),
            }
        } else {
            // just open the existing
            node_option?
        };

        let access_cap = opts.into();
        let attr = node.get_attr()?;

        if (opts._custom_flags & O_NOATIME) != 0 {
            if attr.uid() != uid {
                return ax_err!(NoPermission);
            }
        }
        if (opts._custom_flags & O_DIRECTORY) != 0 {
            if !attr.is_dir() {
                return ax_err!(NotADirectory);
            }
        }
        if attr.is_dir()
            && (opts.create || opts.create_new || opts.write || opts.append || opts.truncate)
        {
            return ax_err!(IsADirectory);
        }

        let mut mask = Self::cap_to_linux_mask(access_cap);
        if opts.create || opts.create_new {
            mask = 0;
        }
        Self::may_open(mask, uid, gid, attr)?;

        node.open(opts._custom_flags)?;
        if opts.truncate {
            node.truncate(0)?;
        }
        Ok(Self {
            node: WithCap::new(node, access_cap),
            is_append: opts.append,
            offset: 0,
            shared_map: BTreeMap::new(),
        })
    }

    fn cap_to_linux_mask(cap: Cap) -> u32 {
        let mut ret: u32 = 0;
        if cap.contains(Cap::READ) {
            ret |= 0o4;
        }
        if cap.contains(Cap::WRITE) {
            ret |= 0o2;
        }
        if cap.contains(Cap::EXECUTE) {
            ret |= 0o1;
        }
        ret
    }

    fn may_open(mask: u32, uid: u32, gid: u32, attr: FileAttr) -> AxResult {
        let fsuid = attr.uid();
        let fsgid = attr.gid();
        let mut mode = attr.perm().mode();
        info!("may_open: mask {:#o} uid {:#x}, gid {:#x}, fsuid {:#x} fsgid {:#x} mode {:#o}",
            mask, uid, gid, fsuid, fsgid, mode);

        if attr.is_symlink() {
            return ax_err!(TooManyLinks);
        }

        // Are we the owner? If so, ACL's don't matter.
        if uid == fsuid {
            mode >>= 6;
            if (mask & !mode) != 0 {
                return ax_err!(PermDenied);
            }
            return Ok(());
        }

        //
        // Are the group permissions different from
        // the other permissions in the bits we care
        // about? Need to check group ownership if so.
        //
        if (mask & (mode ^ (mode >> 3))) != 0 {
            mode >>= 3;
        }

        // Bits in 'mode' clear that we require?
        if (mask & !mode) != 0 {
            return ax_err!(PermDenied);
        }
        return Ok(());
    }

    /// Opens a file at the path relative to the current directory. Returns a
    /// [`File`] object.
    pub fn open(path: &str, opts: &OpenOptions, fs: &FsStruct, uid: u32, gid: u32) -> AxResult<Self> {
        Self::_open_at(None, path, opts, fs, uid, gid)
    }

    /// Truncates the file to the specified size.
    pub fn truncate(&self, size: u64) -> AxResult {
        self.node.access(Cap::WRITE)?.truncate(size)?;
        Ok(())
    }

    /// Gets all entries from dir.
    pub fn getdents(&mut self, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.node.access(Cap::READ)?;
        if !node.get_attr()?.is_dir() {
            return ax_err!(NotADirectory);
        }
        let read_len = node.getdents(self.offset, buf)?;
        self.offset += read_len as u64;
        Ok(read_len)
    }

    /// Reads the file at the current position. Returns the number of bytes
    /// read.
    ///
    /// After the read, the cursor will be advanced by the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.node.access(Cap::READ)?;
        if node.get_attr()?.is_dir() {
            return ax_err!(IsADirectory);
        }
        let read_len = node.read_at(self.offset, buf)?;
        self.offset += read_len as u64;
        Ok(read_len)
    }

    /// Reads the file at the given position. Returns the number of bytes read.
    ///
    /// It does not update the file cursor.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.node.access(Cap::READ)?;
        if node.get_attr()?.is_dir() {
            return ax_err!(IsADirectory);
        }
        node.read_at(offset, buf)
    }

    /// Writes the file at the current position. Returns the number of bytes
    /// written.
    ///
    /// After the write, the cursor will be advanced by the number of bytes
    /// written.
    pub fn write(&mut self, buf: &[u8]) -> AxResult<usize> {
        let node = self.node.access(Cap::WRITE)?;
        if self.is_append {
            self.offset = self.get_attr()?.size();
        };
        let write_len = node.write_at(self.offset, buf)?;
        self.offset += write_len as u64;
        Ok(write_len)
    }

    /// Writes the file at the given position. Returns the number of bytes
    /// written.
    ///
    /// It does not update the file cursor.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> AxResult<usize> {
        let node = self.node.access(Cap::WRITE)?;
        let write_len = node.write_at(offset, buf)?;
        Ok(write_len)
    }

    /// Flushes the file, writes all buffered data to the underlying device.
    pub fn flush(&self) -> AxResult {
        self.node.access(Cap::WRITE)?.fsync()?;
        Ok(())
    }

    /// Sets the cursor of the file to the specified offset. Returns the new
    /// position after the seek.
    pub fn seek(&mut self, pos: SeekFrom) -> AxResult<u64> {
        let size = self.get_attr()?.size();
        let new_offset = match pos {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(off) => self.offset.checked_add_signed(off),
            SeekFrom::End(off) => size.checked_add_signed(off),
        }
        .ok_or_else(|| ax_err_type!(InvalidInput))?;
        self.offset = new_offset;
        Ok(new_offset)
    }

    /// Gets the file attributes.
    pub fn get_attr(&self) -> AxResult<FileAttr> {
        self.node.access(Cap::empty())?.get_attr()
    }

    /// Sets the file attributes.
    pub fn set_attr(&self, attr: &FileAttr, valid: &FileAttrValid) -> AxResult {
        self.node.access(Cap::empty())?.set_attr(attr, valid)
    }

    /// Gets the file cap.
    pub fn get_cap(&self) -> Cap {
        self.node.cap()
    }
}

impl Directory {
    fn _open_dir_at(dir: Option<&VfsNodeRef>, path: &str, opts: &OpenOptions, fs: &FsStruct) -> AxResult<Self> {
        debug!("open dir: {}", path);
        if !opts.read {
            return ax_err!(InvalidInput);
        }
        if opts.create || opts.create_new || opts.write || opts.append || opts.truncate {
            return ax_err!(InvalidInput);
        }

        let node = fs.lookup(dir, path, 0)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            return ax_err!(NotADirectory);
        }
        let access_cap = opts.into();
        if !perm_to_cap(attr.perm()).contains(access_cap) {
            return ax_err!(PermissionDenied);
        }

        node.open(0)?;
        Ok(Self {
            node: WithCap::new(node, access_cap),
            entry_idx: 0,
        })
    }

    fn access_at(&self, path: &str) -> AxResult<Option<&VfsNodeRef>> {
        if path.starts_with('/') {
            Ok(None)
        } else {
            Ok(Some(self.node.access(Cap::EXECUTE)?))
        }
    }

    /// Opens a directory at the path relative to the current directory.
    /// Returns a [`Directory`] object.
    pub fn open_dir(path: &str, opts: &OpenOptions, fs: &FsStruct) -> AxResult<Self> {
        Self::_open_dir_at(None, path, opts, fs)
    }

    /// Opens a directory at the path relative to this directory. Returns a
    /// [`Directory`] object.
    pub fn open_dir_at(&self, path: &str, opts: &OpenOptions, fs: &FsStruct) -> AxResult<Self> {
        Self::_open_dir_at(self.access_at(path)?, path, opts, fs)
    }

    /// Opens a file at the path relative to this directory. Returns a [`File`]
    /// object.
    pub fn open_file_at(&self, path: &str, opts: &OpenOptions, fs: &FsStruct, uid: u32, gid: u32) -> AxResult<File> {
        File::_open_at(self.access_at(path)?, path, opts, fs, uid, gid)
    }

    /// Creates an empty file at the path relative to this directory.
    pub fn create_file(&self, path: &str, fs: &FsStruct, uid: u32, gid: u32, mode: i32) -> AxResult<VfsNodeRef> {
        fs.create_file(self.access_at(path)?, path, VfsNodeType::File, uid, gid, mode)
    }

    /// Creates an empty directory at the path relative to this directory.
    pub fn create_dir(&self, path: &str, fs: &FsStruct, uid: u32, gid: u32) -> AxResult {
        fs.create_dir(self.access_at(path)?, path, uid, gid, 0o777)
    }

    /// Removes a file at the path relative to this directory.
    pub fn remove_file(&self, path: &str, fs: &FsStruct) -> AxResult {
        fs.remove_file(self.access_at(path)?, path)
    }

    /// Removes a directory at the path relative to this directory.
    pub fn remove_dir(&self, path: &str, fs: &FsStruct) -> AxResult {
        fs.remove_dir(self.access_at(path)?, path)
    }

    /// Reads directory entries starts from the current position into the
    /// given buffer. Returns the number of entries read.
    ///
    /// After the read, the cursor will be advanced by the number of entries
    /// read.
    pub fn read_dir(&mut self, dirents: &mut [DirEntry]) -> AxResult<usize> {
        let n = self
            .node
            .access(Cap::READ)?
            .read_dir(self.entry_idx, dirents)?;
        self.entry_idx += n;
        Ok(n)
    }

    /// Rename a file or directory to a new name.
    /// Delete the original file if `old` already exists.
    ///
    /// This only works then the new path is in the same mounted fs.
    pub fn rename(&self, old: &str, new: &str, fs: &FsStruct) -> AxResult {
        fs.rename(old, new)
    }
}
