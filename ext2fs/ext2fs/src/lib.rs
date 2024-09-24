#![no_std]
#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_array_assume_init)]

mod header;
mod tools;
mod body;

use core::fmt;
use core::cell::RefCell;
use core::mem::size_of;
use core::mem::MaybeUninit;
use alloc::vec;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::format;
use tools::{align_next, err_if_zero, u32_align_next, Block};
use header::{BlockGroupDescriptor, SuperBlock};
use axerrno::{LinuxResult, LinuxError};
use axfs_vfs::{VfsResult, VfsOps, VfsNodeRef, VfsNodeOps, VfsNodeType, VfsError};
use lazy_init::LazyInit;
use axdriver::Disk;
use axtype::Path;
use bit_field::{BitArray, BitField};
use crate::body::Mode;
use crate::body::{uid_t, gid_t};
use mutex::Mutex;
use crate::body::SFlag;
use axfs_vfs::VfsNodeAttr;
use axfs_vfs::VfsNodePerm;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::cmp::min;
use core::mem::transmute;
use core::mem;
use core::ptr::copy_nonoverlapping;
use body::directory_entry::DirectoryEntryType::{
    RegularFile, Directory,
    CharacterDevice, BlockDevice, Fifo, Socket, SymbolicLink
};
use axfs_vfs::{DT_, LinuxDirent64};

pub use body::{DirectoryEntry, DirectoryEntryType, Entry, Inode, TypePerm};

pub use tools::div_rounded_up;

#[macro_use]
extern crate log;
extern crate alloc;

/// Used to help confirm the presence of Ext2 on a volume
const EXT2_SIGNATURE_MAGIC: u16 = 0xef53;

static EXT2_FS: LazyInit<Arc<Ext2Fs>> = LazyInit::new();

pub struct Ext2Fs {
    inner: Mutex<Ext2Filesystem>,
}

impl Ext2Fs {
    pub fn new(disk: Disk) -> Self {
        Self {
            inner: Mutex::new(Ext2Filesystem::new(disk).unwrap()),
        }
    }

    pub fn init(disk: Disk) -> Arc<Self> {
        EXT2_FS.init_by(Arc::new(Self::new(disk)));
        EXT2_FS.clone()
    }

    pub fn get() -> Arc<Self> {
        EXT2_FS.clone()
    }

    pub fn create_dir(&self, ino: u32, path: &str, uid: u32, gid: u32) -> LinuxResult<()> {
        self.inner.lock().create_dir(ino, path, uid, gid)
    }

    pub fn remove(&self, ino: u32, path: &str) -> LinuxResult<()> {
        self.inner.lock().remove(ino, path)
    }

    pub fn create_file(&self, ino: u32, path: &str, uid: u32, gid: u32, mode: i32) -> LinuxResult<()> {
        self.inner.lock().create_file(ino, path, uid, gid, mode)
    }

    pub fn lookup(self: Arc<Self>, ino: u32, path: &str) -> LinuxResult<VfsNodeRef> {
        self.inner.lock().lookup(ino, path)
    }

    pub fn read_dir(&self, ino: u32, offset: u64, buf: &mut [u8]) -> LinuxResult<u64> {
        self.inner.lock()._read_dir(ino, offset, buf)
    }

    pub fn read_at(&self, ino: u32, offset: &mut u64, buf: &mut [u8]) -> LinuxResult<u64> {
        self.inner.lock()._read_at(ino, offset, buf)
    }

    pub fn write_at(&self, ino: u32, offset: &mut u64, buf: &[u8]) -> LinuxResult<u64> {
        self.inner.lock()._write_at(ino, offset, buf)
    }

    pub fn truncate(&self, ino: u32, new_size: u64) -> LinuxResult {
        self.inner.lock()._truncate(ino, new_size)
    }
}

/// Global structure of ext2Filesystem, such as disk partition.
struct Ext2Filesystem {
    superblock: SuperBlock,
    superblock_addr: u64,
    disk: RefCell<Disk>,
    nbr_block_grp: u32,
    block_size: u32,
    block_mask: u32,
    block_shift: u32,
    cache: Cache<u64, Block>,
}

impl fmt::Debug for Ext2Filesystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Test")
            .field("superblock", &self.superblock)
            .field("superblock_addr", &self.superblock_addr)
            .field("nbr_block_grp", &self.nbr_block_grp)
            .field("block_size", &self.block_size)
            .field("block_mask", &self.block_mask)
            .field("block_shift", &self.block_shift)
            .field("cache", &self.cache)
            // Not include disk in debug output.
            .finish()
    }
}

type OffsetDirEntry = u32;
type InodeAddr = u64;
type InodeNbr = u32;

impl Ext2Filesystem {
    /// Invocation of a new FileSystem instance: take a FD and his reader as parameter
    pub fn new(mut disk: Disk) -> LinuxResult<Self> {
        let superblock_addr = 1024;
        let superblock: SuperBlock = disk.read_struct(superblock_addr)?;

        let signature = superblock.get_ext2_signature();
        if signature != EXT2_SIGNATURE_MAGIC {
            return Err(LinuxError::EINVAL);
        }

        // consistency check
        let nbr_block_grp = superblock.get_nbr_block_grp();
        assert_eq!(nbr_block_grp, superblock.get_inode_block_grp());

        let block_size = 1024 << superblock.get_log2_block_size();
        // Check block_size constraints
        assert!(block_size != 0 && (block_size & (block_size - 1)) == 0);
        let block_mask = block_size - 1;
        let block_shift = u32::trailing_zeros(block_size);

        Ok(Self {
            block_size,
            block_mask,
            block_shift,
            superblock,
            superblock_addr,
            nbr_block_grp,
            disk: RefCell::new(disk),
            cache: Cache::new(block_size as usize / size_of::<Block>()),
        })
    }

    pub fn _read_dir(&self, ino: u32, offset: u64, buf: &mut [u8]) -> LinuxResult<u64> {
        if offset != 0 {
            warn!("NOTICE! todo: check offset[{}] and real length of directory!", offset);
            return Ok(0);
        }

        let iter = self.lookup_directory(ino)?;

        let mut count = 0;
        for (i, entry) in iter.enumerate() {
            let name = unsafe { entry.directory.get_filename() };
            let mut name = String::from(name);
            name.push('\0');
            let name_len = name.len();
            info!("[{}] name:{:?} [{}] {}", i, name.as_bytes(), name_len, name.len());

            let entry_size = mem::size_of::<LinuxDirent64>() + name_len;
            info!("entry_size : {}", entry_size);

            if count + entry_size > buf.len() {
                error!("buf for dirents overflow!");
                return Ok(count as u64);
            }

            let dirent: &mut LinuxDirent64 = unsafe {
                transmute(buf.as_mut_ptr().offset(count as isize))
            };
            dirent.d_ino = entry.directory.header.inode as u64;
            dirent.d_off = (count + entry_size) as i64;
            dirent.d_reclen = entry_size as u16;
            dirent.d_type = match entry.directory.header.type_indicator {
                RegularFile => DT_::REG as u8,
                Directory => DT_::DIR as u8,
                CharacterDevice => DT_::CHR as u8,
                BlockDevice => DT_::BLK as u8,
                Fifo => DT_::FIFO as u8,
                Socket => DT_::SOCK as u8,
                SymbolicLink => DT_::LNK as u8,
            };

            unsafe {
                copy_nonoverlapping(
                    name.as_ptr(),
                    dirent.d_name.as_mut_ptr(),
                    name_len
                )
            };

            count += entry_size;
        }
        Ok(count as u64)
    }

    pub fn _read_at(&mut self, inode_nbr: u32, file_offset: &mut u64, mut buf: &mut [u8]) -> LinuxResult<u64> {
        debug!("offset {:#x} buflen {:#x}", file_offset, buf.len());
        let (mut inode, _inode_addr) = self.get_inode(inode_nbr)?;

        // EOF
        if *file_offset >= inode.get_size() {
            return Ok(0);
        }

        // Resize buf if read overflow
        if *file_offset + buf.len() as u64 > inode.get_size() {
            buf = &mut buf[..(inode.get_size() - *file_offset) as usize];
        }

        // Invalidate the cache used after
        self.cache.invalidate();

        let file_curr_offset_start = *file_offset;
        let block_mask = (self.block_size - 1) as u64;

        while buf.len() != 0 {
            let mut bytes_to_read = 0;

            let mut start_data_address = None;
            let mut last_data_address: Option<u64> = None;
            loop {
                let data_address = self.inode_data(&mut inode, *file_offset).expect("WTF");
                if let Some(last_address) = last_data_address {
                    if data_address != last_address + self.block_size as u64 {
                        break;
                    }
                } else {
                    start_data_address = Some(data_address);
                }
                let mut bytes = min(
                    self.block_size as u64 - (*file_offset & block_mask),
                    inode.get_size() - *file_offset,
                );
                bytes = min(bytes, buf.len() as u64 - bytes_to_read);

                *file_offset += bytes;
                bytes_to_read += bytes;
                if bytes_to_read == buf.len() as u64 {
                    break;
                }
                last_data_address = Some(data_address);
            }
            let data_read = self.disk.borrow_mut().read_buffer(
                start_data_address.expect("WOOT"),
                &mut buf[0..bytes_to_read as usize],
            )?;
            assert!(data_read == bytes_to_read);
            buf = &mut buf[bytes_to_read as usize..];
        }
        Ok(*file_offset - file_curr_offset_start)
    }

    pub fn _write_at(
        &mut self,
        inode_nbr: u32,
        file_offset: &mut u64,
        buf: &[u8],
    ) -> LinuxResult<u64> {
        let (mut inode, inode_addr) = self.get_inode(inode_nbr)?;
        let file_curr_offset_start = *file_offset;
        if *file_offset > inode.get_size() {
            return Ok(0);
        }
        if buf.len() == 0 {
            return Ok(0);
        }
        let data_address = self.inode_data_alloc((&mut inode, inode_addr), *file_offset)?;
        let offset = min(
            self.block_size as u64 - *file_offset % self.block_size as u64,
            buf.len() as u64,
        );
        let data_write = self
            .disk
            .borrow_mut()
            .write_buffer(data_address, &buf[0..offset as usize])?;
        *file_offset += data_write as u64;
        if inode.get_size() < *file_offset {
            inode.update_size(*file_offset, self.block_size);
            self.disk.borrow_mut().write_struct(inode_addr, &inode)?;
        }
        if data_write < offset {
            return Ok(*file_offset - file_curr_offset_start);
        }

        for chunk in buf[offset as usize..].chunks(self.block_size as usize) {
            let data_address = self.inode_data_alloc((&mut inode, inode_addr), *file_offset)?;
            let data_write = self.disk.borrow_mut().write_buffer(data_address, &chunk)?;
            *file_offset += data_write as u64;
            if inode.get_size() < *file_offset {
                inode.update_size(*file_offset, self.block_size);
                self.disk.borrow_mut().write_struct(inode_addr, &inode)?;
            }
            if data_write < chunk.len() as u64 {
                return Ok(*file_offset - file_curr_offset_start);
            }
        }
        Ok(*file_offset - file_curr_offset_start)
    }

    /// return all the (directory, inode) conainted in inode_nbr
    pub fn lookup_directory<'a>(
        &'a self, ino: u32
    ) -> LinuxResult<impl Iterator<Item = Entry> + 'a> {
        Ok(self
            .iter_entries(ino)?
            .into_iter()
            .filter_map(|(dir, _)| match self.get_inode(dir.get_inode()) {
                Ok((inode, _)) => Some(Entry {
                    directory: dir,
                    inode,
                }),
                Err(_e) => None,
            }))
    }

    fn _lookup_directory<'a>(
        &'a self, ino: u32, path: &Path,
    ) -> LinuxResult<impl Iterator<Item = Entry> + 'a> {
        let mut iter = self.lookup_directory(ino).unwrap();
        for directory in path.components() {
            if directory.len() == 0 {
                continue;
            }
            let elem = iter.find(|entry| {
                let filelen = directory.len();
                unsafe {
                    libc_memcmp(
                        entry.directory.filename.0.as_ptr() as *const u8,
                        directory.as_bytes().as_ptr() as *const u8,
                        filelen,
                    )
                }
            });
            match elem {
                None => return Err(LinuxError::ENOENT),
                Some(entry) => {
                    let inode = entry.directory.get_inode();
                    iter = self.lookup_directory(inode)?;
                }
            }
        }
        Ok(iter)
    }

    fn _find_entry(&self, ino: u32, path: &Path) -> LinuxResult<Option<Entry>> {
        info!("_find_entry: parent: ino: {}, {:?}", ino, path.parent());
        Ok(match path.parent() {
            Some(parent) => {
                let parent = Path::new(parent);
                let mut iter = self._lookup_directory(ino, &parent)?;
                iter.find(|entry| unsafe { entry.directory.get_filename() } == path.file_name().unwrap())
            }
            None => {
                info!("is rootdir: ino {} {}", ino, path.as_str());
                if path.as_str() == "" {
                    let mut iter = self._lookup_directory(ino, path)?;
                    iter.find(|entry| unsafe { entry.directory.get_filename() } == ".")
                } else {
                    let parent = Path::new("/");
                    let mut iter = self._lookup_directory(ino, &parent)?;
                    iter.find(|entry| unsafe { entry.directory.get_filename() } == path.file_name().unwrap())
                }
            }
            // rootdir
            /*
            None => {
                info!("is rootdir: ino {} {}", ino, path.as_str());
                let mut iter = self._lookup_directory(ino, path)?;
                iter.find(|entry| unsafe { entry.directory.get_filename() } == ".")
            }
            */
        })
    }

    pub fn _create_file(
        &mut self,
        filename: &str,
        parent_inode_nbr: u32,
        timestamp: u32,
        type_perm: TypePerm,
        (owner, group): (uid_t, gid_t),
    ) -> LinuxResult<Entry> {
        let direntry_type = DirectoryEntryType::try_from(type_perm)?;
        let inode_nbr = self.alloc_inode().ok_or(LinuxError::ENOSPC)?;
        let (_, inode_addr) = self.get_inode(inode_nbr)?;
        let mut inode = Inode::new(type_perm);

        inode.set_owner(owner);
        inode.set_group(group);
        inode.last_access_time = timestamp;
        inode.creation_time = timestamp;
        inode.last_modification_time = timestamp;

        self.disk.borrow_mut().write_struct(inode_addr, &inode)?;

        let mut new_entry = DirectoryEntry::new(filename, direntry_type, inode_nbr)?;
        self.push_entry(parent_inode_nbr, &mut new_entry)?;
        Ok(Entry {
            directory: new_entry,
            inode,
        })
    }

    pub fn _create_dir(
        &mut self,
        parent_inode_nbr: u32,
        filename: &str,
        timestamp: u32,
        mode: Mode,
        (owner, group): (uid_t, gid_t),
    ) -> LinuxResult<Entry> {
        let inode_nbr = self.alloc_inode().ok_or(LinuxError::ENOSPC)?;
        let (_, inode_addr) = self.get_inode(inode_nbr)?;
        let mut inode = Inode::new(TypePerm((mode.bits() | SFlag::S_IFDIR.bits()) as u16));
        inode.nbr_hard_links = 2;
        inode.set_owner(owner);
        inode.set_group(group);
        inode.last_access_time = timestamp;
        inode.creation_time = timestamp;
        inode.last_modification_time = timestamp;
        inode.low_size = 1024 << self.superblock.get_log2_block_size();

        self.disk.borrow_mut().write_struct(inode_addr, &inode)?;
        let mut new_entry =
            DirectoryEntry::new(filename, DirectoryEntryType::Directory, inode_nbr)?;
        self.push_entry(parent_inode_nbr, &mut new_entry)?;

        let mut point = DirectoryEntry::new(".", DirectoryEntryType::Directory, inode_nbr)?;
        let mut point_point =
            DirectoryEntry::new("..", DirectoryEntryType::Directory, parent_inode_nbr)?;
        self.push_entry(inode_nbr, &mut point)?;
        self.push_entry(inode_nbr, &mut point_point)?;
        Ok(Entry {
            directory: new_entry,
            inode,
        })
    }

    pub fn create_file(&mut self, ino: u32, path: &str, uid: u32, gid: u32, mode: i32) -> LinuxResult<()> {
        let timestamp = axhal::time::current_time();
        let path = Path::new(path);
        let parent = Path::new(path.parent().unwrap_or("/"));
        let filename: &str = path.file_name().unwrap();
        //info!("parent {:?}", parent);
        let iter = self._lookup_directory(ino, &parent)?;
        let parent = iter.fold(Ok(None), |res, entry| {
            if unsafe { entry.directory.get_filename() } == filename {
                return Err(LinuxError::EEXIST);
            }
            res.map(|opt| {
                opt.or({
                    if unsafe { entry.directory.get_filename() == "." } {
                        Some(entry)
                    } else {
                        None
                    }
                })
            })
        })?;

        //info!("parent: {:?}", parent);
        let parent_inode_nbr = parent.unwrap().directory.header.inode;
        self._create_file(
            filename,
            parent_inode_nbr,
            timestamp.as_secs() as u32,
            (mode as u32, SFlag::S_IFREG).try_into().unwrap(),
            (uid, gid),
        )?;
        Ok(())
    }

    pub fn create_dir(&mut self, ino: u32, path: &str, uid: u32, gid: u32) -> LinuxResult<()> {
        let timestamp = axhal::time::current_time();
        let path = Path::new(path);
        let parent = Path::new(path.parent().unwrap_or("/"));
        let filename: &str = path.file_name().unwrap();
        //info!("parent {:?}", parent);
        let iter = self._lookup_directory(ino, &parent)?;
        let parent = iter.fold(Ok(None), |res, entry| {
            if unsafe { entry.directory.get_filename() } == filename {
                return Err(LinuxError::EEXIST);
            }
            res.map(|opt| {
                opt.or({
                    if unsafe { entry.directory.get_filename() == "." } {
                        Some(entry)
                    } else {
                        None
                    }
                })
            })
        })?;

        info!("path {}", path.as_str());
        let parent_inode_nbr = parent.unwrap().directory.header.inode;
        self._create_dir(
            parent_inode_nbr,
            filename,
            timestamp.as_secs() as u32,
            def_mode() | Mode::S_IXUSR | Mode::S_IXOTH | Mode::S_IXGRP,
            (uid, gid),
        )?;
        Ok(())
    }

    pub fn remove(&mut self, ino: u32, path: &str) -> LinuxResult<()> {
        let path = Path::new(path);
        let entry = match self._find_entry(ino, &path)? {
            Some(entry) => entry,
            None => {
                return Err(LinuxError::ENOENT);
            },
        };
        let inode = entry.inode;
        if inode.type_and_perm.is_regular() {
            self.remove_file(ino, path.as_str())
        } else if inode.type_and_perm.is_directory() {
            self.remove_dir(ino, path.as_str())
        } else {
            Err(LinuxError::EINVAL)
        }
    }

    pub fn remove_file(&mut self, ino: u32, path: &str) -> LinuxResult<()> {
        let path = Path::new(path);
        let parent = path.parent().ok_or_else(|| LinuxError::ENOENT)?;
        let parent = Path::new(parent);

        let parent = self._find_entry(ino, &parent)?;
        let parent_inode_nbr = parent.unwrap().directory.header.inode;
        Ok(self._unlink(
            parent_inode_nbr,
            path.file_name().unwrap(),
            true,
        )?)
    }

    /// The unlink() function shall remove a link to a file.
    pub fn _unlink(
        &mut self,
        parent_inode_nbr: u32,
        filename: &str,
        free_inode_data: bool,
    ) -> LinuxResult<()> {
        let entry = self.find_entry_in_inode(parent_inode_nbr, filename)?;
        self.unlink_inode(entry.0.get_inode(), free_inode_data)?;
        self.delete_entry(parent_inode_nbr, entry.1).expect("WTF");
        Ok(())
    }

    pub fn remove_dir(&mut self, ino: u32, path: &str) -> LinuxResult<()> {
        let path = Path::new(path);
        let iter = self._lookup_directory(ino, &path)?;
        let parent = iter.enumerate().fold(Ok(None), |res, (idx, entry)| {
            if idx > 1 {
                return Err(LinuxError::EPERM);
            }
            res.map(|opt| {
                opt.or({
                    if unsafe { entry.directory.get_filename() == ".." } {
                        Some(entry)
                    } else {
                        None
                    }
                })
            })
        })?;
        info!("remove_dir ...");
        match path.file_name() {
            Some(filename) => Ok(self._rmdir(
                parent.unwrap().directory.get_inode(),
                filename,
            )?),
            None => Err(LinuxError::EEXIST),
        }
    }

    /// The Truncate() Function Shall cause the regular file named by
    /// path to have a size which shall be equal to length bytes.
    pub fn _truncate(&mut self, inode_nbr: u32, new_size: u64) -> LinuxResult<()> {
        let (mut inode, inode_addr) = self.get_inode(inode_nbr)?;
        if !inode.is_a_regular_file() {
            return Err(LinuxError::EISDIR);
        }

        let mut size = inode.get_size();
        if new_size <= size {
            self.truncate_inode((&mut inode, inode_addr), new_size)
        } else {
            let buf = vec![0u8; (new_size - size) as usize];
            let _ = self._write_at(inode_nbr, &mut size, &buf)?;
            Ok(())
        }
    }

    pub fn _rmdir(&mut self, parent_inode_nbr: u32, filename: &str) -> LinuxResult<()> {
        let entry = self.find_entry_in_inode(parent_inode_nbr, filename)?;
        let inode_nbr = entry.0.get_inode();
        let (mut inode, inode_addr) = self.get_inode(inode_nbr)?;

        if !inode.is_a_directory() {
            return Err(LinuxError::ENOTDIR);
        }
        self.free_inode((&mut inode, inode_addr), inode_nbr)?;
        self.delete_entry(parent_inode_nbr, entry.1)?;
        Ok(())
    }

    fn lookup(&self, ino: u32, path: &str) -> LinuxResult<VfsNodeRef> {
        info!("ext2: lookup: path: {} parent_ino {} ...", path, ino);
        let path = Path::new(path);
        match self._find_entry(ino, &path)? {
            Some(entry) => {
                let ino = entry.directory.get_inode();
                info!("ext2: lookup: child path: {}, ino: {:?}", path, ino);
                if entry.inode.type_and_perm.is_symlink() {
                    let lnk = entry.inode.read_symlink().unwrap();
                    assert!(!lnk.starts_with('/'));
                    let parent = path.parent().unwrap_or("");
                    let lnk = format!("{}/{}", parent, lnk);
                    info!("lnk: {}", lnk);
                    self.lookup(2, &lnk)
                } else {
                    Ok(Arc::new(Ext2Inode::new(entry)))
                }
            },
            None => {
                info!("ext2: lookup: NOENT");
                Err(LinuxError::ENOENT)
            },
        }
    }

    fn find_entry_in_inode(
        &self,
        inode_nbr: u32,
        filename: &str,
    ) -> LinuxResult<(DirectoryEntry, OffsetDirEntry)> {
        Ok(self
            .iter_entries(inode_nbr)?
            .find(|(x, _)| unsafe { x.get_filename() } == filename)
            .ok_or(LinuxError::ENOENT)?)
    }

    /// truncate inode to the size `new_size` deleting all data blocks above
    fn truncate_inode(
        &mut self,
        (inode, inode_addr): (&mut Inode, InodeAddr),
        new_size: u64,
    ) -> LinuxResult<()> {
        let size = inode.get_size();
        assert!(new_size <= size);
        if size == 0 {
            return Ok(());
        }
        let new_size_block = self.to_block_addr(new_size);
        // let curr_size = self.to_block_addr(align_next(size, self.block_size as u64));
        // size - 1 to get the previous block addr
        let curr_size = self.to_block_addr(size - 1);
        for block_off in (new_size_block.0..=curr_size.0).rev() {
            self.inode_free_block((inode, inode_addr), Block(block_off))
                .unwrap();
        }
        inode.update_size(new_size, self.block_size);
        self.disk.borrow_mut().write_struct(inode_addr, inode)?;
        Ok(())
    }

    /// delete inode `inode_nbr`
    fn free_inode(
        &mut self,
        (inode, inode_addr): (&mut Inode, InodeAddr),
        inode_nbr: u32,
    ) -> LinuxResult<()> {
        assert!(inode_nbr >= 1);
        /* Delete Data Blocks */
        // don't truncate inode if it is a fast symbolic link
        if !(inode.type_and_perm.is_symlink()
            && inode.get_size() <= Inode::FAST_SYMLINK_SIZE_MAX as u64)
        {
            self.truncate_inode((inode, inode_addr), 0).unwrap();
        }
        /* Unset Inode bitmap */
        let block_grp = (inode_nbr - 1) / self.superblock.inodes_per_block_grp;
        let index = (inode_nbr as u64 - 1) % self.superblock.inodes_per_block_grp as u64;
        let (mut block_dtr, block_dtr_addr) = self.get_block_grp_descriptor(block_grp)?;
        let bitmap_addr = self.to_addr(block_dtr.inode_usage_bitmap);

        let mut disk = self.disk.borrow_mut();
        let mut bitmap: u8 = disk.read_struct(bitmap_addr + index / 8)?;
        assert!(bitmap.get_bit((index % 8) as usize));
        bitmap.set_bit((index % 8) as usize, false);
        disk.write_struct(bitmap_addr + index / 8, &bitmap)?;

        // debug_assert!(self.get_inode(inode_nbr).is_err());
        // TODO: check that with fsck
        block_dtr.nbr_free_inodes += 1;
        self.superblock.nbr_free_inodes += 1;
        block_dtr.nbr_free_inodes;
        disk.write_struct(self.superblock_addr, &self.superblock)?;
        disk.write_struct(block_dtr_addr, &block_dtr)?;
        Ok(())
    }

    /// decrement link count of the inode and delete it if it becomes 0
    /// panic if the inode refers to a directory
    fn unlink_inode(&mut self, inode_nbr: u32, free_inode_data: bool) -> LinuxResult<()> {
        info!("unlink_inode");
        let (mut inode, inode_addr) = self.get_inode(inode_nbr)?;
        if inode.is_a_directory() {
            return Err(LinuxError::EISDIR);
        }
        if inode.nbr_hard_links <= 1 && free_inode_data {
            return self.free_inode((&mut inode, inode_addr), inode_nbr);
        }
        inode.nbr_hard_links -= 1;
        self.disk.borrow_mut().write_struct(inode_addr, &inode)?;
        Ok(())
    }

    /// delete the entry at entry_off of the parent_inode nbr
    fn delete_entry(&mut self, parent_inode_nbr: u32, entry_off: u32) -> LinuxResult<()> {
        let (mut inode, inode_addr) = self.get_inode(parent_inode_nbr)?;
        let curr_offset = entry_off;
        let entry = self
            .find_entry((&mut inode, inode_addr), curr_offset as u64)
            .unwrap();

        let (mut previous, previous_offset) = self
            .iter_entries(parent_inode_nbr)
            .unwrap()
            .take_while(|(_, off)| *off < entry_off)
            .last()
            .unwrap();
        /* if it is the last entry */
        if self
            .find_entry(
                (&mut inode, inode_addr),
                curr_offset as u64 + entry.get_size() as u64,
            )
            .is_none()
        {
            self.set_as_last_entry((&mut inode, inode_addr), (&mut previous, previous_offset))
        }
        /* Else, we set previous next to current next.
        this creates a Hole which will be filled in push_entry */
        else {
            let next_entry_off = curr_offset as u64 + entry.get_size() as u64;
            let previous_entry_addr = self
                .inode_data_may_alloc((&mut inode, inode_addr), previous_offset as u64)
                .unwrap();
            previous.set_size((next_entry_off - previous_offset as u64) as u16);
            previous.write_on_disk(previous_entry_addr, &mut self.disk.borrow_mut())?;
            Ok(())
        }
    }

    /// convert a block to an address
    fn to_addr(&self, block_number: Block) -> u64 {
        self.block_size as u64 * block_number.0 as u64
    }

    /// convert an address to a number of block
    fn to_block_addr(&self, size: u64) -> Block {
        Block((size / self.block_size as u64) as u32)
    }

    /// convert an address to a number of block
    fn to_block(&self, size: u64) -> Block {
        Block(
            (size / self.block_size as u64 + ((size % self.block_size as u64 != 0) as u64)) as u32,
        )
    }

    /// get inode nbr inode and return the Inode and it's address
    fn get_inode(&self, inode: u32) -> LinuxResult<(Inode, InodeAddr)> {
        assert!(inode >= 1);
        let block_grp = (inode - 1) / self.superblock.inodes_per_block_grp;
        let index = (inode as u64 - 1) % self.superblock.inodes_per_block_grp as u64;
        let inode_offset = index as u64 * self.superblock.get_size_inode() as u64;

        let (block_dtr, _) = self.get_block_grp_descriptor(block_grp)?;
        let bitmap_addr = self.to_addr(block_dtr.inode_usage_bitmap);
        let bitmap: u8 = self
            .disk
            .borrow_mut()
            .read_struct(bitmap_addr + index / 8)?;
        if !bitmap.get_bit((index % 8) as usize) {
            return Err(LinuxError::ENOENT);
        }

        let inode_addr = self.to_addr(block_dtr.inode_table) + inode_offset;

        Ok((self.disk.borrow_mut().read_struct(inode_addr)?, inode_addr))
    }

    //TODO: better handle disk error
    /// try to allocate a new inode on block group n and return the inode number
    fn alloc_inode_on_grp(&mut self, n: u32) -> Option<InodeNbr> {
        let (mut block_dtr, block_dtr_addr) = self.get_block_grp_descriptor(n).ok()?;
        if block_dtr.nbr_free_inodes == 0 {
            return None;
        }
        let mut disk = self.disk.borrow_mut();

        // TODO: dynamic alloc ?
        let bitmap_addr = self.to_addr(block_dtr.inode_usage_bitmap);
        let mut bitmap: [u8; 1024] = disk.read_struct(bitmap_addr).ok()?;
        for i in 0..self.superblock.inodes_per_block_grp {
            if !bitmap.get_bit(i as usize) {
                bitmap.set_bit(i as usize, true);
                disk.write_struct(bitmap_addr + i as u64 / 8, &bitmap[(i / 8) as usize])
                    .ok()?;
                block_dtr.nbr_free_inodes -= 1;
                self.superblock.nbr_free_inodes -= 1;
                block_dtr.nbr_free_inodes;
                disk.write_struct(self.superblock_addr, &self.superblock)
                    .ok()?;
                disk.write_struct(block_dtr_addr, &block_dtr).ok()?;
                // TODO: Check the + 1
                return Some(self.superblock.inodes_per_block_grp * n + i + 1);
            }
        }
        None
    }

    /// try to allocate a new inode anywhere on the filesystem and return the inode number
    fn alloc_inode(&mut self) -> Option<InodeNbr> {
        for n in 0..self.nbr_block_grp {
            if let Some(n) = self.alloc_inode_on_grp(n) {
                return Some(n);
            }
        }
        None
    }

    /// the the entry at offset entry_offset the last entry of the directory
    fn set_as_last_entry(
        &mut self,
        (inode, inode_addr): (&mut Inode, InodeAddr),
        (entry, entry_offset): (&mut DirectoryEntry, OffsetDirEntry),
    ) -> LinuxResult<()> {
        let entry_addr = self.inode_data_alloc((inode, inode_addr), entry_offset as u64)?;

        // =(the offset to the next block)
        entry.set_size((u32_align_next(entry_offset + 1, self.block_size) - entry_offset) as u16);
        entry.write_on_disk(entry_addr, &mut self.disk.borrow_mut())?;
        /* Update inode size */
        let new_size = entry_offset as u64 + entry.get_size() as u64;
        if new_size < inode.get_size() {
            self.truncate_inode((inode, inode_addr), new_size)?;
        } else {
            inode.update_size(new_size, self.block_size);
            self.disk.borrow_mut().write_struct(inode_addr, inode)?;
        }
        Ok(())
    }

    /// push a directory entry on the Directory inode: `parent_inode_nbr`
    fn push_entry(
        &mut self,
        parent_inode_nbr: u32,
        new_entry: &mut DirectoryEntry,
    ) -> LinuxResult<()> {
        let (mut inode, inode_addr) = self.get_inode(parent_inode_nbr)?;
        // Get the last entry of the Directory
        match self.iter_entries(parent_inode_nbr)?.last() {
            Some((mut entry, offset)) => {
                let offset = offset as u64;

                let entry_addr = self.inode_data_xxx(&mut inode, offset).unwrap();
                // debug_assert_eq!(self.disk.read_struct::<DirectoryEntry>(entry_addr), entry)?;
                let entry_size = entry.size() as u64;

                let new_offset = {
                    let new_offset = align_next(offset + entry_size, 4);
                    // if we do not cross a Block
                    if self.to_block(new_offset) == self.to_block(new_offset + new_entry.size() as u64)
                    // and the block is already allocated
                        && self.inode_data_may_alloc((&mut inode, inode_addr), new_offset).is_ok()
                    //self.to_block( as u32) == self.to_block(offset)
                    {
                        new_offset
                    } else {
                        align_next(offset + entry_size, self.block_size as u64)
                    }
                };
                /* Update previous entry size */
                entry.set_size((new_offset - offset) as u16);
                entry.write_on_disk(entry_addr, &mut self.disk.borrow_mut())?;

                self.set_as_last_entry((&mut inode, inode_addr), (new_entry, new_offset as u32))
            }
            None => self.set_as_last_entry((&mut inode, inode_addr), (new_entry, 0 as u32)),
        }
    }

    /// find the directory entry a offset file.curr_offset
    fn find_entry(&self, inode: (&mut Inode, u64), offset: u64) -> Option<DirectoryEntry> {
        if offset >= inode.0.get_size() {
            return None;
        }
        let base_addr = self.inode_data_xxx(inode.0, offset).ok()? as u64;
        let dir_header: DirectoryEntry = self.disk.borrow_mut().read_struct(base_addr).ok()?;
        Some(dir_header)
    }

    /// iter of the entries of inodes if inode is a directory
    fn iter_entries<'a>(&'a self, inode: InodeNbr) -> LinuxResult<EntryIter<'a>> {
        let (inode, inode_addr) = self.get_inode(inode)?;
        //info!("inode: {:?} {}", inode, inode_addr);
        if !inode.is_a_directory() {
            return Err(LinuxError::ENOTDIR);
        }
        Ok(EntryIter {
            filesystem: self,
            inode: (inode, inode_addr),
            curr_offset: 0,
        })
    }

    /// read the block group descriptor address from the block group number starting at 0
    fn block_grp_descriptor_addr(&self, n: u32) -> u64 {
        // The table is located in the block immediately following the
        // Superblock. So if the block size (determined from a field
        // in the superblock) is 1024 bytes per block, the Block Group
        // Descriptor Table will begin at block 2. For any other block
        // size, it will begin at block 1. Remember that blocks are
        // numbered starting at 0, and that block numbers don't
        // usually correspond to physical block addresses.
        assert!(n <= self.nbr_block_grp);
        let offset = if self.block_size == 1024 { 2 } else { 1 };

        self.to_addr(Block(offset)) + n as u64 * size_of::<BlockGroupDescriptor>() as u64
    }

    /// read the block group descriptor from the block group number starting at 0
    fn get_block_grp_descriptor(&self, n: u32) -> LinuxResult<(BlockGroupDescriptor, u64)> {
        let block_grp_addr = self.block_grp_descriptor_addr(n);
        let block_grp: BlockGroupDescriptor = self.disk.borrow_mut().read_struct(block_grp_addr)?;
        Ok((block_grp, block_grp_addr))
    }

    /// try to allocate a new block on block grp number `n`
    fn alloc_block_on_grp(&mut self, n: u32) -> Option<Block> {
        let (mut block_dtr, block_dtr_addr) = self.get_block_grp_descriptor(n).ok()?;
        if block_dtr.nbr_free_blocks == 0 {
            return None;
        }
        // TODO: dynamic alloc ?
        let bitmap_addr = self.to_addr(block_dtr.block_usage_bitmap);
        let mut bitmap: [u8; 1024] = self.disk.borrow_mut().read_struct(bitmap_addr).ok()?;
        for i in 0..self.superblock.get_block_per_block_grp().0 {
            if !bitmap.get_bit(i as usize) {
                bitmap.set_bit(i as usize, true);
                self.disk
                    .borrow_mut()
                    .write_struct(bitmap_addr + i as u64 / 8, &bitmap[(i / 8) as usize])
                    .ok()?;

                block_dtr.nbr_free_blocks -= 1;
                self.disk
                    .borrow_mut()
                    .write_struct(block_dtr_addr, &block_dtr)
                    .ok()?;
                self.superblock.nbr_free_blocks -= 1;
                self.disk
                    .borrow_mut()
                    .write_struct(self.superblock_addr, &self.superblock)
                    .ok()?;
                // TODO: Check the + 1
                return Some(self.superblock.get_block_per_block_grp() * n + Block(i + 1));
            }
        }
        None
    }

    /// try to allocate a new block anywhere on the filesystem
    fn alloc_block(&mut self) -> Option<Block> {
        for n in 0..self.nbr_block_grp {
            if let Some(addr) = self.alloc_block_on_grp(n) {
                // TODO: dynamic alloc ?
                let _res = self
                    .disk
                    .borrow_mut()
                    .write_buffer(self.to_addr(addr), &[0; 1024]);
                return Some(addr);
            }
        }
        None
    }

    /// try to free the block block_nbr
    fn free_block(&mut self, block_nbr: Block) -> LinuxResult<()> {
        let block_grp = (block_nbr.0 - 1) / self.superblock.get_block_per_block_grp().0;
        let index = (block_nbr.0 as u64 - 1) % self.superblock.get_block_per_block_grp().0 as u64;

        let (mut block_dtr, block_dtr_addr) = self.get_block_grp_descriptor(block_grp)?;
        let bitmap_addr = self.to_addr(block_dtr.block_usage_bitmap);

        let mut disk = self.disk.borrow_mut();
        let mut bitmap: u8 = disk.read_struct(bitmap_addr + index / 8)?;
        assert!(bitmap.get_bit((index % 8) as usize));
        bitmap.set_bit((index % 8) as usize, false);

        disk.write_struct(bitmap_addr + index / 8, &bitmap)?;
        block_dtr.nbr_free_blocks += 1;
        disk.write_struct(block_dtr_addr, &block_dtr)?;
        self.superblock.nbr_free_blocks += 1;
        disk.write_struct(self.superblock_addr, &self.superblock)?;
        Ok(())
    }

    /// get the data of inode at offset `offset`, and allocate the data block if necessary
    fn inode_data_alloc(&mut self, inode: (&mut Inode, u64), offset: u64) -> LinuxResult<u64> {
        self.inode_data_may_alloc(inode, offset)
    }

    /// alloc a pointer (used by the function inode_data_alloc)
    fn alloc_pointer(&mut self, pointer_addr: u64) -> LinuxResult<Block> {
        err_if_zero({
            let pointer = self.disk.borrow_mut().read_struct(pointer_addr)?;
            if pointer == Block(0) {
                let new_block = self.alloc_block().ok_or(LinuxError::ENOSPC)?;
                self.disk
                    .borrow_mut()
                    .write_struct(pointer_addr, &new_block)?;
                new_block
            } else {
                pointer
            }
        })
    }

    fn pointer(&self, pointer_addr: u64) -> LinuxResult<Block> {
        err_if_zero({
            let pointer = self.disk.borrow_mut().read_struct(pointer_addr)?;
            pointer
        })
    }

    /// free a pointer (used by the function inode_data_alloc)
    fn free_pointer(&mut self, pointer_addr: u64) -> LinuxResult<()> {
        let pointer = self.disk.borrow_mut().read_struct(pointer_addr)?;
        if pointer == Block(0) {
            panic!("free pointer null");
        } else {
            self.disk
                .borrow_mut()
                .write_struct(pointer_addr, &Block(0))?;
            self.free_block(pointer)
        }
    }

    /// Get the file location at offset 'offset'
    fn inode_free_block(
        &mut self,
        (inode, inode_addr): (&mut Inode, InodeAddr),
        block_off: Block,
    ) -> LinuxResult<()> {
        let blocknumber_per_block = (self.block_size as usize / size_of::<Block>()) as u32;
        let block_off = block_off.0 as u64;

        // SIMPLE ADDRESSING
        let mut offset_start = 0;
        let mut offset_end = 12;
        if block_off >= offset_start && block_off < offset_end {
            let pointer = err_if_zero(inode.direct_block_pointers[block_off as usize])?;
            self.free_block(pointer)?;
            inode.direct_block_pointers[block_off as usize] = Block(0);
            self.disk.borrow_mut().write_struct(inode_addr, inode)?;
            return Ok(());
        }

        // SINGLY INDIRECT ADDRESSING
        // 12 * blocksize .. 12 * blocksize + (blocksize / 4) * blocksize
        offset_start = offset_end;
        offset_end += blocknumber_per_block as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = (block_off - offset_start) as u64;
            let pointer = err_if_zero(inode.singly_indirect_block_pointers)?;

            self.free_pointer(self.to_addr(pointer) + off * size_of::<Block>() as u64)?;

            if block_off == offset_start {
                let pointer = err_if_zero(inode.singly_indirect_block_pointers)?;
                self.free_block(pointer)?;
                inode.singly_indirect_block_pointers = Block(0);
                self.disk.borrow_mut().write_struct(inode_addr, inode)?;
            }
            return Ok(());
        }

        // DOUBLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end += (blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let doubly_indirect = err_if_zero(inode.doubly_indirect_block_pointers)?;

            let off_doubly = (block_off - offset_start) / blocknumber_per_block as u64;
            let addr_pointer_to_pointer =
                self.to_addr(doubly_indirect) + off_doubly * size_of::<Block>() as u64;

            let pointer_to_pointer: Block = err_if_zero(
                self.disk
                    .borrow_mut()
                    .read_struct(addr_pointer_to_pointer)?,
            )?;
            let off = (block_off - offset_start) % blocknumber_per_block as u64;

            self.free_pointer(self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64)?;

            if off == 0 {
                self.free_pointer(addr_pointer_to_pointer)?;
            }

            if block_off == offset_start {
                let pointer = err_if_zero(inode.doubly_indirect_block_pointers)?;
                self.free_block(pointer)?;
                inode.doubly_indirect_block_pointers = Block(0);
                self.disk.borrow_mut().write_struct(inode_addr, inode)?;
            }
            return Ok(());
        }

        // TRIPLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end +=
            (blocknumber_per_block * blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off_triply =
                (block_off - offset_start) / (blocknumber_per_block * blocknumber_per_block) as u64;

            let tripply_indirect = err_if_zero(inode.triply_indirect_block_pointers)?;

            let addr_pointer_to_pointer_to_pointer =
                self.to_addr(tripply_indirect) + off_triply * size_of::<Block>() as u64;
            let pointer_to_pointer_to_pointer: Block = err_if_zero(
                self.disk
                    .borrow_mut()
                    .read_struct(addr_pointer_to_pointer_to_pointer)?,
            )?;

            let off_doubly = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                / blocknumber_per_block as u64) as u64;

            let addr_pointer_to_pointer = self.to_addr(pointer_to_pointer_to_pointer)
                + off_doubly * size_of::<Block>() as u64;

            let pointer_to_pointer: Block = err_if_zero(
                self.disk
                    .borrow_mut()
                    .read_struct(addr_pointer_to_pointer)?,
            )?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                % blocknumber_per_block as u64) as u64;

            self.free_pointer(self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64)?;

            if off == 0 {
                self.free_pointer(addr_pointer_to_pointer)?;
            }

            if off_doubly == 0 {
                self.free_pointer(addr_pointer_to_pointer_to_pointer)?;
            }

            if block_off == offset_start {
                let pointer = err_if_zero(inode.triply_indirect_block_pointers)?;
                self.free_block(pointer)?;
                inode.triply_indirect_block_pointers = Block(0);
                self.disk.borrow_mut().write_struct(inode_addr, inode)?;
            }
            return Ok(());
        }
        Err(LinuxError::EFBIG)
    }

    /// Get the file location at offset 'offset'
    fn inode_data_may_alloc(
        &mut self,
        (inode, inode_addr): (&mut Inode, InodeAddr),
        offset: u64,
    ) -> LinuxResult<u64> {
        let block_off = offset / self.block_size as u64;
        let blocknumber_per_block = self.block_size as usize / size_of::<Block>();

        // SIMPLE ADDRESSING
        let mut offset_start = 0;
        let mut offset_end = 12;
        if block_off >= offset_start && block_off < offset_end {
            if inode.direct_block_pointers[block_off as usize] == Block(0) {
                inode.direct_block_pointers[block_off as usize] =
                    self.alloc_block().ok_or(LinuxError::ENOSPC)?;
                self.disk.borrow_mut().write_struct(inode_addr, inode)?;
            }
            return Ok(self.to_addr(err_if_zero(
                inode.direct_block_pointers[block_off as usize],
            )?) + offset % self.block_size as u64);
        }

        // SINGLY INDIRECT ADDRESSING
        // 12 * blocksize .. 12 * blocksize + (blocksize / 4) * blocksize
        offset_start = offset_end;
        offset_end += blocknumber_per_block as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = block_off - offset_start;

            let singly_indirect = err_if_zero({
                if inode.singly_indirect_block_pointers == Block(0) {
                    inode.singly_indirect_block_pointers =
                        self.alloc_block().ok_or(LinuxError::ENOSPC)?;
                    self.disk.borrow_mut().write_struct(inode_addr, inode)?;
                }
                inode.singly_indirect_block_pointers
            })?;

            let pointer: Block = self
                .alloc_pointer(self.to_addr(singly_indirect) + off * size_of::<Block>() as u64)?;

            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }

        // DOUBLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end += (blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = (block_off - offset_start) / blocknumber_per_block as u64;
            let doubly_indirect = err_if_zero({
                if inode.doubly_indirect_block_pointers == Block(0) {
                    inode.doubly_indirect_block_pointers =
                        self.alloc_block().ok_or(LinuxError::ENOSPC)?;
                    self.disk.borrow_mut().write_struct(inode_addr, inode)?;
                }
                inode.doubly_indirect_block_pointers
            })?;
            let pointer_to_pointer: Block = self
                .alloc_pointer(self.to_addr(doubly_indirect) + off * size_of::<Block>() as u64)?;
            let off = (block_off - offset_start) % blocknumber_per_block as u64;
            let pointer: Block = self.alloc_pointer(
                self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64,
            )?;
            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }

        // TRIPLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end +=
            (blocknumber_per_block * blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off =
                (block_off - offset_start) / (blocknumber_per_block * blocknumber_per_block) as u64;

            let tripply_indirect = err_if_zero({
                if inode.triply_indirect_block_pointers == Block(0) {
                    inode.triply_indirect_block_pointers =
                        self.alloc_block().ok_or(LinuxError::ENOSPC)?;
                    self.disk.borrow_mut().write_struct(inode_addr, inode)?;
                }
                inode.triply_indirect_block_pointers
            })?;
            let pointer_to_pointer_to_pointer: Block = self
                .alloc_pointer(self.to_addr(tripply_indirect) + off * size_of::<Block>() as u64)?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                / blocknumber_per_block as u64) as u64;
            let pointer_to_pointer: Block = self.alloc_pointer(
                self.to_addr(pointer_to_pointer_to_pointer) + off * size_of::<Block>() as u64,
            )?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                % blocknumber_per_block as u64) as u64;
            let pointer: Block = self.alloc_pointer(
                self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64,
            )?;

            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }
        Err(LinuxError::EFBIG)
    }

    /// Get the file location at offset 'offset'
    /// Return which block store the file data at offset T
    /// Simple Read without CACHE
    fn inode_data_xxx(&self, inode: &mut Inode, offset: u64) -> LinuxResult<u64> {
        let block_off = offset / self.block_size as u64;
        let blocknumber_per_block = self.block_size as usize / size_of::<Block>();

        // SIMPLE ADDRESSING
        let mut offset_start = 0;
        let mut offset_end = 12;
        if block_off >= offset_start && block_off < offset_end {
            return Ok(self.to_addr(err_if_zero(
                inode.direct_block_pointers[block_off as usize],
            )?) + offset % self.block_size as u64);
        }

        // SINGLY INDIRECT ADDRESSING
        // 12 * blocksize .. 12 * blocksize + (blocksize / 4) * blocksize
        offset_start = offset_end;
        offset_end += blocknumber_per_block as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = block_off - offset_start;

            let singly_indirect = err_if_zero(inode.singly_indirect_block_pointers)?;

            let pointer: Block =
                self.pointer(self.to_addr(singly_indirect) + off * size_of::<Block>() as u64)?;

            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }

        // DOUBLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end += (blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = (block_off - offset_start) / blocknumber_per_block as u64;
            let doubly_indirect = err_if_zero(inode.doubly_indirect_block_pointers)?;
            let pointer_to_pointer: Block =
                self.pointer(self.to_addr(doubly_indirect) + off * size_of::<Block>() as u64)?;
            let off = (block_off - offset_start) % blocknumber_per_block as u64;
            let pointer: Block =
                self.pointer(self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64)?;
            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }

        // TRIPLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end +=
            (blocknumber_per_block * blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off =
                (block_off - offset_start) / (blocknumber_per_block * blocknumber_per_block) as u64;

            let tripply_indirect = err_if_zero(inode.triply_indirect_block_pointers)?;
            let pointer_to_pointer_to_pointer: Block =
                self.pointer(self.to_addr(tripply_indirect) + off * size_of::<Block>() as u64)?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                / blocknumber_per_block as u64) as u64;
            let pointer_to_pointer: Block = self.pointer(
                self.to_addr(pointer_to_pointer_to_pointer) + off * size_of::<Block>() as u64,
            )?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                % blocknumber_per_block as u64) as u64;
            let pointer: Block =
                self.pointer(self.to_addr(pointer_to_pointer) + off * size_of::<Block>() as u64)?;

            return Ok(self.to_addr(pointer) + offset % self.block_size as u64);
        }
        Err(LinuxError::EFBIG)
    }

    /// Get the file location at offset 'offset'
    /// Return which block store the file data at offset T
    /// Simple Read
    fn inode_data(&mut self, inode: &Inode, offset: u64) -> LinuxResult<u64> {
        let block_off = offset >> self.block_shift as u64;
        let blocknumber_per_block = self.block_size as usize / size_of::<Block>();
        let blocknumber_per_block_mask = blocknumber_per_block - 1;
        let blocknumber_per_block_shift = usize::trailing_zeros(blocknumber_per_block);

        // SIMPLE ADDRESSING
        let mut offset_start = 0;
        let mut offset_end = 12;
        if block_off >= offset_start && block_off < offset_end {
            return Ok(self.to_addr(err_if_zero(
                inode.direct_block_pointers[block_off as usize],
            )?) + (offset & self.block_mask as u64));
        }

        // SINGLY INDIRECT ADDRESSING
        // 12 * blocksize .. 12 * blocksize + (blocksize / 4) * blocksize
        offset_start = offset_end;
        offset_end += blocknumber_per_block as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = block_off - offset_start;
            let singly_indirect = err_if_zero(inode.singly_indirect_block_pointers)?;

            let addr = self.to_addr(singly_indirect);
            let pointer = self.get_pointer(addr, off, Level::L1)?;
            return Ok(self.to_addr(pointer) + (offset & self.block_mask as u64));
        }

        // DOUBLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end += (blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off = (block_off - offset_start) >> blocknumber_per_block_shift as u64;
            let doubly_indirect = err_if_zero(inode.doubly_indirect_block_pointers)?;

            let addr = self.to_addr(doubly_indirect);
            let pointer_to_pointer = self.get_pointer(addr, off, Level::L1)?;

            let off = (block_off - offset_start) & blocknumber_per_block_mask as u64;

            let addr = self.to_addr(pointer_to_pointer);
            let pointer = self.get_pointer(addr, off, Level::L2)?;

            return Ok(self.to_addr(pointer) + (offset & self.block_mask as u64));
        }

        // TRIPLY INDIRECT ADDRESSING
        offset_start = offset_end;
        offset_end +=
            (blocknumber_per_block * blocknumber_per_block * blocknumber_per_block) as u64;
        if block_off >= offset_start && block_off < offset_end {
            let off =
                (block_off - offset_start) / (blocknumber_per_block * blocknumber_per_block) as u64;
            let tripply_indirect = err_if_zero(inode.triply_indirect_block_pointers)?;

            let addr = self.to_addr(tripply_indirect);
            let pointer_to_pointer_to_pointer = self.get_pointer(addr, off, Level::L1)?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                >> blocknumber_per_block_shift as u64) as u64;

            let addr = self.to_addr(pointer_to_pointer_to_pointer);
            let pointer_to_pointer = self.get_pointer(addr, off, Level::L2)?;

            let off = (((block_off - offset_start)
                % (blocknumber_per_block * blocknumber_per_block) as u64)
                & blocknumber_per_block_mask as u64) as u64;

            let addr = self.to_addr(pointer_to_pointer);
            let pointer = self.get_pointer(addr, off, Level::L3)?;

            return Ok(self.to_addr(pointer) + (offset & self.block_mask as u64));
        }
        Err(LinuxError::EFBIG)
    }

    /// Get a inode pointer
    #[inline(always)]
    fn get_pointer(&mut self, addr: u64, off: u64, level: Level) -> LinuxResult<Block> {
        Ok(*match self.cache.get(addr, off as usize, level) {
            Some(p) => p,
            None => {
                let v = self.cache.update_layer(addr, level);
                unsafe {
                    self.disk.borrow_mut().read_buffer(
                        addr,
                        core::slice::from_raw_parts_mut(
                            v.as_mut_ptr() as *mut u8,
                            self.block_size as usize,
                        ),
                    )?
                };
                self.cache
                    .get(addr, off as usize, level)
                    .expect("Must be founded !")
            }
        })
    }
}

const NB_LAYERS: usize = 3;

/// Multi layer cache
#[derive(Debug)]
struct Cache<K, T> {
    entries: [CacheEntry<K, T>; NB_LAYERS],
}

impl<K: Eq + PartialEq + Copy, T: Clone + Default> Cache<K, T> {
    /// Create a new multi layer cache
    fn new(nb_elems: usize) -> Self {
        let mut entries: [MaybeUninit<CacheEntry<K, T>>; NB_LAYERS] =
            MaybeUninit::uninit_array();
        for entry in entries.iter_mut() {
            entry.write(CacheEntry::new(nb_elems));
        }
        Self {
            entries: unsafe { MaybeUninit::array_assume_init(entries) },
        }
    }

    /// Invalidate all the layers()
    fn invalidate(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.invalidate();
        }
    }

    /// Try to get a layer borrowed data
    fn get(&self, idx: K, offset: usize, level: Level) -> Option<&T> {
        self.entries[get_index(level)].get(idx).map(|v| &v[offset])
    }

    /// Update a layer and get a mutable reference to his content
    fn update_layer(&mut self, idx: K, level: Level) -> &mut Vec<T> {
        self.entries[get_index(level)].update_layer(idx)
    }
}

fn get_index(level: Level) -> usize {
    use Level::*;
    match level {
        L1 => NB_LAYERS - 3,
        L2 => NB_LAYERS - 2,
        L3 => NB_LAYERS - 1,
    }
}

#[derive(Debug, Copy, Clone)]
enum Level {
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone)]
struct CacheEntry<K, T> {
    idx: Option<K>,
    data: Vec<T>,
}

impl<K: Eq + PartialEq + Copy, T: Clone + Default> CacheEntry<K, T> {
    fn new(nb_elems: usize) -> Self {
        Self {
            idx: None,
            data: vec![Default::default(); nb_elems],
        }
    }

    fn invalidate(&mut self) {
        self.idx = None;
    }

    fn get(&self, idx: K) -> Option<&Vec<T>> {
        if let Some(stored_idx) = self.idx {
            if stored_idx == idx {
                return Some(&self.data);
            }
        }
        None
    }

    fn update_layer(&mut self, idx: K) -> &mut Vec<T> {
        self.idx = Some(idx);
        &mut self.data
    }
}

impl Ext2Disk for Disk {
    fn write_buffer(&mut self, offset: u64, mut buf: &[u8]) -> LinuxResult<u64> {
        let size = self.size();
        if offset > size {
            error!("Seek beyond the end of the block device");
        }
        self.set_position(offset);

        let mut write_len = 0;
        while !buf.is_empty() {
            match self.write_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &buf[n..];
                    write_len += n;
                }
                Err(_) => return Err(LinuxError::EIO),
            }
        }
        Ok(write_len as u64)
    }

    fn read_buffer(&mut self, offset: u64, mut buf: &mut [u8]) -> LinuxResult<u64> {
        let size = self.size();
        if offset > size {
            error!("Seek beyond the end of the block device");
        }
        self.set_position(offset);

        let mut read_len = 0;
        while !buf.is_empty() {
            match self.read_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_len += n;
                }
                Err(_) => return Err(LinuxError::EIO),
            }
        }
        Ok(read_len as u64)
    }
}

impl VfsOps for Ext2Fs {
    fn root_dir(&self) -> VfsNodeRef {
        let path = Path::new("");
        let entry = self.inner.lock()._find_entry(2, &path).unwrap().unwrap();
        Arc::new(Ext2Inode::new(entry))
    }
}

unsafe impl Sync for Ext2Fs {}
unsafe impl Send for Ext2Fs {}

struct Ext2Inode {
    entry: Entry,
    curr_offset: AtomicU64,
}

impl Ext2Inode {
    pub fn new(entry: Entry) -> Self {
        Self {
            entry,
            curr_offset: AtomicU64::new(0),
        }
    }
}

impl VfsNodeOps for Ext2Inode {
    fn get_ino(&self) -> usize {
        self.entry.directory.get_inode() as usize
    }

    fn create(&self, path: &str, ty: VfsNodeType, uid: u32, gid: u32, mode: i32) -> VfsResult {
        info!("create path: {} {:?}", path, ty);

        match ty {
            VfsNodeType::File => {
                let ino = self.entry.directory.get_inode();
                let _ = Ext2Fs::get().create_file(ino, path, uid, gid, mode);
                Ok(())
            }
            VfsNodeType::Dir => {
                let ino = self.entry.directory.get_inode();
                let _ = Ext2Fs::get().create_dir(ino, path, uid, gid);
                Ok(())
            }
            _ => Err(VfsError::Unsupported),
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        info!("remove at ext2: {}", path);
        let ino = self.entry.directory.get_inode();
        Ok(Ext2Fs::get().remove(ino, path)?)
    }

    fn lookup(self: Arc<Self>, path: &str, _flags: i32) -> VfsResult<(VfsNodeRef, String)> {
        let ino = self.entry.directory.get_inode();
        info!("VfsNode: lookup path: {} ret ino: {}", path, ino);
        Ok((Ext2Fs::get().lookup(ino, path)?, String::new()))
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        debug!("get_attr ino: {}", self.entry.directory.get_inode());
        let inode = self.entry.inode;
        let perm = inode.type_and_perm.0 as u32 & !SFlag::S_IFMT.bits();
        let perm = VfsNodePerm::from_bits_truncate(perm as u16);
        let node_type = match inode.type_and_perm.extract_type() {
            SFlag::S_IFREG => VfsNodeType::File,
            SFlag::S_IFDIR => VfsNodeType::Dir,
            SFlag::S_IFLNK => VfsNodeType::SymLink,
            _ => panic!("unsupport type {:#x}", inode.type_and_perm.0),
        };
        Ok(VfsNodeAttr::new(
            perm, node_type, inode.low_size as u64, inode.nbr_disk_sectors as u64,
            inode.user_id.into(), inode.group_id.into()
        ))
    }

    fn getdents(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        assert!(self.entry.inode.type_and_perm.is_directory());
        let ino = self.entry.directory.get_inode();
        Ok(Ext2Fs::get().read_dir(ino, offset, buf).unwrap() as usize)
    }

    fn read_at(&self, mut offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        assert!(!self.entry.inode.type_and_perm.is_directory());
        let ino = self.entry.directory.get_inode();
        let ret = Ext2Fs::get().read_at(ino, &mut offset, buf).unwrap();
        self.curr_offset.store(offset, Ordering::Relaxed);
        info!("read_at[file]: ret {} offset {}", ret, offset);
        Ok(ret as usize)
    }

    fn write_at(&self, mut offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let ino = self.entry.directory.get_inode();
        let ret = Ext2Fs::get().write_at(ino, &mut offset, buf).unwrap();
        self.curr_offset.store(offset, Ordering::Relaxed);
        info!("write_at: ret {} offset {}", ret, offset);
        Ok(ret as usize)
    }

    fn truncate(&self, size: u64) -> VfsResult {
        info!("truncate");
        let ino = self.entry.directory.get_inode();
        Ok(Ext2Fs::get().truncate(ino, size)?)
    }
}

/// Magic iterator over the entire fileSytem
struct EntryIter<'a> {
    filesystem: &'a Ext2Filesystem,
    inode: (Inode, u64),
    curr_offset: u32,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = (DirectoryEntry, u32);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(d) = self
            .filesystem
            .find_entry((&mut self.inode.0, self.inode.1), self.curr_offset as u64)
        {
            let curr_offset = self.curr_offset;
            self.curr_offset += d.get_size() as u32;
            if d.get_inode() == 0 {
                self.next()
            } else {
                Some((d, curr_offset))
            }
        } else {
            None
        }
    }
}

pub trait Ext2Disk {
    fn write_buffer(&mut self, offset: u64, buf: &[u8]) -> LinuxResult<u64>;
    fn read_buffer(&mut self, offset: u64, buf: &mut [u8]) -> LinuxResult<u64>;

    /// Write a particulary struct inside file object
    fn write_struct<C: Copy>(&mut self, offset: u64, t: &C) -> LinuxResult<u64> {
        let s = unsafe { core::slice::from_raw_parts(t as *const _ as *const u8, size_of::<C>()) };
        self.write_buffer(offset, s)
    }

    /// Read a particulary struct in file object
    fn read_struct<C: Copy>(&mut self, offset: u64) -> LinuxResult<C> {
        let t = MaybeUninit::<C>::uninit();
        let count = self.read_buffer(offset, unsafe {
            core::slice::from_raw_parts_mut(t.as_ptr() as *mut u8, size_of::<C>())
        })?;
        let t = unsafe { t.assume_init() };
        if count as usize != size_of::<C>() {
            return Err(LinuxError::EIO);
        }
        Ok(t)
    }
}

unsafe fn libc_memcmp(s1: *const u8, s2: *const u8, n: usize) -> bool {
    for i in 0..n {
        if *s1.add(i) != *s2.add(i) {
            return false;
        }
    }
    true
}

fn def_mode() -> Mode {
    Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH
}
