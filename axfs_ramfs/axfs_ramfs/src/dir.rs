use core::mem;
use core::mem::transmute;
use core::ptr::copy_nonoverlapping;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::{string::String, vec::Vec};
use alloc::borrow::ToOwned;
use axfs_vfs::alloc_ino;
use axtype::{O_NOFOLLOW, S_ISGID};

use axfs_vfs::{VfsDirEntry, VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType};
use axfs_vfs::{VfsError, VfsResult, DT_, LinuxDirent64};
use axfs_vfs::VfsNodeAttrValid;
use spin::RwLock;

use crate::file::{FileNode, SymLinkNode};
use pipefs::PipeNode;

/// The directory node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct DirNode {
    this: Weak<DirNode>,
    parent: RwLock<Weak<dyn VfsNodeOps>>,
    children: RwLock<BTreeMap<String, VfsNodeRef>>,
    ino: usize,
    uid: RwLock<u32>,
    gid: RwLock<u32>,
    mode: RwLock<i32>,
}

impl DirNode {
    pub(super) fn new(parent: Option<Weak<dyn VfsNodeOps>>, uid: u32, gid: u32, mode: i32) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            parent: RwLock::new(parent.unwrap_or_else(|| Weak::<Self>::new())),
            children: RwLock::new(BTreeMap::new()),
            ino: alloc_ino(),
            uid: RwLock::new(uid),
            gid: RwLock::new(gid),
            mode: RwLock::new(mode),
        })
    }

    pub(super) fn set_parent(&self, parent: Option<&VfsNodeRef>) {
        *self.parent.write() = parent.map_or(Weak::<Self>::new() as _, Arc::downgrade);
    }

    /// Returns a string list of all entries in this directory.
    pub fn get_entries(&self) -> Vec<String> {
        self.children.read().keys().cloned().collect()
    }

    /// Checks whether a node with the given name exists in this directory.
    pub fn exist(&self, name: &str) -> bool {
        self.children.read().contains_key(name)
    }

    /// Creates a new node with the given name and type in this directory.
    pub fn create_node(&self, name: &str, ty: VfsNodeType, uid: u32, mut gid: u32, mode: i32) -> VfsResult<VfsNodeRef> {
        if self.exist(name) {
            log::error!("AlreadyExists {}", name);
            return Err(VfsError::AlreadyExists);
        }
        let dir_mode = *self.mode.read();
        info!("dir_mode: {:#o}", dir_mode);
        if (dir_mode & S_ISGID) != 0 {
            gid = *self.gid.read();
        }
        let node: VfsNodeRef = match ty {
            VfsNodeType::File => Arc::new(FileNode::new(uid, gid, mode)),
            VfsNodeType::Dir => Self::new(Some(self.this.clone()), uid, gid, mode),
            VfsNodeType::Fifo => Arc::new(PipeNode::new(uid, gid)),
            VfsNodeType::SymLink => Arc::new(SymLinkNode::new(uid, gid)),
            _ => return Err(VfsError::Unsupported),
        };
        self.children.write().insert(name.into(), node.clone());
        Ok(node)
    }

    /// Removes a node by the given name in this directory.
    pub fn remove_node(&self, name: &str) -> VfsResult {
        let mut children = self.children.write();
        let node = children.get(name).ok_or(VfsError::NotFound)?;
        if let Some(dir) = node.as_any().downcast_ref::<DirNode>() {
            if !dir.children.read().is_empty() {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }
        children.remove(name);
        Ok(())
    }

    fn handle_symlink(&self, node: VfsNodeRef, flags: i32, trailing: bool) -> Option<String> {
        if !node.get_attr().unwrap().is_symlink() {
            return None;
        }
        if trailing && (flags & O_NOFOLLOW) != 0 {
            return None;
        }
        let mut target = [0u8; 256];
        let ret = node.read_at(0, &mut target).unwrap();
        assert!(ret < target.len());
        let target = core::str::from_utf8(&target[0..ret]).unwrap();
        debug!("SymLink to target: {}", target);
        Some(target.to_owned())
    }
}

impl VfsNodeOps for DirNode {
    fn symlink(&self, path: &str, target: &str, uid: u32, gid: u32, mode: i32) -> VfsResult {
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.symlink(rest, target, uid, gid, mode),
                ".." => self.parent().ok_or(VfsError::NotFound)?.symlink(rest, target, uid, gid, mode),
                _ => {
                    let subdir = self
                        .children
                        .read()
                        .get(name)
                        .ok_or(VfsError::NotFound)?
                        .clone();
                    subdir.symlink(rest, target, uid, gid, mode)
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Ok(()) // already exists
        } else {
            let node = self.create_node(name, VfsNodeType::SymLink, uid, gid, mode)?;
            node.write_at(0, target.as_bytes())?;
            Ok(())
        }
    }

    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(
            4096, 0, *self.uid.read(), *self.gid.read(), *self.mode.read()
        ))
    }

    fn set_attr(&self, attr: &VfsNodeAttr, valid: &VfsNodeAttrValid) -> VfsResult {
        if valid.contains(VfsNodeAttrValid::ATTR_MODE) {
            *self.mode.write() = attr.mode();
        }
        if valid.contains(VfsNodeAttrValid::ATTR_UID) {
            *self.uid.write() = attr.uid();
        }
        if valid.contains(VfsNodeAttrValid::ATTR_GID) {
            *self.gid.write() = attr.gid();
        }
        Ok(())
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        self.parent.read().upgrade()
    }

    fn lookup(self: Arc<Self>, path: &str, flags: i32) -> VfsResult<VfsNodeRef> {
        info!("lookup: {} flags {:#o}\n", path, flags);
        let (name, rest) = split_path(path);
        let mut name = String::from(name);
        loop {
            let node = match name.as_str() {
                "" | "." => Ok(self.clone() as VfsNodeRef),
                ".." => self.parent().ok_or(VfsError::NotFound),
                _ => self
                    .children
                    .read()
                    .get(name.as_str())
                    .cloned()
                    .ok_or(VfsError::NotFound),
            }?;
            debug!("name {} rest {:?} {} flags {:#o}", name, rest, node.get_attr()?.is_symlink(), flags);
            if let Some(linkname) = self.handle_symlink(node.clone(), flags, rest.is_none()) {
                name = linkname;
                continue;
            }

            if let Some(rest) = rest {
                return node.lookup(rest, flags);
            } else {
                return Ok(node);
            }
        }
    }

    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        let children = self.children.read();
        let mut children = children.iter().skip(start_idx.max(2) - 2);
        for (i, ent) in dirents.iter_mut().enumerate() {
            match i + start_idx {
                0 => *ent = VfsDirEntry::new(".", VfsNodeType::Dir),
                1 => *ent = VfsDirEntry::new("..", VfsNodeType::Dir),
                _ => {
                    if let Some((name, node)) = children.next() {
                        *ent = VfsDirEntry::new(name, node.get_attr().unwrap().file_type());
                    } else {
                        return Ok(i);
                    }
                }
            }
        }
        Ok(dirents.len())
    }

    fn create(&self, path: &str, ty: VfsNodeType, uid: u32, gid: u32, mode: i32) -> VfsResult {
        log::info!("create {:?} at ramfs: {}", ty, path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.create(rest, ty, uid, gid, mode),
                ".." => self.parent().ok_or(VfsError::NotFound)?.create(rest, ty, uid, gid, mode),
                _ => {
                    let mut name = String::from(name);
                    loop {
                        let subdir = self
                            .children
                            .read()
                            .get(name.as_str())
                            .ok_or(VfsError::NotFound)?
                            .clone();
                        if let Some(linkname) = self.handle_symlink(subdir.clone(), 0, true) {
                            name = linkname;
                            continue;
                        }
                        return subdir.create(rest, ty, uid, gid, mode);
                    }
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Ok(()) // already exists
        } else {
            self.create_node(name, ty, uid, gid, mode)?;
            Ok(())
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        log::debug!("remove at ramfs: {}", path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.remove(rest),
                ".." => self.parent().ok_or(VfsError::NotFound)?.remove(rest),
                _ => {
                    let mut name = String::from(name);
                    loop {
                        let subdir = self
                            .children
                            .read()
                            .get(name.as_str())
                            .ok_or(VfsError::NotFound)?
                            .clone();
                        if let Some(linkname) = self.handle_symlink(subdir.clone(), 0, true) {
                            name = linkname;
                            continue;
                        }
                        return subdir.remove(rest);
                    }
                }
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Err(VfsError::InvalidInput) // remove '.' or '..
        } else {
            self.remove_node(name)
        }
    }

    fn getdents(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset != 0 {
            log::error!("NOTICE! todo: check offset[{}] and real length of directory!", offset);
            return Ok(0);
        }

        static mut INO_SEQ: u64 = 0;

        let children = self.children.read();
        let mut children = children.iter().skip((offset.max(2) - 2) as usize);

        let mut count = 0;
        for i in offset.. {
            let (mut name, ty) = match i + offset {
                0 => (String::from("."), DT_::DIR as u8),
                1 => (String::from(".."), DT_::DIR as u8),
                _ => {
                    if let Some((name, node)) = children.next() {
                        let ty = match node.get_attr().unwrap().file_type() {
                            VfsNodeType::File => DT_::REG as u8,
                            VfsNodeType::Dir => DT_::DIR as u8,
                            VfsNodeType::CharDevice => DT_::CHR as u8,
                            VfsNodeType::BlockDevice => DT_::BLK as u8,
                            VfsNodeType::Fifo => DT_::FIFO as u8,
                            VfsNodeType::Socket => DT_::SOCK as u8,
                            VfsNodeType::SymLink => DT_::LNK as u8,
                        };
                        (name.clone(), ty)
                    } else {
                        return Ok(count as usize);
                    }
                }
            };
            name.push('\0');
            let name_len = name.len();
            log::info!("[{}] name:{:?} [{}] {}", i, name.as_bytes(), name_len, name.len());

            let entry_size = mem::size_of::<LinuxDirent64>() + name_len;
            log::info!("entry_size : {}", entry_size);

            if count + entry_size > buf.len() {
                log::error!("buf for dirents overflow!");
                return Ok(count as usize);
            }

            let dirent: &mut LinuxDirent64 = unsafe {
                transmute(buf.as_mut_ptr().offset(count as isize))
            };
            dirent.d_ino = unsafe { INO_SEQ += 1; INO_SEQ };
            dirent.d_off = (count + entry_size) as i64;
            dirent.d_reclen = entry_size as u16;
            dirent.d_type = ty;

            unsafe {
                copy_nonoverlapping(
                    name.as_ptr(),
                    dirent.d_name.as_mut_ptr(),
                    name_len
                )
            };

            count += entry_size;
        }
        Ok(0)
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

fn split_path(path: &str) -> (&str, Option<&str>) {
    let trimmed_path = path.trim_start_matches('/');
    trimmed_path.find('/').map_or((trimmed_path, None), |n| {
        (&trimmed_path[..n], Some(&trimmed_path[n + 1..]))
    })
}
