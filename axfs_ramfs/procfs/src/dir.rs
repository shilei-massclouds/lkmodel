use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::{string::String, vec::Vec};
use axfs_vfs::alloc_ino;
use axtype::S_ISGID;
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType};
use axfs_vfs::{VfsError, VfsResult};
use spin::RwLock;
use axtype::split_path;

use crate::file::{FileNode, SymLinkNode};

pub type LookupOp = fn(Arc<DirNode>, &str, i32) -> VfsResult<VfsNodeRef>;
pub type GetDentsOp = fn(Arc<DirNode>, u64, &mut [u8]) -> VfsResult<usize>;

/// The directory node in the Proc filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct DirNode {
    this: Weak<DirNode>,
    parent: RwLock<Weak<dyn VfsNodeOps>>,
    pub children: RwLock<BTreeMap<String, VfsNodeRef>>,
    ino: usize,
    uid: RwLock<u32>,
    gid: RwLock<u32>,
    mode: RwLock<i32>,
    lookup_op: Option<LookupOp>,
    getdents_op: Option<GetDentsOp>,
    dname: String,
}

impl DirNode {
    pub(super) fn new(
        parent: Option<Weak<dyn VfsNodeOps>>,
        uid: u32, gid: u32, mode: i32,
        lookup_op: Option<LookupOp>,
        getdents_op: Option<GetDentsOp>,
        dname: &str
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            parent: RwLock::new(parent.unwrap_or_else(|| Weak::<Self>::new())),
            children: RwLock::new(BTreeMap::new()),
            ino: alloc_ino(),
            uid: RwLock::new(uid),
            gid: RwLock::new(gid),
            mode: RwLock::new(mode),
            lookup_op,
            getdents_op,
            dname: String::from(dname),
        })
    }

    #[inline]
    pub fn dname(&self) -> String {
        self.dname.clone()
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
            VfsNodeType::File => Arc::new(FileNode::new(None, "", uid, gid, mode)),
            VfsNodeType::Dir => Self::new(Some(self.this.clone()), uid, gid, mode, None, None, ""),
            VfsNodeType::SymLink => Arc::new(SymLinkNode::new(uid, gid)),
            _ => return Err(VfsError::Unsupported),
        };
        self.children.write().insert(name.into(), node.clone());
        Ok(node)
    }

    /// Fill a existed node with the given name into this directory.
    pub fn fill_node(&self, name: &str, node: VfsNodeRef) -> VfsResult {
        if self.exist(name) {
            log::error!("AlreadyExists {}", name);
            return Err(VfsError::AlreadyExists);
        }
        self.children.write().insert(name.into(), node.clone());
        info!("fill_node with name: {}", name);
        Ok(())
    }

    /// Removes a node by the given name in this directory.
    pub fn remove_node(&self, name: &str) -> VfsResult {
        info!("remove_node name {} ..", name);
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
}

impl VfsNodeOps for DirNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    // Todo: use it to replace `create(&self, )`.
    fn create_child(&self, fname: &str, ty: VfsNodeType, uid: u32, gid: u32, mode: i32) -> VfsResult<VfsNodeRef> {
        assert!(fname.find('/').is_none(), "bad filename {}", fname);
        assert!(!fname.is_empty());
        assert!(fname != ".");
        assert!(fname != "..");
        info!("create child [{:?}] '{}'", ty, fname);
        self.create_node(fname, ty, uid, gid, mode)
    }

    fn link_child(&self, fname: &str, node: VfsNodeRef) -> VfsResult {
        info!("link_child: {}", fname);
        assert!(fname.find('/').is_none(), "bad filename {}", fname);
        assert!(!fname.is_empty());
        assert!(fname != ".");
        assert!(fname != "..");
        self.fill_node(fname, node)
    }

    /*
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
    */

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(
            4096, 0, *self.uid.read(), *self.gid.read(), *self.mode.read()
        ))
    }

    /*
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
    */

    fn lookup(self: Arc<Self>, path: &str, flags: i32) -> VfsResult<(VfsNodeRef, String)> {
        info!("lookup: {} flags {:#o}\n", path, flags);

        error!("begin: path {}", path);
        let (name, rest) = split_path(path);
        let node = match name {
            "" | "." => Ok(self.clone() as VfsNodeRef),
            ".." => self.parent().ok_or(VfsError::NotFound),
            _ => {
                match self.children.read().get(name).cloned() {
                    Some(n) => Ok(n),
                    None => {
                        if let Some(lookup_op) = self.lookup_op {
                            let n = lookup_op(self.clone(), &path, flags)?;
                            if n.get_attr()?.is_symlink() {
                                return Ok((n, String::new()));
                            }
                            Ok(n)
                        } else {
                            Err(VfsError::NotFound)
                        }
                    }
                }
            }
        }?;

        if let Some(rest) = rest {
            debug!("lookup: rest {}", rest);
            return node.lookup(rest, flags);
        } else {
            return Ok((node, String::new()));
        }
    }

    /*
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
        log::info!("create {:?} at procfs: {}", ty, path);
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
                        if let Some(linkname) = self.handle_symlink(subdir.clone(), 0, false) {
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
        log::info!("remove at procfs: {}", path);
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
                        if let Some(linkname) = self.handle_symlink(subdir.clone(), 0, false) {
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
    */

    fn getdents(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if let Some(op) = self.getdents_op {
            op(self.this.clone().upgrade().unwrap(), offset, buf)
        } else {
            unimplemented!("no getdents operation!");
        }
    }

    axfs_vfs::impl_vfs_dir_default! {}
}
