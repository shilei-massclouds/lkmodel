use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::string::String;
use axfs_vfs::{VfsDirEntry, VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType};
use axfs_vfs::{VfsError, VfsResult};
use spin::RwLock;
use axfs_vfs::alloc_ino;

/// The directory node in the device filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct DirNode {
    parent: RwLock<Weak<dyn VfsNodeOps>>,
    children: RwLock<BTreeMap<String, VfsNodeRef>>,
    ino: usize,
    uid: u32,
    gid: u32,
}

impl DirNode {
    pub(super) fn new(parent: Option<&VfsNodeRef>, uid: u32, gid: u32) -> Arc<Self> {
        let parent = parent.map_or(Weak::<Self>::new() as _, Arc::downgrade);
        Arc::new(Self {
            parent: RwLock::new(parent),
            children: RwLock::new(BTreeMap::new()),
            ino: alloc_ino(),
            uid,
            gid,
        })
    }

    pub(super) fn set_parent(&self, parent: Option<&VfsNodeRef>) {
        *self.parent.write() = parent.map_or(Weak::<Self>::new() as _, Arc::downgrade);
    }

    /// Create a subdirectory at this directory.
    pub fn mkdir(self: &Arc<Self>, name: &str, uid: u32, gid: u32) -> Arc<Self> {
        let parent = self.clone() as VfsNodeRef;
        let node = Self::new(Some(&parent), uid, gid);
        self.children.write().insert(String::from(name), node.clone());
        node
    }

    /// Add a node to this directory.
    pub fn add(&self, name: &str, node: VfsNodeRef) {
        self.children.write().insert(String::from(name), node);
    }
}

impl VfsNodeOps for DirNode {
    fn get_ino(&self) -> usize {
        self.ino
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new_dir(4096, 0, self.uid, self.gid, 0o777))
    }

    fn parent(&self) -> Option<VfsNodeRef> {
        self.parent.read().upgrade()
    }

    fn lookup(self: Arc<Self>, path: &str, flags: i32) -> VfsResult<(VfsNodeRef, String)> {
        let (name, rest) = split_path(path);
        let node = match name {
            "" | "." => Ok(self.clone() as VfsNodeRef),
            ".." => self.parent().ok_or(VfsError::NotFound),
            _ => self
                .children
                .read()
                .get(name)
                .cloned()
                .ok_or(VfsError::NotFound),
        }?;

        if let Some(rest) = rest {
            node.lookup(rest, flags)
        } else {
            Ok((node, String::new()))
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
        debug!("create {:?} at devfs: {}", ty, path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.create(rest, ty, uid, gid, mode),
                ".." => self.parent().ok_or(VfsError::NotFound)?.create(rest, ty, uid, gid, mode),
                _ => self
                    .children
                    .read()
                    .get(name)
                    .ok_or(VfsError::NotFound)?
                    .create(rest, ty, uid, gid, mode),
            }
        } else if name.is_empty() || name == "." || name == ".." {
            Ok(()) // already exists
        } else {
            Err(VfsError::PermissionDenied) // do not support to create nodes dynamically
        }
    }

    fn remove(&self, path: &str) -> VfsResult {
        log::debug!("remove at devfs: {}", path);
        let (name, rest) = split_path(path);
        if let Some(rest) = rest {
            match name {
                "" | "." => self.remove(rest),
                ".." => self.parent().ok_or(VfsError::NotFound)?.remove(rest),
                _ => self
                    .children
                    .read()
                    .get(name)
                    .ok_or(VfsError::NotFound)?
                    .remove(rest),
            }
        } else {
            Err(VfsError::PermissionDenied) // do not support to remove nodes dynamically
        }
    }

    fn link(&self, path: &str, node: VfsNodeRef) -> VfsResult {
        let (name, rest) = split_path(path);
        assert!(rest.is_none());
        assert!(!name.is_empty());
        self.add(name, node);
        Ok(())
    }

    axfs_vfs::impl_vfs_dir_default! {}
}

fn split_path(path: &str) -> (&str, Option<&str>) {
    let trimmed_path = path.trim_start_matches('/');
    trimmed_path.find('/').map_or((trimmed_path, None), |n| {
        (&trimmed_path[..n], Some(&trimmed_path[n + 1..]))
    })
}
