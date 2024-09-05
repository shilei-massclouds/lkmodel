#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

use axerrno::{ax_err, AxError, AxResult};
use alloc::{string::String, sync::Arc};
use axfs_vfs::{VfsNodeRef, VfsNodeType};
use spinpreempt::SpinLock;
use axfs_vfs::RootDirectory;
use lazy_init::LazyInit;

pub struct FsStruct {
    pub users: i32,
    pub in_exec: bool,
    curr_path: String,
    curr_dir: Option<VfsNodeRef>,
    root_dir: Option<Arc<RootDirectory>>,
}

impl FsStruct {
    pub fn new() -> Self {
        Self {
            users: 1,
            in_exec: false,
            curr_path: String::from("/"),
            curr_dir: None,
            root_dir: None,
        }
    }

    pub fn init(&mut self, root_dir: Arc<RootDirectory>) {
        self.root_dir = Some(root_dir);
        self.curr_dir = Some(self.root_dir.as_ref().unwrap().clone());
        self.curr_path = "/".into();
    }

    pub fn copy_fs_struct(&mut self, fs: Arc<SpinLock<FsStruct>>) {
        let locked_fs = &fs.lock();
        self.root_dir = locked_fs.root_dir.as_ref().map(|root_dir| root_dir.clone());
        self.curr_dir = locked_fs.curr_dir.as_ref().map(|curr_dir| curr_dir.clone());
        self.curr_path = locked_fs.curr_path.clone();
    }
}

impl FsStruct {
    fn parent_node_of(&self, dir: Option<&VfsNodeRef>, path: &str) -> VfsNodeRef {
        if path.starts_with('/') {
            assert!(self.root_dir.is_some());
            self.root_dir.clone().unwrap()
        } else {
            dir.cloned().unwrap_or_else(|| self.curr_dir.clone().unwrap())
        }
    }

    pub fn lookup(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
        if path.is_empty() {
            return ax_err!(NotFound);
        }
        let node = self.parent_node_of(dir, path).lookup(path)?;
        if path.ends_with('/') && !node.get_attr()?.is_dir() {
            ax_err!(NotADirectory)
        } else {
            Ok(node)
        }
    }

    pub fn create_file(&self, dir: Option<&VfsNodeRef>, path: &str, ty: VfsNodeType) -> AxResult<VfsNodeRef> {
        if path.is_empty() {
            return ax_err!(NotFound);
        } else if path.ends_with('/') {
            return ax_err!(NotADirectory);
        }
        let parent = self.parent_node_of(dir, path);
        parent.create(path, ty)?;
        parent.lookup(path)
    }

    pub fn create_dir(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        match self.lookup(dir, path) {
            Ok(_) => ax_err!(AlreadyExists),
            Err(AxError::NotFound) => self.parent_node_of(dir, path).create(path, VfsNodeType::Dir),
            Err(e) => Err(e),
        }
    }

    pub fn current_dir(&self) -> AxResult<String> {
        Ok(self.curr_path.clone())
    }

    pub fn absolute_path(&self, path: &str) -> AxResult<String> {
        if path.starts_with('/') {
            Ok(axfs_vfs::path::canonicalize(path))
        } else {
            let path = self.curr_path.clone() + path;
            Ok(axfs_vfs::path::canonicalize(&path))
        }
    }

    pub fn set_current_dir(&mut self, path: &str) -> AxResult {
        let mut abs_path = self.absolute_path(path)?;
        if !abs_path.ends_with('/') {
            abs_path += "/";
        }
        if abs_path == "/" {
            self.curr_dir = Some(self.root_dir.as_ref().unwrap().clone());
            self.curr_path = "/".into();
            return Ok(());
        }

        let node = self.lookup(None, &abs_path)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            ax_err!(NotADirectory)
        } else if !attr.perm().owner_executable() {
            ax_err!(PermissionDenied)
        } else {
            self.curr_dir = Some(node);
            self.curr_path = abs_path;
            Ok(())
        }
    }
    pub fn remove_file(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        let node = self.lookup(dir, path)?;
        let attr = node.get_attr()?;
        if attr.is_dir() {
            ax_err!(IsADirectory)
        } else if !attr.perm().owner_writable() {
            ax_err!(PermissionDenied)
        } else {
            self.parent_node_of(dir, path).remove(path)
        }
    }
    pub fn remove_dir(&self, dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
        if path.is_empty() {
            return ax_err!(NotFound);
        }
        let path_check = path.trim_matches('/');
        if path_check.is_empty() {
            return ax_err!(DirectoryNotEmpty); // rm -d '/'
        } else if path_check == "."
            || path_check == ".."
            || path_check.ends_with("/.")
            || path_check.ends_with("/..")
        {
            return ax_err!(InvalidInput);
        }
        if self.root_dir.as_ref().unwrap().contains(&self.absolute_path(path)?) {
            return ax_err!(PermissionDenied);
        }

        let node = self.lookup(dir, path)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            ax_err!(NotADirectory)
        } else if !attr.perm().owner_writable() {
            ax_err!(PermissionDenied)
        } else {
            self.parent_node_of(dir, path).remove(path)
        }
    }
    pub fn rename(&self, old: &str, new: &str) -> AxResult {
        if self.parent_node_of(None, new).lookup(new).is_ok() {
            warn!("dst file already exist, now remove it");
            self.remove_file(None, new)?;
        }
        self.parent_node_of(None, old).rename(old, new)
    }
}

pub fn init_fs() -> Arc<SpinLock<FsStruct>> {
    INIT_FS.clone()
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();
    info!("Initialize fstree ...");

    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init();

    spinpreempt::init(cpu_id, dtb_pa);

    axmount::init(cpu_id, dtb_pa);
    let root_dir = axmount::init_root();
    let mut fs = FsStruct::new();
    fs.init(root_dir);

    INIT_FS.init_by(Arc::new(SpinLock::new(fs)));
}

static INIT_FS: LazyInit<Arc<SpinLock<FsStruct>>> = LazyInit::new();
