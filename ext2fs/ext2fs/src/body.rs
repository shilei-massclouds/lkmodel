//! This module provide common structures and methods for EXT2 filesystems

mod inode;
mod typeperm;
pub mod directory_entry;

pub use inode::{Inode, gid_t, uid_t};
pub use typeperm::{TypePerm, Mode, SFlag};
pub use directory_entry::{DirectoryEntry, DirectoryEntryType};

use core::{borrow::Borrow, cmp::Ordering};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(align(512))]
pub struct Entry {
    pub directory: DirectoryEntry,
    pub inode: Inode,
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let s1: &str = self.borrow();
        let s2: &str = other.borrow();
        Some(s1.cmp(s2))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl Borrow<str> for Entry {
    fn borrow(&self) -> &str {
        unsafe { self.directory.get_filename() }
    }
}
