//! This file describe all the Directory Entry Header model

use core::fmt;
use core::ffi::c_char;
use core::mem::size_of;
use crate::Disk;
use axerrno::{LinuxResult, LinuxError};
use crate::{Ext2Disk, TypePerm, SFlag};

// Directories are inodes which contain some number of "entries" as their contents.
// These entries are nothing more than a name/inode pair. For instance the inode
// corresponding to the root directory might have an entry with the name of "etc" and an inode value of 50.
// A directory inode stores these entries in a linked-list fashion in its contents blocks.

// The root directory is Inode 2.

// The total size of a directory entry may be longer then the length of the name would imply
// (The name may not span to the end of the record), and records have to be aligned to 4-byte
// boundaries. Directory entries are also not allowed to span multiple blocks on the file-system,
// so there may be empty space in-between directory entries. Empty space is however not allowed
// in-between directory entries, so any possible empty space will be used as part of the preceding
// record by increasing its record length to include the empty space. Empty space may also be
// equivalently marked by a separate directory entry with an inode number of zero, indicating that directory entry should be skipped.

const FILENAME_MAX: usize = 255;

/// Directory Entry base structure
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(packed)]
pub struct DirectoryEntryHeader {
    /// Inode
    /*0 	3 	4*/
    pub inode: u32,
    /// Total size of this entry (Including all subfields)
    /*4 	5 	2*/
    pub size: u16,
    /// Name Length least-significant 8 bits
    /*6 	6 	1*/
    pub name_length: u8,
    /// Type indicator (only if the feature bit for "directory entries have file type byte" is set, else this is the most-significant 8 bits of the Name Length)
    /*7 	7 	1*/
    pub type_indicator: DirectoryEntryType,
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(packed)]
pub struct DirectoryEntry {
    pub header: DirectoryEntryHeader,
    pub filename: Filename,
}

impl fmt::Debug for DirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "filename: {:?}\nheader: {:#?}",
            unsafe { self.get_filename() },
            self.header
        )
    }
}

/// Directory Entry Type Indicators
// Value 	Type Description
// 0 	Unknown type
// 1 	Regular file
// 2 	Directory
// 3 	Character device
// 4 	Block device
// 5 	FIFO
// 6 	Socket
// 7 	Symbolic link (soft link)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
#[allow(unused)]
pub enum DirectoryEntryType {
    RegularFile = 1,
    Directory,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
    SymbolicLink,
}

impl TryFrom<TypePerm> for DirectoryEntryType {
    type Error = LinuxError;
    fn try_from(file_type: TypePerm) -> Result<Self, Self::Error> {
        Ok(match file_type.extract_type() {
            SFlag::S_IFSOCK => DirectoryEntryType::Socket,
            SFlag::S_IFLNK => DirectoryEntryType::SymbolicLink,
            SFlag::S_IFREG => DirectoryEntryType::RegularFile,
            SFlag::S_IFBLK => DirectoryEntryType::BlockDevice,
            SFlag::S_IFDIR => DirectoryEntryType::Directory,
            SFlag::S_IFCHR => DirectoryEntryType::CharacterDevice,
            SFlag::S_IFIFO => DirectoryEntryType::Fifo,
            _ => Err(LinuxError::EINVAL)?,
        })
    }
}

/// Implementations of the Directory Entry
impl DirectoryEntry {
    pub fn new(filename: &str, type_indicator: DirectoryEntryType, inode: u32) -> LinuxResult<Self> {
        Ok(Self {
            header: DirectoryEntryHeader {
                inode,
                size: size_of::<DirectoryEntry>() as u16,
                name_length: filename.len() as u8,
                type_indicator,
            },
            filename: filename.try_into()?,
        })
    }

    /// Set the file name
    #[allow(unused)]
    pub fn set_filename(&mut self, filename: &str) -> LinuxResult<()> {
        let filenamelen = filename.len();
        assert!(filenamelen <= FILENAME_MAX as usize);
        self.filename = filename.try_into()?;
        self.header.name_length = filenamelen as u8;
        Ok(())
    }

    /// Get the file name
    pub unsafe fn get_filename(&self) -> &str {
        let slice: &[u8] = core::slice::from_raw_parts(
            &self.filename.0 as *const c_char as *const u8,
            self.header.name_length as usize,
        );
        core::str::from_utf8_unchecked(slice)
    }

    pub fn get_inode(&self) -> u32 {
        self.header.inode
    }

    pub fn get_size(&self) -> u16 {
        self.header.size
    }

    pub fn size(&self) -> u16 {
        self.header.name_length as u16 + size_of::<DirectoryEntryHeader>() as u16
    }

    pub fn set_size(&mut self, new_size: u16) {
        self.header.size = new_size;
    }

    pub fn write_on_disk(&self, addr: u64, disk: &mut Disk) -> LinuxResult<u64>
    {
        disk.write_struct(addr, &self.header)?;
        disk.write_buffer(addr + size_of::<DirectoryEntryHeader>() as u64, unsafe {
            self.get_filename().as_bytes()
        })
    }
}

/// Newtype of filename
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Filename(pub [c_char; FILENAME_MAX as usize + 1]);

impl TryFrom<&str> for Filename {
    type Error = LinuxError;
    fn try_from(s: &str) -> Result<Self, LinuxError> {
        let mut n = [0; FILENAME_MAX as usize + 1];
        if s.len() > FILENAME_MAX as usize {
            return Err(LinuxError::ENAMETOOLONG);
        } else if s.len() == 0 {
            return Err(LinuxError::ENOTEMPTY);
        } else {
            for (n, c) in n.iter_mut().zip(s.bytes()) {
                if c == '/' as u8 {
                    return Err(LinuxError::ENOSTR);
                }
                *n = c as c_char;
            }
            Ok(Self(n))
        }
    }
}

impl Default for Filename {
    fn default() -> Self {
        Self([0; FILENAME_MAX as usize + 1])
    }
}

/// Debug boilerplate of filename
impl fmt::Debug for Filename {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let slice: &[u8] = core::slice::from_raw_parts(
                &self.0 as *const c_char as *const u8,
                FILENAME_MAX as usize,
            );
            let s = core::str::from_utf8_unchecked(slice);
            write!(f, "{:?}", s)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! make_test {
        (pass, $test_name: ident, $body: tt) => {
            #[test]
            fn $test_name() {
                $body
            }
        };
        (fail, $test_name: ident, $body: tt) => {
            #[test]
            #[should_panic]
            fn $test_name() {
                $body
            }
        };
    }

    macro_rules! make_filename_creation_test {
        ($body: block, $test_name: ident) => {
            make_test! {pass, $test_name, {
                Filename::try_from($body.as_str()).unwrap();
            }
            }
        };
        (fail, $body: block, $test_name: ident) => {
            make_test! {fail, $test_name, {
                Filename::try_from($body.as_str()).unwrap();
            }
            }
        };
        ($filename: expr, $test_name: ident) => {
            make_test! {pass, $test_name, {
                Filename::try_from($filename).unwrap();
            }
            }
        };
        (fail, $filename: expr, $test_name: ident) => {
            make_test! {fail, $test_name, {
                Filename::try_from($filename).unwrap();
            }
            }
        };
    }

    make_filename_creation_test! {fail, {
        let make_component = |count: usize| {
            let mut s = String::new();

            for _ in 0..count {
                s.push_str("a");
            }
            s
        };

        make_component(0)
    }, test_filename_posix_filename_cant_be_zero_len
    }

    make_filename_creation_test! {fail, {
        let make_component = |count: usize| {
            let mut s = String::new();

            for _ in 0..count {
                s.push_str("a");
            }
            s
        };

        make_component(FILENAME_MAX + 1)
    }, test_filename_posix_filename_cant_be_greater_than_name_max
    }

    make_filename_creation_test! {fail, {
        use std::str::FromStr;
        String::from_str("aaa/bbb.txt").expect("This should never happened") // the expect kind of breaks the test but hey, that should not happen anyway
    }, test_filename_posix_filename_cant_be_have_slash
    }

    make_filename_creation_test! {{
        let make_component = |count: usize| {
            let mut s = String::new();

            for _ in 0..count {
                s.push_str("a");
            }
            s
        };

        make_component(FILENAME_MAX)
    }, test_filename_posix_filename_can_be_name_max
    }

    make_filename_creation_test! {{
        let make_component = |count: usize| {
            let mut s = String::new();

            for _ in 0..count {
                s.push_str("a");
            }
            s
        };

        make_component(1)
    }, test_filename_posix_filename_can_be_one
    }
}
