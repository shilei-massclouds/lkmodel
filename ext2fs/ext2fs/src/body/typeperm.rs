//! This file describe Type and Permissions first inode field and methods

use bitflags::bitflags;
use axerrno::LinuxError;

bitflags! {
    #[derive(PartialEq, Eq)]
    pub struct SFlag: u32 {
        const S_IFMT   = 0o170000;
        const S_IFSOCK = 0o140000;
        const S_IFLNK  = 0o120000;
        const S_IFREG  = 0o100000;
        const S_IFBLK  = 0o060000;
        const S_IFDIR  = 0o040000;
        const S_IFCHR  = 0o020000;
        const S_IFIFO  = 0o010000;
        const S_ISUID  = 0o004000;
        const S_ISGID  = 0o002000;
        const S_ISVTX  = 0o001000;
    }
}

bitflags! {
    pub struct Mode: u32 {
        const S_IRWXU = 0o700;
        const S_IRUSR = 0o400;
        const S_IWUSR = 0o200;
        const S_IXUSR = 0o100;

        const S_IRWXG = 0o070;
        const S_IRGRP = 0o040;
        const S_IWGRP = 0o020;
        const S_IXGRP = 0o010;

        const S_IRWXO = 0o007;
        const S_IROTH = 0o004;
        const S_IWOTH = 0o002;
        const S_IXOTH = 0o001;
    }
}

#[derive(Default, Debug, PartialEq, Copy, Clone, Eq)]
pub struct TypePerm(pub u16);

/*
lazy_static::lazy_static! {
    pub static ref SPECIAL_BITS: Mode = Mode::S_ISUID | Mode::S_ISGID | Mode::S_ISVTX;
    pub static ref PERMISSIONS_MASK: Mode = Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO;
}
*/
/*
// bitflags! {
//     #[derive(Default, Debug, PartialEq, Copy, Clone, Eq)]
//     pub struct TypePerm: u16 {
//         const S_IFMT = S_IFMT as u16;
//         const UNIX_SOCKET = S_IFSOCK as u16;
//         const SYMBOLIC_LINK = S_IFLNK as u16;
//         const REGULAR_FILE = S_IFREG as u16;
//         const BLOCK_DEVICE = S_IFBLK as u16;
//         const DIRECTORY = S_IFDIR as u16;
//         const CHARACTER_DEVICE = S_IFCHR as u16;
//         const FIFO = S_IFIFO as u16;

//         const SET_USER_ID = S_ISUID as u16;
//         const SET_GROUP_ID = S_ISGID as u16;
//         const STICKY_BIT = S_ISVTX as u16;
//         const SPECIAL_BITS = Self::SET_USER_ID.bits() |
//                             Self::SET_GROUP_ID.bits() |
//                             Self::STICKY_BIT.bits();

//         const S_IRWXU = Mode::S_IRWXU as u16;
//         const USER_READ_PERMISSION = S_IRUSR as u16;
//         const USER_WRITE_PERMISSION = S_IWUSR as u16;
//         const USER_EXECUTE_PERMISSION = S_IXUSR as u16;

//         const S_IRWXG = S_IRWXG as u16;
//         const GROUP_READ_PERMISSION = S_IRGRP as u16;
//         const GROUP_WRITE_PERMISSION = S_IWGRP as u16;
//         const GROUP_EXECUTE_PERMISSION = S_IXGRP as u16;

//         const S_IRWXO = S_IRWXO as u16;
//         const OTHER_READ_PERMISSION = S_IROTH as u16;
//         const OTHER_WRITE_PERMISSION = S_IWOTH as u16;
//         const OTHER_EXECUTE_PERMISSION = S_IXOTH as u16;
//         const PERMISSIONS_MASK = S_IRWXU as u16 |
//                                  S_IRWXG as u16 |
//                                  S_IRWXO as u16;
//     }
// }
*/

#[allow(unused)]
impl TypePerm {
    /*
    pub fn remove_mode(&mut self, mode: Mode) {
        let new_mode = self.0 & !mode.bits() as u16;
        self.0 = new_mode;
    }

    pub fn insert_mode(&mut self, mode: Mode) {
        let new_mode = self.0 | mode.bits() as u16;
        self.0 = new_mode;
    }
    */

    pub fn extract_type(self) -> SFlag {
        let mask = SFlag::S_IFMT;
        SFlag::from_bits_truncate(self.0 as u32) & mask
    }

    /*
    pub fn is_typed(&self) -> bool {
        !self.extract_type().is_empty()
    }

    pub fn is_character_device(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFCHR
    }

    pub fn is_fifo(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFIFO
    }
    */

    pub fn is_regular(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFREG
        //(self.0 as usize & S_IFMT) == S_IFREG
    }

    pub fn is_directory(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFLNK
    }

    /*
    pub fn is_socket(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFSOCK
    }

    pub fn is_block_device(&self) -> bool {
        SFlag::from_bits_truncate(self.0 as u32) == SFlag::S_IFBLK
    }

    /// returns the owner rights on the file, in a bitflags Amode
    pub fn owner_access(&self) -> AccessFlags {
        let mask = Mode::S_IRWXU;
        AccessFlags::from_bits(((self.0 as libc::mode_t & mask.bits()) >> 6) as i32)
            .expect("bits should be valid")
        //Amode::from_bits((*self & FileType::S_IRWXU).bits() as u32 >> 6)
        //    .expect("bits should be valid")
    }

    /// returns the group rights on the file, in a bitflags Amode
    pub fn group_access(&self) -> AccessFlags {
        let mask = Mode::S_IRWXG;
        AccessFlags::from_bits(((self.0 as libc::mode_t & mask.bits()) >> 3) as i32)
            .expect("bits should be valid")
    }

    /// returns the other rights on the file, in a bitflags Amode
    pub fn other_access(&self) -> AccessFlags {
        let mask = Mode::S_IRWXO;
        AccessFlags::from_bits((self.0 as libc::mode_t & mask.bits()) as i32)
            .expect("bits should be valid")
    }

    pub fn class_access(&self, class: PermissionClass) -> AccessFlags {
        match class {
            PermissionClass::Owner => self.owner_access(),
            PermissionClass::Group => self.group_access(),
            PermissionClass::Other => self.other_access(),
        }
    }

    /// Returns whether self is solely composed of special bits and/or file permissions bits
    pub fn is_pure_mode(&self) -> bool {
        let mask = *SPECIAL_BITS | *PERMISSIONS_MASK;
        let excess_bits = self.0 & !mask.bits() as u16;
        excess_bits == 0
    }
    pub fn extract_pure_mode(self) -> Self {
        let mask = *SPECIAL_BITS | *PERMISSIONS_MASK;
        Self(self.0 & mask.bits() as u16)
    }
    */
}

impl TryFrom<(u32, SFlag)> for TypePerm {
    type Error = LinuxError;
    fn try_from(values: (u32, SFlag)) -> Result<Self, Self::Error> {
        let (mode, filetype) = values;
        let mode = Mode::from_bits(mode).ok_or(LinuxError::EINVAL)?;
        Ok(TypePerm(mode.bits() as u16 | filetype.bits() as u16))
    }
}

/// Also known as File Classes in POSIX-2018.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(unused)]
pub enum PermissionClass {
    Owner,
    Group,
    Other,
}
