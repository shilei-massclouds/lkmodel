/// Filesystem attributes.
#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct FileSystemInfo {
    /// Type of filesystem
    pub f_type: u64,
    /// Optimal transfer block size
    pub f_bsize: u64,
    /// Total data blocks in filesystem
    pub f_blocks: u64,
    /// Free blocks in filesystem
    pub f_bfree: u64,
    /// Free blocks available to unprivileged user
    pub f_bavail: u64,
    /// Total inodes in filesystem
    pub f_files: u64,
    /// Free inodes in filesystem
    pub f_ffree: u64,
    /// Filesystem ID
    pub f_fsid: KernelFsid,
    /// Maximum length of filenames
    pub f_namelen: u64,
    /// Fragment size (since Linux 2.6)
    pub f_frsize: u64,
    /// Mount flags of filesystem (since Linux 2.6.36)
    pub f_flags: u64,
    /// Padding bytes reserved for future use
    pub f_spare: [u64; 4],
}

#[derive(Default, Debug, Clone, Copy)]
pub struct KernelFsid {
    _val: [i32; 2],
}

// #define ATTR_SIZE   (1 << 3)
// #define ATTR_ATIME  (1 << 4)
// #define ATTR_MTIME  (1 << 5)
// #define ATTR_CTIME  (1 << 6)
// #define ATTR_ATIME_SET  (1 << 7)
// #define ATTR_MTIME_SET  (1 << 8)
// #define ATTR_FORCE  (1 << 9) /* Not a change, but a change it */
// #define ATTR_KILL_SUID  (1 << 11)
// #define ATTR_KILL_SGID  (1 << 12)
// #define ATTR_FILE   (1 << 13)
// #define ATTR_KILL_PRIV  (1 << 14)
// #define ATTR_OPEN   (1 << 15) /* Truncating from open(O_TRUNC) */
// #define ATTR_TIMES_SET  (1 << 16)
// #define ATTR_TOUCH  (1 << 17)

bitflags::bitflags! {
    /// Node attributes valid-bits.
    #[derive(Debug, Clone, Copy)]
    pub struct VfsNodeAttrValid: u32 {
        const ATTR_MODE = (1 << 0);
        const ATTR_UID  = (1 << 1);
        const ATTR_GID  = (1 << 2);
    }
}

/// Node (file/directory) attributes.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VfsNodeAttr {
    /// File permission mode.
    mode: VfsNodePerm,
    /// File type.
    ty: VfsNodeType,
    /// Total size, in bytes.
    size: u64,
    /// Number of 512B blocks allocated.
    blocks: u64,
    /// uid
    uid: u32,
    /// gid
    gid: u32,
}

bitflags::bitflags! {
    /// Node (file/directory) permission mode.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct VfsNodePerm: u16 {
        /// Owner has set_uid_bit.
        const SET_UID = 0o4000;
        /// Directory has set_gid_bit.
        const SET_GID = 0o2000;
        /// Others cannot remove file not owned by themselves.
        const SET_VTX = 0o1000;

        /// Owner has read permission.
        const OWNER_READ = 0o400;
        /// Owner has write permission.
        const OWNER_WRITE = 0o200;
        /// Owner has execute permission.
        const OWNER_EXEC = 0o100;

        /// Group has read permission.
        const GROUP_READ = 0o40;
        /// Group has write permission.
        const GROUP_WRITE = 0o20;
        /// Group has execute permission.
        const GROUP_EXEC = 0o10;

        /// Others have read permission.
        const OTHER_READ = 0o4;
        /// Others have write permission.
        const OTHER_WRITE = 0o2;
        /// Others have execute permission.
        const OTHER_EXEC = 0o1;
    }
}

/// Node (file/directory) type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum VfsNodeType {
    #[default]
    /// FIFO (named pipe)
    Fifo = 0o1,
    /// Character device
    CharDevice = 0o2,
    /// Directory
    Dir = 0o4,
    /// Block device
    BlockDevice = 0o6,
    /// Regular file
    File = 0o10,
    /// Symbolic link
    SymLink = 0o12,
    /// Socket
    Socket = 0o14,
}

pub enum DT_ {
    #[allow(dead_code)]
    UNKNOWN = 0,
    FIFO = 1,
    CHR = 2,
    DIR = 4,
    BLK = 6,
    REG = 8,
    LNK = 10,
    SOCK = 12,
    #[allow(dead_code)]
    WHT = 14,
}

/// Directory entry.
pub struct VfsDirEntry {
    d_type: VfsNodeType,
    d_name: [u8; 63],
}

impl VfsNodePerm {
    /// Returns the default permission for a file.
    ///
    /// The default permission is `0o666` (owner/group/others can read and write).
    pub const fn default_file() -> Self {
        Self::from_bits_truncate(0o666)
    }

    /// Returns the default permission for a directory.
    ///
    /// The default permission is `0o755` (owner can read, write and execute,
    /// group/others can read and execute).
    pub const fn default_dir() -> Self {
        Self::from_bits_truncate(0o755)
    }

    pub fn set_mode(mode: u16) -> Self {
        Self::from_bits_truncate(mode)
    }

    /// Returns the underlying raw `st_mode` bits that contain the standard
    /// Unix permissions for this file.
    pub const fn mode(&self) -> u32 {
        self.bits() as u32
    }

    /// Returns a 9-bytes string representation of the permission.
    ///
    /// For example, `0o755` is represented as `rwxr-xr-x`.
    pub const fn rwx_buf(&self) -> [u8; 9] {
        let mut perm = [b'-'; 9];
        if self.contains(Self::OWNER_READ) {
            perm[0] = b'r';
        }
        if self.contains(Self::OWNER_WRITE) {
            perm[1] = b'w';
        }
        if self.contains(Self::OWNER_EXEC) {
            perm[2] = b'x';
        }
        if self.contains(Self::GROUP_READ) {
            perm[3] = b'r';
        }
        if self.contains(Self::GROUP_WRITE) {
            perm[4] = b'w';
        }
        if self.contains(Self::GROUP_EXEC) {
            perm[5] = b'x';
        }
        if self.contains(Self::OTHER_READ) {
            perm[6] = b'r';
        }
        if self.contains(Self::OTHER_WRITE) {
            perm[7] = b'w';
        }
        if self.contains(Self::OTHER_EXEC) {
            perm[8] = b'x';
        }
        perm
    }

    /// Whether the owner has read permission.
    pub const fn owner_readable(&self) -> bool {
        self.contains(Self::OWNER_READ)
    }

    /// Whether the owner has write permission.
    pub const fn owner_writable(&self) -> bool {
        self.contains(Self::OWNER_WRITE)
    }

    /// Whether the owner has execute permission.
    pub const fn owner_executable(&self) -> bool {
        self.contains(Self::OWNER_EXEC)
    }
}

impl VfsNodeType {
    /// Tests whether this node type represents a regular file.
    pub const fn is_file(self) -> bool {
        matches!(self, Self::File)
    }

    /// Tests whether this node type represents a directory.
    pub const fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }

    /// Tests whether this node type represents a symbolic link.
    pub const fn is_symlink(self) -> bool {
        matches!(self, Self::SymLink)
    }

    /// Returns `true` if this node type is a block device.
    pub const fn is_block_device(self) -> bool {
        matches!(self, Self::BlockDevice)
    }

    /// Returns `true` if this node type is a char device.
    pub const fn is_char_device(self) -> bool {
        matches!(self, Self::CharDevice)
    }

    /// Returns `true` if this node type is a fifo.
    pub const fn is_fifo(self) -> bool {
        matches!(self, Self::Fifo)
    }

    /// Returns `true` if this node type is a socket.
    pub const fn is_socket(self) -> bool {
        matches!(self, Self::Socket)
    }

    /// Returns a character representation of the node type.
    ///
    /// For example, `d` for directory, `-` for regular file, etc.
    pub const fn as_char(self) -> char {
        match self {
            Self::Fifo => 'p',
            Self::CharDevice => 'c',
            Self::Dir => 'd',
            Self::BlockDevice => 'b',
            Self::File => '-',
            Self::SymLink => 'l',
            Self::Socket => 's',
        }
    }
}

impl VfsNodeAttr {
    /// Creates a new `VfsNodeAttr` with the given permission mode, type, size
    /// and number of blocks.
    pub const fn new(mode: VfsNodePerm, ty: VfsNodeType, size: u64, blocks: u64, uid: u32, gid: u32) -> Self {
        Self {
            mode,
            ty,
            size,
            blocks,
            uid,
            gid,
        }
    }

    #[inline]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    #[inline]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    #[inline]
    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    #[inline]
    pub fn set_gid(&mut self, gid: u32) {
        self.gid = gid;
    }

    #[inline]
    pub fn set_mode(&mut self, mode: i32) {
        self.mode = VfsNodePerm::set_mode(mode as u16);
    }

    #[inline]
    pub const fn mode(&self) -> i32 {
        self.mode.mode() as i32
    }

    /// Creates a new `VfsNodeAttr` for a pipe, with the default file permission.
    pub const fn new_pipe(size: u64, blocks: u64, uid: u32, gid: u32) -> Self {
        Self {
            mode: VfsNodePerm::default_file(),
            ty: VfsNodeType::Fifo,
            size,
            blocks,
            uid,
            gid,
        }
    }

    /// Creates a new `VfsNodeAttr` for a symlink, with the default file permission.
    pub const fn new_symlink(size: u64, blocks: u64, uid: u32, gid: u32) -> Self {
        Self {
            mode: VfsNodePerm::default_file(),
            ty: VfsNodeType::SymLink,
            size,
            blocks,
            uid,
            gid,
        }
    }

    /// Creates a new `VfsNodeAttr` for a file, with the default file permission.
    pub fn new_file(size: u64, blocks: u64, uid: u32, gid: u32, mode: i32) -> Self {
        Self {
            mode: VfsNodePerm::set_mode(mode as u16),
            ty: VfsNodeType::File,
            size,
            blocks,
            uid,
            gid,
        }
    }

    /// Creates a new `VfsNodeAttr` for a directory, with the default directory
    /// permission.
    pub fn new_dir(size: u64, blocks: u64, uid: u32, gid: u32, mode: i32) -> Self {
        Self {
            mode: VfsNodePerm::set_mode(mode as u16),
            ty: VfsNodeType::Dir,
            size,
            blocks,
            uid,
            gid,
        }
    }

    /// Returns the size of the node.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the number of blocks the node occupies on the disk.
    pub const fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Returns the permission of the node.
    pub const fn perm(&self) -> VfsNodePerm {
        self.mode
    }

    /// Sets the permission of the node.
    pub fn set_perm(&mut self, perm: VfsNodePerm) {
        self.mode = perm
    }

    /// Returns the type of the node.
    pub const fn file_type(&self) -> VfsNodeType {
        self.ty
    }

    /// Whether the node is a file.
    pub const fn is_file(&self) -> bool {
        self.ty.is_file()
    }

    /// Whether the node is a directory.
    pub const fn is_dir(&self) -> bool {
        self.ty.is_dir()
    }

    /// Whether the node is a symlink.
    pub const fn is_symlink(&self) -> bool {
        self.ty.is_symlink()
    }
}

impl VfsDirEntry {
    /// Creates an empty `VfsDirEntry`.
    pub const fn default() -> Self {
        Self {
            d_type: VfsNodeType::File,
            d_name: [0; 63],
        }
    }

    /// Creates a new `VfsDirEntry` with the given name and type.
    pub fn new(name: &str, ty: VfsNodeType) -> Self {
        let mut d_name = [0; 63];
        if name.len() > d_name.len() {
            log::warn!(
                "directory entry name too long: {} > {}",
                name.len(),
                d_name.len()
            );
        }
        d_name[..name.len()].copy_from_slice(name.as_bytes());
        Self { d_type: ty, d_name }
    }

    /// Returns the type of the entry.
    pub fn entry_type(&self) -> VfsNodeType {
        self.d_type
    }

    /// Converts the name of the entry to a byte slice.
    pub fn name_as_bytes(&self) -> &[u8] {
        let len = self
            .d_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.d_name.len());
        &self.d_name[..len]
    }
}

#[repr(C, packed)]
pub struct LinuxDirent64 {
    pub d_ino:      u64,    // 64-bit inode number
    pub d_off:      i64,    // 64-bit offset to next structure
    pub d_reclen:   u16,    // Size of this dirent
    pub d_type:     u8,     // File type
    pub d_name:     [u8; 0],// Filename (null-terminated)
}
