#![cfg_attr(not(test), no_std)]

mod path;
pub use path::Path;

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

pub const PAGE_SIZE: usize  = 0x1000;
pub const PAGE_SHIFT: usize = 12;

/// Align address downwards.
///
/// Returns the greatest `x` with alignment `align` so that `x <= addr`.
///
/// The alignment must be a power of two.
#[inline]
pub const fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

/// Align address upwards.
///
/// Returns the smallest `x` with alignment `align` so that `x >= addr`.
///
/// The alignment must be a power of two.
#[inline]
pub const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

/// Returns the offset of the address within the alignment.
///
/// Equivalent to `addr % align`, but the alignment must be a power of two.
#[inline]
pub const fn align_offset(addr: usize, align: usize) -> usize {
    addr & (align - 1)
}

/// Checks whether the address has the demanded alignment.
///
/// Equivalent to `addr % align == 0`, but the alignment must be a power of two.
#[inline]
pub const fn is_aligned(addr: usize, align: usize) -> bool {
    align_offset(addr, align) == 0
}

/// Align address downwards to 4096 (bytes).
#[inline]
pub const fn align_down_4k(addr: usize) -> usize {
    align_down(addr, PAGE_SIZE)
}

/// Align address upwards to 4096 (bytes).
#[inline]
pub const fn align_up_4k(addr: usize) -> usize {
    align_up(addr, PAGE_SIZE)
}

/// Returns the offset of the address within a 4K-sized page.
#[inline]
pub const fn align_offset_4k(addr: usize) -> usize {
    align_offset(addr, PAGE_SIZE)
}

/// Checks whether the address is 4K-aligned.
#[inline]
pub const fn is_aligned_4k(addr: usize) -> bool {
    is_aligned(addr, PAGE_SIZE)
}

#[inline]
pub const fn virt_to_phys(va: usize) -> usize {
    va - axconfig::PHYS_VIRT_OFFSET
}

#[inline]
pub const fn phys_to_virt(pa: usize) -> usize {
    pa + axconfig::PHYS_VIRT_OFFSET
}

pub struct DtbInfo {
    pub init_cmd: Option<String>,
}

impl DtbInfo {
    pub fn new() -> Self {
        Self {
            init_cmd: None,
        }
    }

    pub fn set_init_cmd(&mut self, init_cmd: &str) {
        self.init_cmd = Some(init_cmd.into());
    }

    pub fn get_init_cmd(&self) -> Option<&str> {
        self.init_cmd.as_deref()
    }
}

pub fn get_user_str(ptr: usize) -> String {
    if ptr == 0 {
        return String::new();
    }
    let ptr = ptr as *const u8;
    String::from(raw_ptr_to_ref_str(ptr))
}

/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
pub fn raw_ptr_to_ref_str(ptr: *const u8) -> &'static str {
    let len = unsafe { get_str_len(ptr) };
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    match core::str::from_utf8(slice) {
        Ok(s) => s,
        Err(e) => panic!("not utf8 slice: {:?}", e),
    }
}

/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
/// The string must be null-terminated.
pub unsafe fn get_str_len(ptr: *const u8) -> usize {
    let mut cur = ptr as usize;
    while *(cur as *const u8) != 0 {
        cur += 1;
    }
    cur - ptr as usize
}

pub fn get_user_str_vec(addr: usize) -> Vec<String> {
    let mut vec = Vec::new();
    let ptr = addr as *const usize;
    let mut index = 0;
    loop {
        let ptr_str = unsafe { ptr.add(index).read() };
        if ptr_str == 0 {
            break;
        }
        vec.push(get_user_str(ptr_str));
        index += 1;
    }
    vec
}

/// 
/// __ffs - find first bit in u64-word.
/// @word: The set to search
/// 
/// Return index when there's some bits, or None if no bit exists.
/// 
pub fn ffz(mut word: u64) -> Option<usize> {
    if word == 0 {
        return None;
    }

    let mut num = 0;

    if (word & 0xffffffff) == 0 {
        num += 32;
        word >>= 32;
    }
    if (word & 0xffff) == 0 {
        num += 16;
        word >>= 16;
    }
    if (word & 0xff) == 0 {
        num += 8;
        word >>= 8;
    }
    if (word & 0xf) == 0 {
        num += 4;
        word >>= 4;
    }
    if (word & 0x3) == 0 {
        num += 2;
        word >>= 2;
    }
    if (word & 0x1) == 0 {
        num += 1;
    }
    return Some(num);
}

pub fn set_bit(nr: usize, bitword: &mut usize) {
    *bitword |= 1 << nr;
}

pub fn clr_bit(nr: usize, bitword: &mut usize) {
    *bitword &= !(1 << nr);
}

//
// RLimit64
//

pub const RLIMIT_DATA: usize = 2;  /* max data size */
pub const RLIMIT_STACK:usize = 3;  /* max stack size */
pub const RLIMIT_CORE: usize = 4;  /* max core size */
pub const RLIMIT_NOFILE: usize = 7; /* max number of open files */
pub const RLIM_NLIMITS: usize = 16;

#[derive(Default, Copy, Clone)]
pub struct RLimit64 {
    pub rlim_cur: u64,
    #[allow(dead_code)]
    rlim_max: u64,
}

impl RLimit64 {
    pub fn new(rlim_cur: u64, rlim_max: u64) -> Self {
        Self { rlim_cur, rlim_max }
    }
}

///
/// FileMode
///
pub const O_ACCMODE:    i32 = 0o000003;
pub const O_RDONLY:     i32 = 0o000000;
pub const O_WRONLY:     i32 = 0o000001;
pub const O_RDWR:       i32 = 0o000002;
pub const O_CREAT:      i32 = 0o000100;
pub const O_EXCL:       i32 = 0o000200;
pub const O_TRUNC:      i32 = 0o001000;
pub const O_APPEND:     i32 = 0o002000;
pub const O_NONBLOCK:   i32 = 0o004000;
pub const O_DIRECTORY:  i32 = 0o200000;     /* must be a directory */
pub const O_NOFOLLOW:   i32 = 0o400000;     /* don't follow links */
pub const O_NOATIME:    i32 = 0o1000000;
pub const O_CLOEXEC:    i32 = 0o2000000;    /* set close_on_exec */
pub const O_PATH:       i32 = 0o10000000;
pub const __O_TMPFILE:  i32 = 0o20000000;

pub const FS_NAME_LEN: usize = 255;

///
/// File flags.
///
/*
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
 */
pub const S_IFMT:   i32 = 0o170000;
pub const S_IFREG:  i32 = 0o100000;
pub const S_IFIFO:  i32 = 0o10000;
pub const S_IFCHR:  i32 = 0o20000;
pub const S_ISUID:  i32 = 0o04000;
pub const S_ISGID:  i32 = 0o02000;
pub const S_ISVTX:  i32 = 0o01000;

/// Max loop dev number.
pub const MAX_LOOP_NUMBER: usize = 2;
