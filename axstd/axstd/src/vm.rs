//
// Flags for map region
//

/// Readable.
pub const READ: usize       = 1 << 0;
/// Writable.
pub const WRITE: usize      = 1 << 1;
/// Executable.
pub const EXECUTE: usize    = 1 << 2;

#[cfg(feature = "alloc")]
pub fn alloc_pages(num_pages: usize, align_pow2: usize) -> usize {
    arceos_api::mem::alloc_pages(num_pages, align_pow2)
}

#[cfg(feature = "paging")]
pub fn map_region(va: usize, pa: usize, len: usize, flags: usize) {
    arceos_api::mem::map_region(va, pa, len, flags)
}

pub fn get_brk() -> usize {
    arceos_api::mem::get_brk()
}

pub fn set_brk(brk: usize) {
    arceos_api::mem::set_brk(brk)
}
