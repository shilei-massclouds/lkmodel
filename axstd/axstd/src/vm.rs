//
// Flags for map region
//

// use core::alloc::Layout;
// use core::ptr::NonNull;
use axhal::mem::virt_to_phys;

/// Readable.
pub const READ: usize       = 1 << 0;
/// Writable.
pub const WRITE: usize      = 1 << 1;
/// Executable.
pub const EXECUTE: usize    = 1 << 2;

// pub fn ax_alloc(layout: Layout) -> Option<NonNull<u8>> {
//     axalloc::global_allocator().alloc(layout).ok()
// }

// pub fn ax_dealloc(ptr: NonNull<u8>, layout: Layout) {
//     axalloc::global_allocator().dealloc(ptr, layout)
// }

pub fn get_brk() -> usize {
    let mut task = task::current();
    task.as_task_mut().brk()
}

pub fn set_brk(brk: usize) {
    let mut task = task::current();
    task.as_task_mut().set_brk(brk);
}

pub fn alloc_pages(
    num_pages: usize, align_pow2: usize
) -> usize {
    axalloc::global_allocator().alloc_pages(num_pages, align_pow2)
        .map(|va| virt_to_phys(va.into())).ok().unwrap().into()
}

pub fn map_region(va: usize, pa: usize, len: usize, flags: usize) {
    let mut task = task::current();
    // 向当前任务的mm中进行map_region
    task.as_task_mut().map_region(va, pa, len, flags)
}

