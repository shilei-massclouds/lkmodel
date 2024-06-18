cfg_alloc! {
    use core::alloc::Layout;
    use core::ptr::NonNull;
    use axhal::mem::virt_to_phys;

    pub fn ax_alloc(layout: Layout) -> Option<NonNull<u8>> {
        axalloc::global_allocator().alloc(layout).ok()
    }

    pub fn ax_dealloc(ptr: NonNull<u8>, layout: Layout) {
        axalloc::global_allocator().dealloc(ptr, layout)
    }

    pub fn alloc_pages(
        num_pages: usize, align_pow2: usize
    ) -> usize {
        axalloc::global_allocator().alloc_pages(num_pages, align_pow2)
            .map(|va| virt_to_phys(va.into())).ok().unwrap().into()
    }

    // pub fn map_region(va: usize, pa: usize, len: usize, flags: usize) {
    //     axhal::arch::map_region(va, pa, len, flags).unwrap()
    // }

    // pub fn get_brk() -> usize {
    //     unsafe { axhal::arch::get_tls_brk() }
    // }

    // pub fn set_brk(brk: usize) {
    //     unsafe { axhal::arch::set_tls_brk(brk) }
    // }
}
