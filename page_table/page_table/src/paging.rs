//! Page table manipulation.

use axalloc::global_allocator;
use core::cell::OnceCell;
use crate::PagingIf;

use axhal::arch::write_page_table_root;
use axhal::mem::{phys_to_virt, virt_to_phys, PhysAddr, VirtAddr, PAGE_SIZE_4K};

#[doc(no_inline)]
pub use crate::{MappingFlags, PageSize, PagingError, PagingResult};

/// Implementation of [`PagingIf`], to provide physical memory manipulation to
/// the [page_table] crate.
pub struct PagingIfImpl;

impl PagingIf for PagingIfImpl {
    fn alloc_frame() -> Option<PhysAddr> {
        global_allocator()
            .alloc_pages(1, PAGE_SIZE_4K)
            .map(|vaddr| virt_to_phys(vaddr.into()))
            .ok()
    }

    fn dealloc_frame(paddr: PhysAddr) {
        global_allocator().dealloc_pages(phys_to_virt(paddr).as_usize(), 1)
    }

    #[inline]
    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        /// The architecture-specific page table.
        pub type PageTable = crate::x86_64::X64PageTable<PagingIfImpl>;
    } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
        /// The architecture-specific page table.
        pub type PageTable = crate::riscv::Sv39PageTable<PagingIfImpl>;
    } else if #[cfg(target_arch = "aarch64")]{
        /// The architecture-specific page table.
        pub type PageTable = crate::aarch64::A64PageTable<PagingIfImpl>;
    }
}

static mut KERNEL_PAGE_TABLE: OnceCell<PageTable> = OnceCell::new();

fn kernel_pg_root_paddr() -> PhysAddr {
    unsafe { KERNEL_PAGE_TABLE.get().unwrap().root_paddr() }
}

pub fn setup_page_table_root(pt: PageTable) {
    unsafe {
        let _ = KERNEL_PAGE_TABLE.set(pt);
        write_page_table_root(kernel_pg_root_paddr());
    }
}

pub fn reuse_page_table_root() {
    unsafe {
        assert!(KERNEL_PAGE_TABLE.get().is_some());
        write_page_table_root(kernel_pg_root_paddr());
    }
}

fn sync_kernel_mappings(src_paddr: PhysAddr, dst_paddr: PhysAddr) {
    let dst_ptr = phys_to_virt(dst_paddr).as_mut_ptr();
    let src_ptr = phys_to_virt(src_paddr).as_ptr();
    unsafe {
        core::ptr::copy_nonoverlapping(
            src_ptr.wrapping_add(PAGE_SIZE_4K / 2),
            dst_ptr.wrapping_add(PAGE_SIZE_4K / 2),
            PAGE_SIZE_4K / 2,
        );
        info!(
            "CLONE: from {:#X} => {:#X}",
            src_ptr as usize, dst_ptr as usize
        );
    }
}

pub fn pgd_alloc() -> PageTable {
    let pgtable = unsafe { KERNEL_PAGE_TABLE.get().unwrap().clone() };
    /* Copy kernel mappings */
    sync_kernel_mappings(kernel_pg_root_paddr(), pgtable.root_paddr());
    pgtable
}

// 直接使用内核页表进行map_region
pub fn map_region(va:usize,pa:usize,len:usize,flags:usize) -> PagingResult {
    let flags = MappingFlags::from_bits(flags).ok_or(PagingError::NoMemory)?;
    unsafe { KERNEL_PAGE_TABLE.get_mut().unwrap().map_region(
                va.into(),
                pa.into(),
                len,
                flags.into(),
                true,)
    }
}

// static mut APP_PG_DIR: OnceCell<PageTable> = OnceCell::new();

// pub fn init_tls_pg_dir() {
//     unsafe {
//         if APP_PG_DIR.get().is_none() {
//             APP_PG_DIR = KERNEL_PAGE_TABLE.clone();
//             debug!("############ APP_PG_DIR clone {:?}",
//                    APP_PG_DIR.get().unwrap().root_paddr());
//         }
//         write_page_table_root(APP_PG_DIR.get().unwrap().root_paddr());
//     }
// }

// pub fn map_region(va: usize, pa: usize, len: usize, flags: usize) -> PagingResult {
//     let flags = MappingFlags::from_bits(flags).ok_or(PagingError::NoMemory)?;
//     unsafe { APP_PG_DIR.get_mut().unwrap().map_region(
//         va.into(),
//         pa.into(),
//         len,
//         flags.into(),
//         true,
//     )}
// }