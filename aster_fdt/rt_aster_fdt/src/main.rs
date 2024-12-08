#![no_std]
#![no_main]

extern crate alloc;

mod lang_item;

use spin::Once;
use alloc::string::String;

use aster_boot::{
    early_println,
    kspace::paddr_to_vaddr,
};

use aster_fdt::{
    kcmdline::KCmdlineArg,
    memory_region::{non_overlapping_regions_from, MemoryRegion, MemoryRegionType},
    BootloaderAcpiArg, BootloaderFramebufferArg,
};

/// The entry point of the Rust code portion of Asterinas.
#[no_mangle]
pub extern "C" fn main(hart_id: usize, device_tree_paddr: usize) -> ! {
    let package = option_env!("CARGO_PKG_NAME").unwrap_or("Unknown");
    early_println!("[{}]: ...", package);

    aster_fdt::init(hart_id, device_tree_paddr);

    //crate::boot::call_ostd_main();
    early_println!("[{}]: ok!", package);
    aster_boot::terminate()
}
