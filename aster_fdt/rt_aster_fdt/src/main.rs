#![no_std]
#![no_main]

use spin::Once;

use aster_boot::{
    /*
    boot::{
        kcmdline::KCmdlineArg,
        memory_region::{non_overlapping_regions_from, MemoryRegion, MemoryRegionType},
        BootloaderAcpiArg, BootloaderFramebufferArg,
    },
    */
    early_println,
    kspace::paddr_to_vaddr,
};

/// The Flattened Device Tree of the platform.
pub static DEVICE_TREE: Once<fdt::Fdt> = Once::new();

/// The entry point of the Rust code portion of Asterinas.
#[no_mangle]
pub extern "C" fn main(_hart_id: usize, device_tree_paddr: usize) -> ! {
    let package = option_env!("CARGO_PKG_NAME").unwrap_or("Unknown");
    early_println!("[{}]: ok!", package);

    let device_tree_ptr = paddr_to_vaddr(device_tree_paddr) as *const u8;
    let fdt = unsafe { fdt::Fdt::from_ptr(device_tree_ptr).unwrap() };
    DEVICE_TREE.call_once(|| fdt);

    /*
    crate::boot::register_boot_init_callbacks(
        init_bootloader_name,
        init_kernel_commandline,
        init_initramfs,
        init_acpi_arg,
        init_framebuffer_info,
        init_memory_regions,
    );
    */

    //crate::boot::call_ostd_main();
    panic!();
}

use core::panic::PanicInfo;

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    aster_boot::panic_handler(info)
}
