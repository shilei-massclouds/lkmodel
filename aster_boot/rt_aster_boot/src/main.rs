#![no_std]
#![no_main]

use fdt::Fdt;
use spin::Once;

use aster_boot::{early_println, kspace::paddr_to_vaddr};

/// The entry point of the Rust code portion of Asterinas.
#[no_mangle]
pub extern "C" fn main(_hart_id: usize, device_tree_paddr: usize) -> ! {
    let package = option_env!("CARGO_PKG_NAME").unwrap_or("Unknown");
    early_println!("[{}]: ok!", package);
    aster_boot::terminate()
}

use core::panic::PanicInfo;

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    aster_boot::panic_handler(info)
}
