#![no_std]
#![no_main]

extern crate alloc;

mod lang_item;

use alloc::string::String;
use spin::Once;

use aster_boot::{
    early_println,
    kspace::paddr_to_vaddr,
};

/// The entry point of the Rust code portion of Asterinas.
#[no_mangle]
pub extern "C" fn main(hart_id: usize, device_tree_paddr: usize) -> ! {
    let package = option_env!("CARGO_PKG_NAME").unwrap_or("Unknown");
    early_println!("[{}]: ...", package);

    aster_early_init::init(hart_id, device_tree_paddr);

    let s = String::from("Hello, String!");
    early_println!("String: {}", s);

    //crate::boot::call_ostd_main();
    early_println!("[{}]: ok!", package);
    aster_boot::terminate()
}
