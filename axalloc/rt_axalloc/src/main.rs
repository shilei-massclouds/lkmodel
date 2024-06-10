#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;
use alloc::string::String;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    axlog2::init("debug");
    info!("[rt_axalloc]: ...");

    axalloc::init();

    let s = String::from("Hello, axalloc!");
    info!("Alloc string: {}", s);
    info!("[rt_axalloc]: ok!");

    const RUN_START: usize = 0x48000000 - 0x10 ;
    let address: *mut u8 = RUN_START as *const u8 as *mut u8;
    unsafe {
        *address = 0x30;
        let value = *address;
        ax_print!("The value at address 0x4010_0000 is: 0x{:02x}\n", value);
    }

    axhal::misc::terminate();
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}
