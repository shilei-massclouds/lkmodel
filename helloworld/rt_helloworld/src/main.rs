#![no_std]
#![no_main]

use core::panic::PanicInfo;

use axstd::println;
#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    println!("hello_world");
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}
