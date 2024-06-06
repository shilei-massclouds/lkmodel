#![no_std]
#![no_main]

// use core::panic::PanicInfo;


use hello;

// Since Rust 2018 edition, the extern crate syntax is no longer necessary. Instead, you just need to add the library crate hello to the dependencies in the Cargo.toml file of the rt_hello project.
// extern crate hello;
// use hello::say_hello;


#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    hello::say_hello();
    panic!("Reach here!");
}

// #[panic_handler]
// pub fn panic(info: &PanicInfo) -> ! {
//     arch_boot::panic(info)
// }



