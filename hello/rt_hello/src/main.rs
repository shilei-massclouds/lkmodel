#![no_std]
#![no_main]


use hello;
#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    hello::say_hello();
    panic!("Reach here!");
}




// use core::panic::PanicInfo;
// #[panic_handler]
// pub fn panic(info: &PanicInfo) -> ! {
//     arch_boot::panic(info)
// }



