#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;
use core::panic::PanicInfo;

mod basic;
mod bench;
mod boundary;

/// Entry
#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    axlog2::init("info");
    info!("[rt_ramfs]: ...");

    axalloc::init();

    basic::test_basic();
    bench::test_write();
    boundary::test_boundary().unwrap();

    info!("[rt_ramfs]: ok!");
    axhal::misc::terminate();
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}
