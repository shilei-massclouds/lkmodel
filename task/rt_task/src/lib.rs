#![no_std]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use core::panic::PanicInfo;

/// Entry
#[no_mangle]
pub extern "Rust" fn runtime_main(cpu_id: usize, _dtb_pa: usize) {
    assert_eq!(cpu_id, 0);

    axlog2::init("debug");
    axlog2::set_max_level("debug");
    info!("[rt_task]: ... cpuid {}", cpu_id);

    axhal::arch_init_early(cpu_id);

    axalloc::init();
    page_table::init();

    task::init();

    info!("[rt_task]: ok!");
    axhal::misc::terminate();
}

pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}
