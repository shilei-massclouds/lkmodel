//! Startup process for monolithic kernel.

#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use core::panic::PanicInfo;
use alloc::vec;
use alloc::borrow::ToOwned;

/// The main entry point for monolithic kernel startup.
#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(cpu_id: usize, dtb: usize) {
    init(cpu_id, dtb);
    start(cpu_id, dtb);
    panic!("Never reach here!");
}

pub fn init(cpu_id: usize, dtb: usize) {
    axlog2::init("error");
    exec::init(cpu_id, dtb);
    axtrap::init(cpu_id, dtb);
}

pub fn start(_cpu_id: usize, _dtb: usize) {
    let mut init_cmd = env!("AX_INIT");
    if init_cmd.len() == 0 {
        init_cmd = "/btp/sbin/hello";
    }

    let _ = fileops::console_on_rootfs();

    let _ = exec::kernel_execve(init_cmd, vec![init_cmd.to_owned()], vec![]);

    let sp = task::current().pt_regs_addr();
    axhal::arch::ret_from_fork(sp);
    unreachable!();
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    axhal::misc::terminate();
    #[allow(unreachable_code)]
    arch_boot::panic(info)
}
