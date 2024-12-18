#![no_std]
#![no_main]
#![feature(register_tool)]
#![register_tool(component_access_control)]
#![feature(specialization)]
#![feature(btree_cursors)]
#![feature(let_chains)]
#![feature(format_args_nl)]
#![feature(panic_can_unwind)]
#![feature(debug_closure_helpers)]
#![feature(fn_traits)]
#![feature(btree_extract_if)]
#![feature(trait_upcasting)]
#![feature(linked_list_cursors)]
#![feature(linked_list_retain)]

extern crate lru;

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate controlled;
#[macro_use]
extern crate getset;

mod arch;
mod context;
mod cpu;
mod device;
mod driver;
mod error;
mod events;
mod fs;
mod ipc;
mod net;
mod prelude;
mod process;
mod sched;
mod syscall;
mod time;
mod thread;
mod util;
mod vdso;
mod vm;

use ostd::{
    arch::qemu::{exit_qemu, QemuExitCode},
    boot,
    cpu::PinCurrentCpu,
};
use process::Process;

use crate::{
    prelude::*,
    sched::priority::Priority,
    thread::{kernel_thread::ThreadOptions, Thread},
};

use ostd::early_println as println;

#[ostd::main]
#[controlled]
pub fn main() {
    ostd::early_println!("[kernel] OSTD initialized. Preparing components.");
    component::init_all(component::parse_metadata!()).unwrap();
    init();

    // Spawn all AP idle threads.
    ostd::boot::smp::register_ap_entry(ap_init);

    // Spawn the first kernel thread on BSP.
    ThreadOptions::new(init_thread)
        .priority(Priority::idle())
        .spawn();
    todo!("Normally exit!");
}

fn init() {
    util::random::init();
    driver::init();
    time::init();
    #[cfg(target_arch = "x86_64")]
    net::init();
    sched::init();
    //fs::rootfs::init(boot::initramfs()).unwrap();
    fs::rootfs::init().unwrap();
    device::init().unwrap();
    syscall::init();
    //vdso::init();
    process::init();
}

fn ap_init() {
    fn ap_idle_thread() {
        let preempt_guard = ostd::task::disable_preempt();
        let cpu_id = preempt_guard.current_cpu();
        drop(preempt_guard);
        log::info!("Kernel idle thread for CPU #{} started.", cpu_id.as_usize());
        loop {
            Thread::yield_now();
        }
    }
    let preempt_guard = ostd::task::disable_preempt();
    let cpu_id = preempt_guard.current_cpu();
    drop(preempt_guard);

    ThreadOptions::new(ap_idle_thread)
        .cpu_affinity(cpu_id.into())
        .priority(Priority::idle())
        .spawn();
}

fn init_thread() {
    println!("[kernel] Spawn init thread");
    // Work queue should be initialized before interrupt is enabled,
    // in case any irq handler uses work queue as bottom half
    thread::work_queue::init();
    #[cfg(target_arch = "x86_64")]
    net::lazy_init();
    fs::lazy_init();
    ipc::init();
    // driver::pci::virtio::block::block_device_test();
    let thread = ThreadOptions::new(|| {
        println!("[kernel] Hello world from kernel!");
    })
    .spawn();
    thread.join();

    print_banner();

    let karg = boot::kernel_cmdline();

    /*
    let initproc = Process::spawn_user_process(
        karg.get_initproc_path().unwrap(),
        karg.get_initproc_argv().to_vec(),
        karg.get_initproc_envp().to_vec(),
    )
    .expect("Run init process failed.");
    */
    let initproc = Process::spawn_user_process(
        "/ext2/sbin/hello",
        vec![CString::new("").unwrap()],
        vec![],
    )
    .expect("Run init process failed.");

    /*
    // Wait till initproc become zombie.
    while !initproc.is_zombie() {
        // We don't have preemptive scheduler now.
        // The long running init thread should yield its own execution to allow other tasks to go on.
        Thread::yield_now();
    }

    // TODO: exit via qemu isa debug device should not be the only way.
    let exit_code = if initproc.exit_code() == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    };
    exit_qemu(exit_code);
    */
    info!("init ok!");
    Thread::yield_now();
}

fn print_banner() {
    println!("\x1B[36m");
    println!(
        r"
   _   ___ _____ ___ ___ ___ _  _   _   ___
  /_\ / __|_   _| __| _ \_ _| \| | /_\ / __|
 / _ \\__ \ | | | _||   /| || .` |/ _ \\__ \
/_/ \_\___/ |_| |___|_|_\___|_|\_/_/ \_\___/
"
    );
    println!("\x1B[0m");
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    extern "Rust" {
        pub fn __ostd_panic_handler(info: &core::panic::PanicInfo) -> !;
    }
    unsafe { __ostd_panic_handler(info); }
}
