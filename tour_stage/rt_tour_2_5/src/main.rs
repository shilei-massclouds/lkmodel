#![no_std]
#![no_main]
#![feature(asm_const)]

#[macro_use]
extern crate axlog2;
extern crate alloc;

mod userboot;
mod trap;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use wait_queue::WaitQueue;
use taskctx::PF_KTHREAD;

static WQ: WaitQueue = WaitQueue::new();
static APP_READY: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub extern "Rust" fn runtime_main(cpu_id: usize, dtb_pa: usize) {
    axlog2::init("info");
    info!("[rt_tour_2_5]: ...");

    // Setup simplest trap framework.
    trap::init();

    // Startup a kernel thread.
    run_queue::init(cpu_id, dtb_pa);
    trap::start();

    let ctx = run_queue::spawn_task_raw(1, 0, move || {
        // Prepare for user app to startup.
        userboot::init(cpu_id, dtb_pa);

        info!("App kernel-thread load ..");
        // Load userland app into pgd.
        userboot::load();

        // Note: wait wander-thread to notify.
        info!("App kernel-thread waits for wanderer to notify ..");
        APP_READY.store(true, Ordering::Relaxed);
        WQ.wait();

        // Start userland app.
        info!("App kernel-thread is starting ..");
        userboot::start();
        userboot::cleanup();
    });
    run_queue::activate_task(ctx.clone());

    let ctx = run_queue::spawn_task_raw(2, PF_KTHREAD, || {
        info!("Wander kernel-thread is running ..");
        info!("Wander kernel-thread waits for app to be ready ..");
        while !APP_READY.load(Ordering::Relaxed) {
            run_queue::yield_now();
        }
        info!("Wander notifies app ..");
        WQ.notify_one(true);
        loop {}
    });
    run_queue::activate_task(ctx.clone());

    run_queue::yield_now();

    unreachable!();
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{:?}", info);
    arch_boot::panic(info)
}
