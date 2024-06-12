#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use core::panic::PanicInfo;
use fork::user_mode_thread;
use fork::CloneFlags;

/// Entry
#[no_mangle]
pub extern "Rust" fn runtime_main(cpu_id: usize, dtb: usize) {
    init(cpu_id, dtb);
    run(cpu_id, dtb);
    panic!("Never reach here!");
}

pub fn init(cpu_id: usize, _dtb: usize) {
    assert_eq!(cpu_id, 0);

    axlog2::init("debug");
    info!("[rt_fork]: ... cpuid {}", cpu_id);

    axhal::arch_init_early(cpu_id);

    info!("Initialize global memory allocator...");
    axalloc::init();

    info!("Initialize kernel page table...");
    page_table::init();

    info!("Initialize schedule system ...");
    task::init();
}

pub fn run(_cpu_id: usize, _dtb: usize) {
    info!("start thread ...");
    let tid = user_mode_thread(
        move || {
            kernel_init();
        },
        CloneFlags::CLONE_FS,
    );
    assert_eq!(tid, 1);

    schedule_preempt_disabled();

    info!("[rt_fork]: ok!");
    axhal::misc::terminate();
}

fn schedule_preempt_disabled() {
    let task = task::current();
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().resched(false);
}

/// Prepare for entering first user app.
fn kernel_init() {
    info!("enter kernel_init ...");
    let task = task::current();
    task.set_state(taskctx::TaskState::Blocked);
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().resched(false);
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}