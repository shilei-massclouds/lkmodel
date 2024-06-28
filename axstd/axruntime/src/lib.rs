#![cfg_attr(not(test), no_std)]

use axlog::ax_println;
use axlog::info;
use axlog::warn;
use fork::{user_mode_thread, CloneFlags};

#[cfg(all(target_os = "none", not(test)))]
mod lang_items;

extern "Rust" {
    fn main();
}

use core::sync::atomic::{AtomicUsize, Ordering};

static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn runtime_main(cpu_id: usize, dtb: usize) -> () {
    ax_println!(
        "\
        arch = {}\n\
        platform = {}\n\
        target = {}\n\
        smp = {}\n\
        build_mode = {}\n\
        log_level = {}\n\
        ",
        option_env!("AX_ARCH").unwrap_or(""),
        option_env!("AX_PLATFORM").unwrap_or(""),
        option_env!("AX_TARGET").unwrap_or(""),
        option_env!("AX_SMP").unwrap_or(""),
        option_env!("AX_MODE").unwrap_or(""),
        option_env!("AX_LOG").unwrap_or(""),
    );
    axlog::init("debug");
    axlog::set_max_level(option_env!("AX_LOG").unwrap_or("")); // no effect if set `log-level-*` features
    info!("Logging is enabled.");
    info!("Primary CPU {} started, dtb = {:#x}.", cpu_id, dtb);

    axhal::arch_init_early(cpu_id); // 如果不在页表初始化之前加入这行代码会触发unsafe

    axtrap::early_init();

    info!("Found physcial memory regions:");
    for r in axhal::mem::memory_regions() {
        info!(
            "  [{:x?}, {:x?}) {} ({:?})",
            r.paddr,
            r.paddr + r.size,
            r.name,
            r.flags
        );
    }

    // #[cfg(feature = "alloc")]
    axalloc::init();

    // #[cfg(feature = "paging")]
    {
        page_table::init();
        // use axhal::mem::phys_to_virt;
        // // Try to access virtio_mmio space.
        // let va = phys_to_virt(0x1000_1000.into()).as_usize();
        // let ptr = va as *const u32;
        // unsafe {
        //     info!("Try to access virtio_mmio [{:#X}]", *ptr);
        // }
        // info!("[rt_page_table]: ok!");
    }

    info!("Initialize platform devices...");
    axhal::platform_init();

    // 必须要有分页机制才能开启task
    // #[cfg(feature = "paging")]
    {
        info!("Initialize schedule system ..."); 
        task::init();
    }

    // #[cfg(feature = "paging")]
    axtrap::final_init();
    info!("Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Relaxed);

    while !is_init_ok() {
        core::hint::spin_loop();
    }

    let tid = user_mode_thread(
        move || {    
            unsafe { main() };

        },
        CloneFlags::CLONE_FS,
    );
    assert_eq!(tid, 1);

    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();
    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(/* CPUHP_ONLINE */);
}

fn schedule_preempt_disabled() {
    let task = task::current();
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().resched(false);
    unimplemented!("schedule_preempt_disabled()");
}

fn cpu_startup_entry() {
    unimplemented!("do idle()");
}

fn is_init_ok() -> bool {
    INITED_CPUS.load(Ordering::Acquire) == axconfig::SMP
}