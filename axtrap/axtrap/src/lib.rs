#![cfg_attr(not(test), no_std)]
#![feature(asm_const)]

#[macro_use]
extern crate log;

mod arch;
pub mod irq;
mod platform;
use crate::irq::IrqHandler;
use axhal::time::TIMER_IRQ_NUM;
use preempt_guard::NoPreempt;

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();

    //axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axlog2::init("debug");
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);

    arch::init_trap();
    // Todo: extract irq as standalone modular axirq.
    axsyscall::init();

    register_irq_handler(TIMER_IRQ_NUM, || {
        update_timer();
        let _ = NoPreempt::new();
        wait_queue::on_timer_tick();
        run_queue::on_timer_tick();
    });
}

pub fn update_timer() {
    // Setup timer interrupt handler
    const PERIODIC_INTERVAL_NANOS: u64 =
        axhal::time::NANOS_PER_SEC / axconfig::TICKS_PER_SEC as u64;

    #[percpu2::def_percpu]
    static NEXT_DEADLINE: u64 = 0;

    let now_ns = axhal::time::current_time_nanos();
    // Safety: we have disabled preemption in IRQ handler.
    let mut deadline = unsafe { NEXT_DEADLINE.read_current_raw() };
    if now_ns >= deadline {
        deadline = now_ns + PERIODIC_INTERVAL_NANOS;
    }
    unsafe { NEXT_DEADLINE.write_current_raw(deadline + PERIODIC_INTERVAL_NANOS) };
    axhal::time::set_oneshot_timer(deadline);
}

pub fn register_irq_handler(irq: usize, handler: IrqHandler) {
    irq::register_handler(irq, handler);
}

pub fn start(_cpu_id: usize, _dtb: usize) {
    // Enable IRQs before starting app
    axhal::arch::enable_irqs();
    error!("irqs enabled! irqs {}", axhal::arch::irqs_enabled());
}
