#![cfg_attr(not(test), no_std)]
#![feature(asm_const)]

#[macro_use]
extern crate axlog2;

mod arch;
pub mod irq;
mod platform;
use preempt_guard::NoPreempt;

pub fn early_init() {
    arch::init_trap();
}

pub fn final_init() {
    // Todo: extract irq as standalone modular axirq.
    info!("Initialize interrupt handlers...");
    init_irq();
    info!("Initialize systemcalls ...");
    axsyscall::init();
}

fn init_irq() {
    use axhal::time::TIMER_IRQ_NUM;

    // Setup timer interrupt handler
    const PERIODIC_INTERVAL_NANOS: u64 =
        axhal::time::NANOS_PER_SEC / axconfig::TICKS_PER_SEC as u64;

    #[percpu2::def_percpu]
    static NEXT_DEADLINE: u64 = 0;

    fn update_timer() {
        let now_ns = axhal::time::current_time_nanos();
        // Safety: we have disabled preemption in IRQ handler.
        let mut deadline = unsafe { NEXT_DEADLINE.read_current_raw() };
        if now_ns >= deadline {
            deadline = now_ns + PERIODIC_INTERVAL_NANOS;
        }
        unsafe { NEXT_DEADLINE.write_current_raw(deadline + PERIODIC_INTERVAL_NANOS) };
        axhal::time::set_oneshot_timer(deadline);
    }

    irq::register_handler(TIMER_IRQ_NUM, || {
        update_timer();
        let _ = NoPreempt::new();
        run_queue::on_timer_tick();
    });

    // Enable IRQs before starting app
    axhal::arch::enable_irqs();
}
