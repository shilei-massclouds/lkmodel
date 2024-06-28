mod idt;
pub use self::idt::IdtStruct;
mod syscall;
use x86::{controlregs::cr2, irq::*};
use preempt_guard::NoPreempt;

use axhal::arch::TrapFrame;

core::arch::global_asm!(include_str!("trap.S"));

const IRQ_VECTOR_START: u8 = 0x20;
const IRQ_VECTOR_END: u8 = 0xff;

pub fn init_trap() {
    // To init the IDT
    crate::platform::init_percpu_interrupt();
    syscall::init_syscall();
}

#[no_mangle]
fn x86_trap_handler(tf: &mut TrapFrame) {
    match tf.vector as u8 {
        PAGE_FAULT_VECTOR => {
            // if tf.is_user() {
            debug!(
                "User #PF @ {:#x}, fault_vaddr={:#x}, error_code={:#x}",
                tf.rip,
                unsafe { cr2() },
                tf.error_code,
            );
            let badaddr = unsafe { cr2() };
            //  31              15                             4               0
            // +---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+
            // |   Reserved   | SGX |   Reserved   | SS | PK | I | R | U | W | P |
            // +---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+
            /*
            axlog2::debug!("error_code: {:?}", tf.error_code);
            if tf.error_code & (1 << 1) != 0 {
                handle_page_fault(badaddr, 2);
            }
            if tf.error_code & (1 << 2) != 0 {
                handle_page_fault(badaddr, 3);
            }
            if tf.error_code & (1 << 3) != 0 {
                handle_page_fault(badaddr, 1);
            }
            if tf.error_code & (1 << 4) != 0 {
                handle_page_fault(badaddr, 0);
            }
            */
            // Todo: set proper cause for handle_page_fault.
            handle_page_fault(badaddr, 0 /* cause */);
            // } else {
            //     panic!(
            //         "Kernel #PF @ {:#x}, fault_vaddr={:#x}, error_code={:#x}:\n{:#x?}",
            //         tf.rip,
            //         unsafe { cr2() },
            //         tf.error_code,
            //         tf,
            //     );
            // }
        }
        BREAKPOINT_VECTOR => debug!("#BP @ {:#x} ", tf.rip),
        GENERAL_PROTECTION_FAULT_VECTOR => {
            panic!(
                "#GP @ {:#x}, error_code={:#x}:\n{:#x?}",
                tf.rip, tf.error_code, tf
            );
        }
        IRQ_VECTOR_START..=IRQ_VECTOR_END => handle_irq_extern(tf.vector as _),
        _ => {
            panic!(
                "Unhandled exception {} (error_code = {:#x}) @ {:#x}:\n{:#x?}",
                tf.vector, tf.error_code, tf.rip, tf
            );
        }
    }
    #[cfg(feature = "signal")]
    if tf.is_user() {
        crate::trap::handle_signal();
    }
}
/// Call page fault handler.
fn handle_page_fault(badaddr: usize, cause: usize) {
    debug!("handle_page_fault...");
    mmap::faultin_page(badaddr, cause);
}

/// Call the external IRQ handler.
fn handle_irq_extern(irq_num: usize) {
    debug!("handle_irq_extern irq: {:#X} ...", irq_num);
    let _ = NoPreempt::new();
    crate::platform::irq::dispatch_irq(irq_num);
    //drop(guard); // rescheduling may occur when preemption is re-enabled.
}
