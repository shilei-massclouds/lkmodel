use axhal::arch::TrapFrame;
use axhal::trap::TRAPFRAME_SIZE;
use axsyscall::SyscallArgs;
use riscv::register::scause::{self, Exception as E, Trap};
use riscv::register::stval;
use riscv::register::stvec;
use riscv::register::sstatus;
use preempt_guard::NoPreempt;
use axstd::println;
use core::arch::asm;
axhal::include_asm_marcos!();

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const TRAPFRAME_SIZE,
);
extern "C" {
    fn trap_vector_base();
}

/// Writes Supervisor Trap Vector Base Address Register (`stvec`).
#[inline]
pub fn init_trap() {
    unsafe { stvec::write(trap_vector_base as usize, stvec::TrapMode::Direct) }
}

#[no_mangle]
pub fn riscv_trap_handler(tf: &mut TrapFrame, _from_user: u64) {
    let scause = scause::read();
    println!( "sepc:0x{:0x}  ,  a7:{}  , scause:{}" , tf.sepc , tf.regs.a7 , scause.code());
    let sstatus_value = sstatus::read();

    // 打印sstatus的原始值
    //println!("sstatus: 0x{:x}", sstatus_value.bits());

    // 提取并打印SPP位
    // let spp_bit = sstatus_value.spp();
    // println!("SPP bit: {:?}", spp_bit);

    if scause.code() == 0x9 {
        if tf.regs.a7 == 96 {
            tf.sepc += 4;
            let satp_value: usize;
            unsafe {
                asm!("csrr {0}, satp", out(reg) satp_value);
            }
            //info!("fake done and stval:0x{:0x} , sapt:0x{:0x}" , stval::read() , satp_value );
            return ();
        }
        handle_linux_syscall(tf);
        return;
    }

    match scause.cause() {
        
        Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
        Trap::Exception(E::UserEnvCall) => handle_linux_syscall(tf),
        Trap::Exception(E::InstructionPageFault) => {
            let satp_value: usize;
            unsafe {
                asm!("csrr {0}, satp", out(reg) satp_value);
            }
            handle_page_fault(stval::read(), scause.code(), tf);
        }
        Trap::Exception(E::LoadPageFault) => {
            handle_page_fault(stval::read(), scause.code(), tf);
        }
        Trap::Exception(E::StorePageFault) => {
            handle_page_fault(stval::read(), scause.code(), tf);
        }
        Trap::Interrupt(_) => handle_irq_extern(scause.bits(), tf),
        _ => {
            panic!(
                "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                scause.cause(),
                tf.sepc,
                tf
            );
        }
    }
}

/// Call page fault handler.
fn handle_page_fault(badaddr: usize, cause: usize, tf: &mut TrapFrame) {
    debug!("handle_page_fault... cause {}", cause);
    mmap::faultin_page(badaddr, cause);
    signal::do_signal(tf);
}

/// Call the external IRQ handler.
fn handle_irq_extern(irq_num: usize, _tf: &mut TrapFrame) {
    let _ = NoPreempt::new();
    crate::platform::irq::dispatch_irq(irq_num);
    // Todo: why we cannot do_signal here (irq context -> userland).
    //drop(guard); // rescheduling may occur when preemption is re-enabled.
}

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

fn handle_linux_syscall(tf: &mut TrapFrame) {
    debug!("handle_linux_syscall");
    syscall(tf, axsyscall::do_syscall);
    signal::do_signal(tf);
    return;
}

fn syscall_args(tf: &TrapFrame) -> SyscallArgs {
    [
        tf.regs.a0, tf.regs.a1, tf.regs.a2, tf.regs.a3, tf.regs.a4, tf.regs.a5,
    ]
}

fn syscall<F>(tf: &mut TrapFrame, do_syscall: F)
where
    F: FnOnce(SyscallArgs, usize) -> usize,
{
    warn!("Syscall: {:#x} , Sepc:{:#x}", tf.regs.a7, tf.sepc);
    let args = syscall_args(tf);
    // Note: "tf.sepc += 4;" must be put before do_syscall. Or:
    // E.g., when we do clone, child task will call clone again
    // and cause strange behavior.
    tf.sepc += 4;
    tf.regs.a0 = do_syscall(args, tf.regs.a7);
    info!("0x{:0x}" , tf.regs.a0 );
}
