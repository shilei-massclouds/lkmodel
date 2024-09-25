use core::mem;

use axhal::arch::gp_in_global;
use axhal::arch::{SR_SPP, SR_SPIE};
use axerrno::LinuxResult;
use crate::CloneFlags;
use crate::KernelCloneArgs;
use axhal::arch::TrapFrame;

pub fn copy_thread(
    pt_regs: &mut TrapFrame,
    args: &KernelCloneArgs,
) -> LinuxResult {
    info!("copy_thread ... irqs {}", axhal::arch::irqs_enabled());

    if args.entry.is_some() {
        *pt_regs = unsafe { mem::zeroed() };
        pt_regs.regs.gp = gp_in_global();
        // Supervisor/Machine, irqs on:
        pt_regs.sstatus = SR_SPP | SR_SPIE;
    } else {
        let ctx = taskctx::current_ctx();
        *pt_regs = ctx.pt_regs().clone();
        if let Some(sp) = args.stack {
            pt_regs.regs.sp = sp; // User fork
        }
        if args.flags.contains(CloneFlags::CLONE_SETTLS) {
            pt_regs.regs.tp = args.tls;
        }
        pt_regs.regs.a0 = 0; // Return value of fork()
    }

    info!("copy_thread!");
    Ok(())
}
