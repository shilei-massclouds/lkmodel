use core::mem;
use alloc::sync::Arc;

use axhal::arch::gp_in_global;
use axhal::arch::{SR_SPP, SR_SPIE};
use task::{Tid, TaskStruct};
use axtype::align_up_4k;
use axerrno::LinuxResult;
use taskctx::SchedInfo;
use taskctx::THREAD_SIZE;
use taskctx::TaskStack;
use crate::CloneFlags;
use crate::KernelCloneArgs;

use axlog2;
pub fn copy_thread(
    task: &mut TaskStruct,
    args: &KernelCloneArgs,
    tid: Tid,
    tgid: Tid,
    set_child_tid: usize,
    clear_child_tid: usize,
    real_parent: Option<Arc<SchedInfo>>,
    group_leader: Option<Arc<SchedInfo>>,
) -> LinuxResult {
    info!("copy_thread ...222");
    let mut sched_info = SchedInfo::new();
    //sched_info.init(self.entry, task_entry as usize, 0.into());
    /////////////////////
    sched_info.entry = args.entry;
    sched_info.kstack = Some(TaskStack::alloc(align_up_4k(THREAD_SIZE)));
    /////////////////////
    sched_info.init_tid(tid);
    sched_info.init_tgid(tgid);
    sched_info.real_parent = real_parent;
    sched_info.group_leader = group_leader;
    sched_info.set_child_tid = set_child_tid;
    sched_info.clear_child_tid = clear_child_tid;
    if let Some(mm) = task.try_mm() {
        let locked_mm = mm.lock();
        sched_info.set_mm(locked_mm.id(), locked_mm.pgd());
    }

    let pt_regs = sched_info.pt_regs();
    if args.entry.is_some() {
        *pt_regs = unsafe { mem::zeroed() };
        pt_regs.regs.gp = gp_in_global();
        // Supervisor/Machine, irqs on:
        pt_regs.sstatus = SR_SPP | SR_SPIE;
    } else {
        let ctx = taskctx::current_ctx();
        *pt_regs = ctx.pt_regs().clone();
        info!(" ctx.pt_regs:0x{:0x}" , ctx.pt_regs() as *const _ as *const usize  as usize );
        info!(" pt_regs.regs.ra:0x{:0x}" , pt_regs.regs.ra );
        if let Some(sp) = args.stack {
            pt_regs.regs.sp = sp; // User fork
        }
        if args.flags.contains(CloneFlags::CLONE_SETTLS) {
            pt_regs.regs.tp = args.tls;
        }
        pt_regs.regs.a0 = 0; // Return value of fork()
    }

    let sp = sched_info.pt_regs_addr();
    sched_info.thread.get_mut().init(crate::task_entry as usize, sp.into(), 0.into());
    task.sched_info = Arc::new(sched_info);
    match task.sched_info.pgd {
        None => {
            info!("PAGE TABLE IS NONE");
        }
        _ => {
            info!("HAVE PAGE TABLE");
        }
    }
    info!("copy_thread!");
    Ok(())
}
