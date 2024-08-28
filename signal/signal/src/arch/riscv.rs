use axhal::arch::{TrapFrame, local_flush_icache_all};
use axtype::align_down;
use crate::{RTSigFrame, KSignal, SIGFRAME_SIZE, SA_RESTART};
use crate::{setup_sigcontext, restore_sigcontext};
use task::{SIGKILL, SIGSTOP, SA_NODEFER};
use crate::{sigmask, sigorsets, sigaddset, sigdelsetmask};
use core::sync::atomic::Ordering;
use taskctx::TIF_SIGPENDING;

const ERESTARTSYS: isize = 512;

pub fn rt_sigreturn() -> usize {
    info!("sigreturn ...");

    let ctx = taskctx::current_ctx();
    let tf = ctx.pt_regs();

    let frame_addr = tf.regs.sp;
    let frame = unsafe { &mut(*(frame_addr as *mut RTSigFrame)) };

    // Validation: sigreturn_code must be 'li a7, 139; scall'.
    // For riscv64, NR_sigreturn == 139.
    assert_eq!(frame.sigreturn_code, 0x7308B00893);

    let set = frame.uc._sigmask as u64;
    debug!("sigreturn_ :  set {:#x}", set);
    set_current_blocked(set);

    restore_sigcontext(tf, frame);

    // Todo: restore_altstack
    return tf.regs.a0;
}

fn get_sigframe(tf: &TrapFrame) -> usize {
    let sp = tf.regs.sp - SIGFRAME_SIZE;
    /* Align the stack frame. */
    align_down(sp, 16)
}

pub fn handle_signal(ksig: &KSignal, tf: &mut TrapFrame, cause: usize) {
    const EXC_SYSCALL: usize = 8;
    extern "C" {
        fn __user_rt_sigreturn();
    }
    if cause == EXC_SYSCALL {
        if tf.regs.a0 == (-ERESTARTSYS) as usize {
            if (ksig.action.flags & SA_RESTART) != 0 {
                tf.sepc -= 4;
            }
        }
    }

    let frame_addr = get_sigframe(tf);
    let frame = unsafe { &mut(*(frame_addr as *mut RTSigFrame)) };
    setup_sigcontext(frame, tf);
    frame.uc._sigmask = task::current().blocked.load(Ordering::Relaxed) as usize;

    // Note: Now we store user_rt_sigreturn code into user stack,
    // but it's unsafe to execute code on stack.
    // Consider to implement vdso and put that code in vdso page.
    let user_rt_sigreturn = __user_rt_sigreturn as usize as *const usize;
    frame.sigreturn_code = unsafe { *user_rt_sigreturn };

    let ra = &(frame.sigreturn_code) as *const usize;
    /* Make sure the two instructions are pushed to icache. */
    local_flush_icache_all();
    tf.regs.ra = ra as usize;

    assert!(ksig.action.handler != 0);
    tf.sepc = ksig.action.handler;
    tf.regs.sp = frame_addr;
    tf.regs.a0 = ksig.signo;    // a0: signal number
    /*
    tf.regs.a1 = &frame.info;   // a1: siginfo pointer
    tf.regs.a2 = &frame.uc;     // a2: ucontext pointer
    */

    signal_setup_done(ksig);
    info!("handle_signal signo {} frame {:#X} tf.epc {:#x}",
          ksig.signo, frame.sigreturn_code, tf.sepc);
}

fn signal_setup_done(ksig: &KSignal) {
    signal_delivered(ksig)
}

///
/// signal_delivered -
/// @ksig:       kernel signal struct
///
/// This function should be called when a signal has successfully been
/// delivered. It updates the blocked signals accordingly (@ksig->ka.sa.sa_mask
/// is always blocked, and the signal itself is blocked unless %SA_NODEFER
/// is set in @ksig->ka.sa.sa_flags.
///
fn signal_delivered(ksig: &KSignal) {
    let mut blocked = 0;

    /* A signal was successfully delivered, and the
       saved sigmask was stored on the signal frame,
       and will be restored by sigreturn.  So we can
       simply clear the restore sigmask flag.  */
    // Todo: handle clear_restore_sigmask
    //clear_restore_sigmask();

    sigorsets(&mut blocked,
        task::current().blocked.load(Ordering::Relaxed),
        ksig.action.mask);

    if (ksig.action.flags & SA_NODEFER) == 0 {
        sigaddset(&mut blocked, ksig.signo);
    }
    set_current_blocked(blocked);
}

/**
 * set_current_blocked - change current->blocked mask
 * @newset: new mask
 *
 * It is wrong to change ->blocked directly, this helper should be used
 * to ensure the process can't miss a shared signal we are going to block.
 */
fn set_current_blocked(mut newset: u64) {
    sigdelsetmask(&mut newset, sigmask(SIGKILL) | sigmask(SIGSTOP));
    // Todo: implement __set_current_blocked according to linux.
    //__set_current_blocked(newset);
    task::current().blocked.store(newset, Ordering::Relaxed);
    recalc_sigpending();
}

fn recalc_sigpending() {
    debug!("recalc_sigpending clear_tsk_thread_flag");
    taskctx::current_ctx().clear_tsk_thread_flag(TIF_SIGPENDING);
}
