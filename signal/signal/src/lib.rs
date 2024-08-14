#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod arch;
pub use arch::rt_sigreturn;

use alloc::sync::Arc;
use taskctx::Tid;
use task::{SigInfo, SigAction, SA_RESTORER, SA_RESTART};
use axerrno::LinuxResult;
use task::{SIGKILL, SIGSTOP, TaskStruct};
use axhal::arch::TrapFrame;
use core::sync::atomic::Ordering;
use taskctx::TIF_SIGPENDING;
use taskctx::{_TIF_SIGPENDING, _TIF_NOTIFY_SIGNAL};
use axtype::ffz;

/// si_code values
/// Digital reserves positive values for kernel-generated signals.

// sent by kill, sigsend, raise
const SI_USER: usize = 0;

#[derive(Clone)]
struct UContext {
    _flags: usize,
    _stack: usize,
    _sigmask: usize,
    mcontext: TrapFrame,
}

#[repr(C)]
#[derive(Clone)]
struct RTSigFrame {
    info: SigInfo,
    uc: UContext,
    sigreturn_code: usize,
}

pub const SIGFRAME_SIZE: usize = core::mem::size_of::<RTSigFrame>();

struct KSignal {
    action: SigAction,
    _info: SigInfo,
    signo: usize,
}

//#define SI_KERNEL   0x80        /* sent by the kernel from somewhere */
//#define SI_QUEUE    -1      /* sent by sigqueue */
//#define SI_TIMER    -2      /* sent by timer expiration */
//#define SI_MESGQ    -3      /* sent by real time mesq state change */
//#define SI_ASYNCIO  -4      /* sent by AIO completion */
//#define SI_SIGIO    -5      /* sent by queued SIGIO */
//#define SI_TKILL    -6      /* sent by tkill system call */
//#define SI_DETHREAD -7      /* sent by execve() killing subsidiary threads */
//#define SI_ASYNCNL  -60     /* sent by glibc async name lookup completion */
//
//#define SI_FROMUSER(siptr)  ((siptr)->si_code <= 0)
//#define SI_FROMKERNEL(siptr)    ((siptr)->si_code > 0)

pub fn kill(tid: Tid, sig: usize) -> usize {
    debug!("kill tid {} sig {}", tid, sig);
    assert!(tid > 0);
    let info = prepare_kill_siginfo(sig, tid);
    kill_proc_info(sig, info, tid).unwrap();
    0
}

pub fn prepare_kill_siginfo(sig: usize, tid: Tid) -> SigInfo {
    SigInfo {
        signo: sig as i32,
        errno: 0,
        code: SI_USER as i32,
        tid: tid,
    }
}

fn kill_proc_info(sig: usize, info: SigInfo, tid: Tid) -> LinuxResult {
    assert!(tid > 0);
    if sig != 0 {
        do_send_sig_info(sig, info, tid)
    } else {
        Ok(())
    }
}

fn do_send_sig_info(sig: usize, info: SigInfo, tid: Tid) -> LinuxResult {
    let task = task::get_task(tid).unwrap();
    let mut pending = task.sigpending.lock();
    pending.list.push(info);
    sigaddset(&mut pending.signal, sig);
    signal_wake_up(task.clone());
    error!("do_send_sig_info tid {} sig {} ok!", tid, sig);
    Ok(())
}

fn signal_wake_up(task: Arc<TaskStruct>) {
    task.sched_info.set_tsk_thread_flag(TIF_SIGPENDING)
}

#[inline]
fn sigmask(signo: usize) -> u64 {
    1 << (signo - 1)
}

#[inline]
fn sigaddset(set: &mut u64, signo: usize) {
    *set |= 1 << (signo - 1);
}

#[inline]
fn sigdelsetmask(set: &mut u64, mask: u64) {
    *set &= !mask;
}

#[inline]
fn sigorsets(rset: &mut u64, set1: u64, set2: u64) {
    *rset = set1 | set2;
}

pub fn rt_sigaction(sig: usize, act: usize, oact: usize, sigsetsize: usize) -> usize {
    assert_eq!(sigsetsize, 8);
    debug!("rt_sigaction: sig {} act {:#X} oact {:#X}", sig, act, oact);

    let task = task::current();

    if oact != 0 {
        let oact = oact as *mut SigAction;
        unsafe {
            *oact = task.sighand.lock().action[sig - 1];
        }
    }

    if act != 0 {
        let act = unsafe { &(*(act as *const SigAction)) };
        debug!("act: {:#X} {:#X} {:#X}", act.handler, act.flags, act.mask);
        assert!((act.flags & SA_RESTORER) == 0);

        let mut kact = act.clone();
        sigdelsetmask(&mut kact.mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
        debug!("get_signal signo {} handler {:#X}", sig, kact.handler);
        task.sighand.lock().action[sig - 1] = kact;
    }
    0
}

pub fn do_signal(tf: &mut TrapFrame, cause: usize) {
    debug!("do_signal ...");

    {
        let thread_info_flags = taskctx::current_ctx().flags.load(Ordering::Relaxed);
        if thread_info_flags != 0 {
            error!("thread_info_flags {:#x}", thread_info_flags);
        }
        if (thread_info_flags & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL)) == 0 {
            return;
        }
    }

    if let Some(ksig) = get_signal() {
        /* Actually deliver the signal */
        arch::handle_signal(&ksig, tf, cause);
        return;
    }

    // Todo: handle 'regs->cause == EXC_SYSCALL';
}

fn get_signal() -> Option<KSignal> {
    let task = task::current();
    let blocked = task.blocked.load(Ordering::Relaxed);
    let mut sigpending = task.sigpending.lock();
    let signo = next_signal(sigpending.signal, blocked)?;
    let (idx, _) = sigpending.list.iter().enumerate().find(|(_, &ref item)| {
        item.signo == signo as i32
    })?;
    error!("next_signal: index {}, signo {}", idx, signo);

    let _info = sigpending.list.remove(idx);
    assert_eq!(signo, _info.signo as usize);

    let action = task.sighand.lock().action[signo - 1];
    assert!(action.handler != 0);
    debug!("get_signal signo {} handler {:#X}", signo, action.handler);
    Some(KSignal {action, _info, signo})
}

fn next_signal(mut sigset: u64, blocked: u64) -> Option<usize> {
    sigdelsetmask(&mut sigset, blocked);
    Some(ffz(sigset)? + 1)
}

fn restore_sigcontext(tf: &mut TrapFrame, frame: &RTSigFrame) {
    *tf = frame.uc.mcontext.clone();
    // Todo: Restore the floating-point state. */
}

fn setup_sigcontext(frame: &mut RTSigFrame, tf: &TrapFrame) {
    frame.uc.mcontext = tf.clone();
    // Todo: Save the floating-point state.
}

pub fn force_sig_fault(signo: usize, code: usize, _addr: usize) {
    let tid = taskctx::current_ctx().tid();
    let info = SigInfo {
        signo: signo as i32,
        errno: 0,
        code: code as i32,
        tid: tid,
    };

    debug!("force tid {} sig {}", tid, signo);
    do_send_sig_info(signo, info, tid).unwrap();
}
