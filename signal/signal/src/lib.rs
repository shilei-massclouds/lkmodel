#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod arch;
pub use arch::rt_sigreturn;

use core::mem;
use alloc::sync::Arc;
use taskctx::Tid;
use task::{SigInfo, SigAction, SA_RESTORER, SA_RESTART};
use axerrno::{linux_err, LinuxError, LinuxResult};
use task::{SIGKILL, SIGSTOP, TaskStruct};
use axhal::arch::TrapFrame;
use core::sync::atomic::Ordering;
use taskctx::TIF_SIGPENDING;
use taskctx::{_TIF_SIGPENDING, _TIF_NOTIFY_SIGNAL};
use axtype::ffz;

const SIG_DFL: usize = 0;   // default signal handling
//const SIG_IGN: usize = 1;   // ignore signal
//const SIG_ERR: usize = -1;  // error return from signal

const SIG_BLOCK:    usize = 0; // for blocking signals
const SIG_UNBLOCK:  usize = 1; // for unblocking signals
const SIG_SETMASK:  usize = 2; // for setting the signal mask

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

pub fn kill(tid: isize, sig: usize) -> usize {
    info!("kill tid {} sig {}", tid, sig);
    let info = prepare_kill_siginfo(sig);
    kill_proc_info(sig, info, tid).unwrap();
    0
}

pub fn prepare_kill_siginfo(sig: usize) -> SigInfo {
    SigInfo {
        signo: sig as i32,
        errno: 0,
        code: SI_USER as i32,
    }
}

fn kill_proc_info(sig: usize, info: SigInfo, tid: isize) -> LinuxResult {
    error!("kill_proc_info: tid {} sig {}", tid, sig);
    if tid > 0 {
        if sig != 0 {
            return do_send_sig_info(sig, info, tid as usize);
        } else {
            return Ok(());
        }
    }

    if tid == 0 {
        panic!("tid == 0");
    }
    if tid == -1 {
        panic!("tid == -1");
    }

    assert!(tid < -1);
    let tid = -tid as usize;
    let tid_map = task::get_tid_map().lock();
    for (_, t) in tid_map.iter() {
        if tid == t.tgid() {
            panic!("tgid: {}", t.tgid());
        }
    }
    Ok(())
}

fn do_send_sig_info(sig: usize, info: SigInfo, tid: Tid) -> LinuxResult {
    debug!("do_send_sig_info tid {:#x} sig {} ...", tid, sig);
    let task = if let Some(tsk) = task::get_task(tid) {
        tsk
    } else {
        warn!("No task [{:#x}].", tid);
        return Ok(());
    };
    let mut pending = task.sigpending.lock();
    pending.list.push(info);
    sigaddset(&mut pending.signal, sig);
    signal_wake_up(task.clone());
    debug!("do_send_sig_info tid {:#x} sig {} ok!", tid, sig);
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

#[inline]
fn sigandnsets(rset: &mut u64, set1: u64, set2: u64) {
    *rset = set1 & set2;
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
        info!("act: {:#X} {:#X} {:#X}", act.handler, act.flags, act.mask);
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
    debug!("next_signal: index {}, signo {}", idx, signo);

    let _info = sigpending.list.remove(idx);
    assert_eq!(signo, _info.signo as usize);

    let action = task.sighand.lock().action[signo - 1];
    if action.handler != SIG_DFL {
        debug!("get_signal signo {} handler {:#X}", signo, action.handler);
        return Some(KSignal {action, _info, signo});
    }

    let leader = if let Some(leader) = &task.sched_info.group_leader {
        force_sig_fault(leader.tid(), signo, 0, 0);
        leader
    } else {
        &task.sched_info
    };

    for tid in leader.siblings.lock().iter() {
        if *tid == task.tid() {
            continue;
        }
        force_sig_fault(*tid, signo, 0, 0);
    }

    sys::do_group_exit(signo as u32)
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

pub fn force_sig_fault(tid: Tid, signo: usize, code: usize, _addr: usize) {
    let info = SigInfo {
        signo: signo as i32,
        errno: 0,
        code: code as i32,
        //tid: tid,
    };

    debug!("force tid {} sig {}", tid, signo);
    do_send_sig_info(signo, info, tid).unwrap();
}

pub fn rt_sigprocmask(how: usize, nset: usize, oset: usize, sigsetsize: usize) -> usize {
    info!(
        "impl sigprocmask how {} nset {:#X} oset {:#X} size {} tid {}",
        how, nset, oset, sigsetsize, task::current().tid(),
    );

    /* XXX: Don't preclude handling different sized sigset_t's.  */
    if sigsetsize != mem::size_of::<u64>() {
        return linux_err!(EINVAL);
    }

    let old_set = task::current().blocked.load(Ordering::Relaxed);
    if nset != 0 {
        let nset = nset as *const u64;
        let mut new_set = unsafe { *nset };
        sigdelsetmask(&mut new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));
        sigprocmask(how, new_set);
    }
    if oset != 0 {
        let oset = oset as *mut u64;
        unsafe { *oset = old_set };
    }
    0
}

//
// This is also useful for kernel threads that want to temporarily
// (or permanently) block certain signals.
//
// NOTE! Unlike the user-mode sys_sigprocmask(), the kernel
// interface happily blocks "unblockable" signals like SIGKILL
// and friends.
//
fn sigprocmask(how: usize, set: u64) {
    let blocked = task::current().blocked.load(Ordering::Relaxed);

    let mut newset = 0;
    match how {
        SIG_BLOCK => sigorsets(&mut newset, blocked, set),
        SIG_UNBLOCK => sigandnsets(&mut newset, blocked, set),
        SIG_SETMASK => { newset = set },
        _ => panic!("invalid how"),
    };

    __set_current_blocked(newset);
}

fn __set_current_blocked(newset: u64) {
    let blocked = task::current().blocked.load(Ordering::Relaxed);

    /*
     * In case the signal mask hasn't changed, there is nothing we need
     * to do. The current->blocked shouldn't be modified by other task.
     */
    if blocked == newset {
        return;
    }

    //spin_lock_irq(&tsk->sighand->siglock);
    task::current().blocked.store(newset, Ordering::Relaxed);
    //spin_unlock_irq(&tsk->sighand->siglock);
}
