#![cfg_attr(not(test), no_std)]

use core::sync::atomic::Ordering;
use taskctx::Tid;
use axtype::PAGE_SIZE;
use axerrno::{LinuxResult, LinuxError, linux_err_from};
use taskctx::TaskState;
use axtype::{RLimit64, RLIM_NLIMITS};
use axtype::{RLIMIT_DATA, RLIMIT_STACK, RLIMIT_CORE, RLIMIT_NOFILE};
use axtype::{CLOCK_REALTIME, CLOCK_MONOTONIC, TimeSpec};
use axhal::time::current_time;
use axhal::arch::{irqs_enabled, enable_irqs, disable_irqs};

pub use futex::{do_futex, FUTEX_WAKE};

mod futex;

#[macro_use]
extern crate log;
extern crate alloc;

const WNOHANG: usize = 0x00000001;
const WEXITED: usize = 0x00000004;

// Used in tsk->exit_state:
const EXIT_DEAD: usize = 0x0010;
const EXIT_ZOMBIE: usize = 0x0020;
#[allow(dead_code)]
const EXIT_TRACE: usize = EXIT_ZOMBIE | EXIT_DEAD;

#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: usize = 0x1002;

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
enum PidType {
    PID,
    TGID,
    PGID,
    SID,
    MAX,
}

pub fn gettid() -> usize {
    taskctx::current_ctx().tid()
}

pub fn getpid() -> usize {
    taskctx::current_ctx().tgid()
}

pub fn getppid() -> usize {
    let ppid = taskctx::current_ctx().real_parent.as_ref().unwrap().tid();
    info!("getppid: {}", ppid);
    ppid
}

pub fn getgid() -> usize {
    let task = task::current();
    let cred = task.cred.lock();
    cred.gid as usize
}

pub fn getegid() -> usize {
    let task = task::current();
    let cred = task.cred.lock();
    cred.egid as usize
}

pub fn setpgid(pid: usize, pgid: usize) -> usize {
    warn!("impl setpgid pid {} pgid {}", pid, pgid);
    0
}

// Refer to "include/asm-generic/resource.h"
pub fn prlimit64(tid: Tid, resource: usize, new_rlim: usize, old_rlim: usize) -> usize {
    info!(
        "linux_syscall_prlimit64: tid {}, resource: {}, {:?} {:?}",
        tid, resource, new_rlim, old_rlim
    );
    assert!(tid == 0);
    assert!(resource < RLIM_NLIMITS);
    assert!(matches!(resource, RLIMIT_DATA|RLIMIT_STACK|RLIMIT_CORE|RLIMIT_NOFILE));
    let current = task::current();
    if old_rlim != 0 {
        let old_rlim = old_rlim as *mut RLimit64;
        unsafe { *old_rlim = current.rlim[resource]; }
    }
    0
}

#[cfg(target_arch = "x86_64")]
pub fn arch_prctl(code: usize, addr: usize) -> usize {
    let ctx = taskctx::current_ctx();
    match code {
        ARCH_SET_FS => {
            use axhal::arch::write_thread_pointer;
            warn!("=========== arch_prctl ARCH_SET_FS {:#X}", addr);
            unsafe {
                write_thread_pointer(addr);
                (*ctx.ctx_mut_ptr()).fs_base = addr;
            }
            0
        },
        _ =>  {
            error!("=========== arch_prctl code {:#X}", code);
            linux_err!(EPERM)
        }
    }
}

pub fn setuid(uid: usize) -> usize {
    let task = task::current();
    let mut cred = task.cred.lock();
    cred.uid = uid as u32;
    cred.euid = uid as u32;
    cred.fsuid = uid as u32;
    // Todo: handle [suid] according to capability
    0
}

pub fn setreuid(ruid: usize, euid: usize) -> usize {
    info!("setresuid: {:#x}, {:#x}", ruid, euid);
    let ruid = ruid as u32;
    let euid = euid as u32;

    let task = task::current();
    let mut cred = task.cred.lock();
    cred.uid = ruid;
    cred.euid = euid;
    cred.fsuid = euid;
    0
}

pub fn setresuid(ruid: usize, euid: usize, suid: usize) -> usize {
    info!("setresuid: {:#x}, {:#x}, {:#x}", ruid, euid, suid);
    let ruid = ruid as u32;
    let euid = euid as u32;
    let suid = suid as u32;

    let task = task::current();
    let mut cred = task.cred.lock();
    cred.uid = ruid;
    cred.euid = euid;
    cred.suid = suid;
    cred.fsuid = euid;
    0
}

pub fn setgid(gid: usize) -> usize {
    info!("setgid: {}", gid);
    let task = task::current();
    let mut cred = task.cred.lock();
    cred.gid = gid as u32;
    cred.egid = gid as u32;
    cred.fsgid = gid as u32;
    // Todo: handle [sgid] according to capability
    0
}

pub fn wait4(pid: usize, wstatus: usize, options: usize, rusage: usize) -> usize {
    let pid = pid as isize;
    info!("wait4: pid {:#X} wstatus {:#X} options {:#X} rusage {:#X} irqs {}",
           pid, wstatus, options, rusage, irqs_enabled());

    if rusage != 0 {
        // Todo: deal with rusage in future.
        warn!("+++ Handle rusage in wait4 +++");
    }
    if options != 0 {
        // Todo: deal with options in future.
        warn!("+++ Handle options in wait4 +++");
    }
    if (options & WNOHANG) != 0 {
        warn!("WNOHANG");
    }

    let pid_type =
        if pid == -1 {
            PidType::MAX
        } else if pid < 0 {
            //pid = find_get_pid(-pid);
            PidType::PGID
        } else if pid == 0 {
            //pid = get_task_pid(current, PIDTYPE_PGID);
            PidType::PGID
        } else /* pid > 0 */ {
            PidType::PID
        };

    let mut status = 0u32;
    let tid = match do_wait(pid_type, pid as usize, options|WEXITED, &mut status) {
        Ok(tid) => tid,
        Err(e) => linux_err_from!(e),
    };

    if wstatus != 0 {
        let wstatus = wstatus as *mut u32;
        unsafe {
            (*wstatus) = status;
        }
    }
    tid
}

fn do_wait(
    pid_type: PidType, tid: Tid, options: usize, status: &mut u32
) -> LinuxResult<Tid> {
    info!("do_wait: pidtype {:?} pid {:#X} options {:#X}; curr {} irqs {}",
        pid_type, tid, options, taskctx::current_ctx().tid(), irqs_enabled());

    // Todo: sleep with intr
    //set_current_state(TASK_INTERRUPTIBLE);

    loop {
        if pid_type == PidType::PID {
            if let Some(tid) = wait_pid(tid, status) {
                return Ok(tid);
            }
        } else {
            if children_count() > 0 {
                if let Some(tid) = wait_children(status) {
                    return Ok(tid);
                }
            }

            if siblings_count() > 0 {
                let ctx = taskctx::current_ctx();
                for sibling in ctx.siblings.lock().iter() {
                    let cur = task::get_task(*sibling).unwrap();
                    for child in cur.sched_info.children.lock().iter() {
                        info!("Task[{}]: has child[{}]", cur.tid(), child);
                        if let Some(tid) = wait_children(status) {
                            return Ok(tid);
                        }
                    }
                    info!("cur state {:?} exit {:?}", cur.state(), cur.exit_state);
                    if let Some(tid) = wait_task_zombie(*sibling, status) {
                        ctx.siblings.lock().retain(|&cid| cid != tid);
                        return Ok(tid);
                    }
                }
            }

            if children_count() == 0 && siblings_count() == 0 {
                return Err(LinuxError::ECHILD);
            }
        }

        if (options & WNOHANG) != 0 {
            error!("WNOHANG");
            return Ok(0);
        }

        // Todo: wait on Exit_WaitQueue of child and resched.
        let task = task::current();
        let rq = run_queue::task_rq(&task.sched_info);

        let irqs_flag = irqs_enabled();
        if !irqs_flag {
            enable_irqs();
        }

        rq.lock().resched(false);

        if !irqs_flag {
            disable_irqs();
        }
    }
}

fn wait_pid(tid: Tid, status: &mut u32) -> Option<Tid> {
    let tid = wait_task_zombie(tid, status)?;

    let ctx = taskctx::current_ctx();
    ctx.children.lock().retain(|&cid| cid != tid);
    return Some(tid);
}

fn children_count() -> usize {
    taskctx::current_ctx().children.lock().len()
}

fn siblings_count() -> usize {
    taskctx::current_ctx().siblings.lock().len()
}

fn wait_children(status: &mut u32) -> Option<Tid> {
    let ctx = taskctx::current_ctx();
    for (index, child) in ctx.children.lock().iter().enumerate() {
        debug!("Current[{}]: has child[{}]", ctx.tid(), child);
        if let Some(tid) = wait_task_zombie(*child, status) {
            info!("child[{}] zombie", *child);
            ctx.children.lock().remove(index);
            return Some(tid);
        }
    }
    None
}

fn wait_task_zombie(tid: Tid, status: &mut u32) -> Option<Tid> {
    debug!("wait_task_zombie tid {}", tid);
    let target = task::get_task(tid).unwrap();
    let exit_state = target.exit_state.compare_exchange(
        EXIT_ZOMBIE, EXIT_DEAD,
        Ordering::Relaxed, Ordering::Relaxed
    );
    if exit_state != Ok(EXIT_ZOMBIE) {
        return None;
    }

    task::unregister_task(tid);
    *status = target.exit_code.load(Ordering::Relaxed);
    Some(tid)
}

/// Exits the current task.
pub fn exit(exit_code: u32) -> ! {
    info!("task {} exit [{}] ...", taskctx::current_ctx().tid(), exit_code);
    do_exit(exit_code)
}

/// Exits the current task group.
pub fn exit_group(exit_code: u32) -> ! {
    info!("exit_group ... [{}]", exit_code);
    do_group_exit(exit_code)
}

pub fn do_group_exit(exit_code: u32) -> ! {
    debug!("do_exit_group ... [{}]", exit_code);
    do_exit(exit_code)
}

pub fn do_umask(mode: u32) -> usize {
    // Todo: use umask for mknot & open(create)
    assert_eq!(mode, 0);
    let current = task::current();
    let mut fs = current.fs.lock();
    fs.set_umask(mode);
    0
}

fn do_exit(exit_code: u32) -> ! {
    exit_mm();
    exit_notify(exit_code);
    do_task_dead()
}

fn exit_mm_release() {
    // futex_exit_release(tsk);
    mm_release();
}

fn mm_release() {
    let mut ctx = task::current_ctx();
    // Todo: temporary solution.
    // If I'm the main-thread, I don't need to notify parent by futex.
    if ctx.group_leader.is_none() {
        return;
    }
    if ctx.clear_child_tid != 0 {
        put_user_u32(0, ctx.clear_child_tid);
        do_futex(ctx.clear_child_tid, FUTEX_WAKE, 1, 0, 0, 0);
        ctx.as_ctx_mut().clear_child_tid = 0;
    }
}

fn put_user_u32(val: u32, pos: usize) -> usize {
    let ptr = pos as *mut u32;
    unsafe { *ptr = val; }
    pos + 4
}

// Todo: implement it in mm.drop
fn exit_mm() {
    let task = task::current();

    exit_mm_release();

    if task.sched_info.group_leader.is_some() {
        // Todo: dont release mm for threads.
        // It's just a temp solution. Implement page refcount.
        return;
    }

    if task.has_vfork_done() {
        // Todo: this is a temporary solution.
        // We need mm.drop to handle it automatically.
        return;
    }

    let mm = task.mm();
    let mut locked_mm = mm.lock();
    loop {
        if let Some((va, dva)) = &locked_mm.mapped.pop_first() {
            let _ = locked_mm.unmap_region((*va).into(), PAGE_SIZE);
            axalloc::global_allocator().dealloc_pages(*dva, 1);
        } else {
            break;
        }
    }
}

fn exit_notify(exit_code: u32) {
    let task = task::current();
    info!("exit_notify: tid {} code {}", task.tid(), exit_code);
    task.exit_code.store(exit_code, Ordering::Relaxed);
    task.exit_state.store(EXIT_ZOMBIE, Ordering::Relaxed);
    // Todo: wakeup parent
    task.complete_vfork_done();
}

fn do_task_dead() -> ! {
    let task = task::current();
    info!("do_task_dead ... tid {}", task.tid());

    // Causes final put_task_struct in finish_task_switch():
    task.set_state(TaskState::Dead);

    if task.tid() == 1 {
        info!("InitTask[1] exits normally ...");
        axhal::misc::terminate()
    } else {
        let rq = run_queue::task_rq(&task.sched_info);
        rq.lock().resched(false);
        unreachable!()
    }
}

pub fn clock_gettime(clockid: usize, tp: usize) -> LinuxResult<usize> {
    info!("clock_gettime: clockid {}, tp {:#x}", clockid, tp);
    assert!(clockid == CLOCK_REALTIME || clockid == CLOCK_MONOTONIC);
    let ktp = current_time();

    let tp = tp as *mut TimeSpec;
    unsafe {
        (*tp).tv_sec = ktp.as_secs() as i64;
        (*tp).tv_nsec = ktp.subsec_nanos() as i64;
    }
    Ok(0)
}
