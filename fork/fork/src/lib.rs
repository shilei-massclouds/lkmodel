#![no_std]

mod arch;

#[macro_use]
extern crate axlog2;
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use axerrno::{LinuxError, LinuxResult};
use axhal::{arch::TrapFrame, trap::TRAPFRAME_SIZE};
use mm::MmStruct;
use task::{current, Tid, TaskRef, TaskStruct};
use spinbase::SpinNoIrq;
use task::SIGCHLD;

bitflags::bitflags! {
    /// clone flags
    #[derive(Debug, Copy, Clone)]
    pub struct CloneFlags: usize {
        /// signal mask to be sent at exit
        const CSIGNAL       = 0x000000ff;
        /// set if VM shared between processes
        const CLONE_VM      = 0x00000100;
        /// set if fs info shared between processes
        const CLONE_FS      = 0x00000200;
        /// set if open files shared between processes
        const CLONE_FILES   = 0x00000400;
        /// set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = 0x00000800;
        /// set if the parent wants the child to wake it up on mm_release
        const CLONE_VFORK   = 0x00004000;
        /// set if we want to have the same parent as the cloner
        const CLONE_PARENT  = 0x00008000;
        /// Same thread group?
        const CLONE_THREAD  = 0x00010000;
        /// create a new TLS for the child
        const CLONE_SETTLS  = 0x00080000;

        /// set the TID in the parent
        const CLONE_PARENT_SETTID   = 0x00100000;
        /// clear the TID in the child
        const CLONE_CHILD_CLEARTID  = 0x00200000;
        /// set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED        = 0x00800000;
        /// set the TID in the child
        const CLONE_CHILD_SETTID    = 0x01000000;
    }
}

struct KernelCloneArgs {
    flags: CloneFlags,
    _name: String,
    exit_signal: i32,
    tls: usize,
    parent_tid: usize,
    child_tid: usize,
    stack: Option<usize>,
    entry: Option<*mut dyn FnOnce()>,
}

impl KernelCloneArgs {
    fn new(
        flags: CloneFlags,
        name: &str,
        exit_signal: i32,
        tls: usize,
        parent_tid: usize,
        child_tid: usize,
        stack: Option<usize>,
        entry: Option<*mut dyn FnOnce()>,
    ) -> Self {
        Self {
            flags,
            _name: String::from(name),
            exit_signal,
            tls,
            parent_tid,
            child_tid,
            stack,
            entry,
        }
    }

    /// The main fork-routine, as kernel_clone in linux kernel.
    ///
    /// It copies the process, and if successful kick-starts it and
    /// waits for it to finish using the VM if required.
    /// The arg *exit_signal* is expected to be checked for sanity
    /// by the caller.
    fn perform(&self) -> LinuxResult<Tid> {
        // Todo: handle ptrace in future.
        let trace = !self.flags.contains(CloneFlags::CLONE_UNTRACED);
        let task = self.copy_process(None, trace)?;
        debug!(
            "sched task fork: tid[{}] -> tid[{}].",
            task::current().tid(),
            task.tid()
        );

        let tid = task.tid();
        if self.flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
            let ptid_ptr = self.parent_tid as *mut usize;
            unsafe { (*ptid_ptr) = tid; }
        }

        self.wake_up_new_task(task.clone());

        if self.flags.contains(CloneFlags::CLONE_VFORK) {
            task.wait_for_vfork_done();
        }

        Ok(tid)
    }

    /// Wake up a newly created task for the first time.
    ///
    /// This function will do some initial scheduler statistics housekeeping
    /// that must be done for every newly created context, then puts the task
    /// on the runqueue and wakes it.
    fn wake_up_new_task(&self, task: TaskRef) {
        let rq = run_queue::task_rq(&task.sched_info);
        rq.lock().activate_task(task.sched_info.clone());
        info!("wakeup the new task[{}].", task.tid());
    }

    fn copy_process(&self, tid: Option<Tid>, _trace: bool) -> LinuxResult<TaskRef> {
        info!("copy_process...");
        //assert!(!trace);
        let tid = match tid {
            Some(tid) => tid,
            None => task::alloc_tid(),
        };

        let mut task = current().dup_task_struct();
        //copy_files();
        self.copy_fs(&mut task)?;
        self.copy_sighand(&mut task)?;
        //copy_signal();
        
        self.copy_mm(&mut task)?;
        
        self.copy_thread(&mut task, tid)?;
        match task.sched_info.kstack {
            None => {
                info!("user mode stack is NOne");
            }
            _ => {
                info!(" user mode stack set ok");
            }
        }
        if self.flags.contains(CloneFlags::CLONE_VFORK) {
            task.init_vfork_done();
        }
        info!("new_brk:0x{:0x}" , task.mm().lock().brk());
        let arc_task = Arc::new(task);
        task::register_task(arc_task.clone());
        info!("copy_process tid: {} -> {}", current().tid(), arc_task.tid());
        Ok(arc_task)
    }

    fn copy_sighand(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_SIGHAND) {
            task.sighand = task::current().sighand.clone();
        } else {
            task.sighand.lock().action = task::current().sighand.lock().action;
        }
        Ok(())
    }

    fn copy_thread(&self, task: &mut TaskStruct, tid: Tid) -> LinuxResult {
        let current_ctx = taskctx::current_ctx();
        let group_leader;
        let tgid;
        if self.flags.contains(CloneFlags::CLONE_THREAD) {
            group_leader =
            match &current_ctx.group_leader {
                Some(leader) => Some(leader.clone()),
                None => {
                    Some(current_ctx.as_ctx_ref().clone())
                },
            };
            assert!(group_leader.is_some());
            tgid = current_ctx.tgid();
        } else {
            group_leader = None;
            tgid = tid;
        }

        // CLONE_PARENT re-uses the old parent
        let real_parent;
        let exit_signal: i32;
        if self.flags.contains(CloneFlags::CLONE_PARENT) ||
            self.flags.contains(CloneFlags::CLONE_THREAD) {
            real_parent = current_ctx.real_parent.clone();
            if self.flags.contains(CloneFlags::CLONE_THREAD) {
                exit_signal = -1;
            } else {
                // Todo: add exit_signal in taskctx
                //exit_signal = current_ctx.group_leader.exit_signal;
                exit_signal = SIGCHLD as i32;
            }
        } else {
            real_parent = Some(current_ctx.as_ctx_ref().clone());
            exit_signal = self.exit_signal;
        }

        // Todo: thread_group_leader
        if group_leader.is_none() {
            real_parent.clone().unwrap().children.lock().push(tid);
        } else {
            group_leader.clone().unwrap().siblings.lock().push(tid);
        }

        // Todo: in exit_mm_release && exec_mm_release, handle clear_child_tid.
        /*
         * This _must_ happen before we call free_task(), i.e. before we jump
         * to any of the bad_fork_* labels. This is to avoid freeing
         * p->set_child_tid which is (ab)used as a kthread's data pointer for
         * kernel threads (PF_KTHREAD).
         */
        let set_child_tid =
            if self.flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
                self.child_tid
            } else {
                0
            };

        /*
         * Clear TID on mm_release()?
         */
        let clear_child_tid =
            if self.flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
                self.child_tid
            } else {
                0
            };

        warn!("Todo: handle exit_signal {}", exit_signal);
        arch::copy_thread(task, self, tid, tgid, set_child_tid, clear_child_tid, real_parent, group_leader)
    }

    fn copy_mm(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_VM) {
            task.mm = current().mm.clone();
        } else {
            info!("copy_mm: NO CLONE_VM");
            let mm: mm::MmStruct = current().mm().lock().deep_dup();
            task.mm = Some(Arc::new(SpinNoIrq::new(mm)));
        }
        Ok(())
    }

    fn copy_fs(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_FS) {
            info!("clone fs ssss");
            /* task.fs is already what we want */
            let fs = task::current().fs.clone();
            let mut locked_fs = fs.lock();
            if locked_fs.in_exec {
                return Err(LinuxError::EAGAIN);
            }
            locked_fs.users += 1;
            return Ok(());
        }
        task.fs.lock().copy_fs_struct(task::current().fs.clone());
        Ok(())
    }
}

// Todo: We should move task_entry to taskctx.
// Now schedule_tail: 'run_queue::force_unlock();` hinders us.
// Consider to move it to sched first!
use core::arch::asm;
extern "C" fn task_entry() -> ! {
    info!("################ task_entry ...");
    // schedule_tail
    // unlock runqueue for freshly created task
    run_queue::force_unlock();

    let task = crate::current();
    if task.sched_info.set_child_tid != 0 {
        let ctid_ptr = task.sched_info.set_child_tid as *mut usize;
        unsafe { (*ctid_ptr) = task.sched_info.tid(); }
    }

    let value = task::current().pt_regs_addr() + TRAPFRAME_SIZE;

    unsafe {
        asm!("csrw sscratch, {}", in(reg) value);
    }

    info!("Value has been written to sscratch");

    if let Some(entry) = task.sched_info.entry {
        unsafe { Box::from_raw(entry)() };
    }

    let sp = task::current().pt_regs_addr();
    let xx = task::current().sched_info.kstack.as_ref().unwrap().top() - sp;
    info!("gap::0x{:0x}" , xx );
    unsafe {
        let debugsp = (sp + 176 - 264) as *const usize as *const TrapFrame;
        info!("spec:0x{:0x}" , (*debugsp).sepc);
    }
    axhal::arch::ret_from_fork(sp);
    unimplemented!("task_entry!");
}

/// Create a user mode thread.
///
/// Invoke `f` to do some preparations before entering userland.
pub fn user_mode_thread<F>(f: F, flags: CloneFlags) -> Tid
where
    F: FnOnce() + 'static,
{
    info!("create a user mode thread ...");
    assert_eq!(flags.intersection(CloneFlags::CSIGNAL).bits(), 0);
    //assert!((flags.bits() & CloneFlags::CSIGNAL.bits()) == 0);
    let f = Box::into_raw(Box::new(f));
    let args = KernelCloneArgs::new(
        flags | CloneFlags::CLONE_VM | CloneFlags::CLONE_UNTRACED,
        "",
        0,
        0,
        0,
        0,
        None,
        Some(f),
    );
    args.perform().expect("kernel_clone failed.")
}

///
/// Clone thread according to SysCall requirements
///
pub fn sys_clone(
    flags: usize, stack: usize, tls: usize, ptid: usize, ctid: usize
) -> usize {
    let flags = CloneFlags::from_bits_truncate(flags);
    warn!("clone: flags {:#X} stack {:#X} ptid {:#X} tls {:#X} ctid {:#X}",
        flags.bits(), stack, ptid, tls, ctid);

    let exit_signal = flags.intersection(CloneFlags::CSIGNAL).bits() as i32;
    let flags = flags.difference(CloneFlags::CSIGNAL) | CloneFlags::CLONE_FS;
    let stack = if stack == 0 {
        None
    } else {
        Some(stack)
    };
    let args = KernelCloneArgs::new(flags, "", exit_signal, tls, ptid, ctid, stack, None);
    warn!("impl clone: flags {:#X} sig {:#X} stack {:#X} ptid {:#X} tls {:#X} ctid {:#X}",
        flags.bits(), exit_signal, stack.unwrap_or(0), ptid, tls, ctid);
    args.perform().unwrap_or(usize::MAX)
}

#[cfg(target_arch = "x86_64")]
pub fn sys_vfork() -> usize {
    let flags = CloneFlags::CLONE_VFORK | CloneFlags::CLONE_VM;
    let args = KernelCloneArgs::new(flags, "", SIGCHLD as i32, 0, 0, 0, None, None);
    args.perform().unwrap_or(usize::MAX)
}

pub fn set_tid_address(tidptr: usize) -> usize {
    info!("set_tid_address: tidptr {:#X}", tidptr);
    let mut ctx = taskctx::current_ctx();
    info!("get current context");
    ctx.as_ctx_mut().clear_child_tid = tidptr;
    0
}
