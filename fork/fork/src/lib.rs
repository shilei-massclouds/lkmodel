#![no_std]

mod arch;

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use axerrno::{LinuxError, LinuxResult};
use task::{current, Tid, TaskRef, TaskStruct};
use spinpreempt::SpinLock;
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
        info!(
            "sched task fork: tid[{}] -> tid[{}]. irqs {}",
            task::current().tid(), task.tid(),
            axhal::arch::irqs_enabled()
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
        task::activate(task.clone());
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

        self.copy_files(&mut task)?;
        self.copy_fs(&mut task)?;
        self.copy_sighand(&mut task)?;
        //copy_signal();
        self.copy_mm(&mut task)?;
        self.copy_thread(&mut task, tid)?;

        if self.flags.contains(CloneFlags::CLONE_VFORK) {
            task.init_vfork_done();
        }

        let arc_task = Arc::new(task);
        task::register_task(arc_task.clone());
        info!("copy_process tid: {} -> {}", current().tid(), arc_task.tid());
        Ok(arc_task)
    }

    fn copy_files(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_FILES) {
            task.filetable = task::current().filetable.clone();
            Ok(())
        } else {
            let current = task::current();
            let src_files = current.filetable.lock();
            task.filetable.lock().copy_from(&src_files);
            Ok(())
        }
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

        let mut sched_info = run_queue::spawn_task(tid, self.entry);
        sched_info.init_tgid(tgid);
        sched_info.real_parent = real_parent;
        sched_info.group_leader = group_leader;
        sched_info.set_child_tid = set_child_tid;
        sched_info.clear_child_tid = clear_child_tid;
        if let Some(mm) = task.try_mm() {
            let locked_mm = mm.lock();
            sched_info.set_mm(locked_mm.id(), locked_mm.pgd());
        }

        arch::copy_thread(sched_info.pt_regs(), self)?;
        task.sched_info = Arc::new(sched_info);
        Ok(())
    }

    fn copy_mm(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_VM) {
            info!("copy_mm: CLONE_VM");
            task.mm = current().mm.clone();
        } else {
            info!("copy_mm: NO CLONE_VM");
            let mm = current().mm().lock().deep_dup();
            task.mm = Some(Arc::new(SpinLock::new(mm)));
        }
        Ok(())
    }

    fn copy_fs(&self, task: &mut TaskStruct) -> LinuxResult {
        if self.flags.contains(CloneFlags::CLONE_FS) {
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
    let flags = flags.difference(CloneFlags::CSIGNAL);
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
    ctx.as_ctx_mut().clear_child_tid = tidptr;
    ctx.tid()
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    task::init(cpu_id, dtb_pa);
}
