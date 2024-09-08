#![no_std]
#![feature(get_mut_unchecked)]
#![feature(const_trait_impl)]
#![feature(effects)]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{Ordering, AtomicUsize, AtomicU32, AtomicU64};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use axtype::{RLimit64, RLIM_NLIMITS};
use axtype::{RLIMIT_DATA, RLIMIT_STACK, RLIMIT_CORE, RLIMIT_NOFILE};
use axhal::arch::TaskContext as ThreadStruct;
use mm::MmStruct;
use taskctx::switch_mm;
use taskctx::SchedInfo;
use taskctx::TaskState;
use spinbase::SpinNoIrq;
use spinpreempt::SpinLock;
use fstree::FsStruct;
use filetable::FileTable;
use wait_queue::WaitQueue;
use preempt_guard::NoPreempt;
use axconfig::TASK_STACK_SIZE;

pub use crate::tid_map::{register_task, unregister_task, get_task};
pub use taskctx::Tid;
pub use taskctx::current_ctx;
pub use taskctx::{TaskStack, THREAD_SIZE};
pub use tid::alloc_tid;

mod tid;
mod tid_map;

const NSIG: usize = 64;

pub const SIGINT : usize = 2;
pub const SIGKILL: usize = 9;
pub const SIGBUS : usize = 7;
pub const SIGSEGV: usize = 11;
pub const SIGPIPE: usize = 13;
pub const SIGCHLD: usize = 17;
pub const SIGSTOP: usize = 19;

/*
 * SIGBUS si_codes
 */
//#define BUS_ADRALN  1   /* invalid address alignment */
pub const BUS_ADRERR : usize =  2;  // non-existent physical address

#[derive(Clone)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    pub tid: Tid,
}

/// signal action flags
pub const SA_RESTORER:  usize = 0x4000000;
pub const SA_RESTART:   usize = 0x10000000;
pub const SA_NODEFER:   usize = 0x40000000;

// Note: No restorer in sigaction for riscv64.
#[derive(Copy, Clone, Default)]
pub struct SigAction {
    pub handler: usize,
    pub flags: usize,
    pub mask: u64,
}

pub struct SigPending {
    pub list: Vec<SigInfo>,
    pub signal: u64,
}

impl SigPending {
    pub fn new() -> Self {
        Self {
            list: Vec::new(),
            signal: 0,
        }
    }
}

pub struct SigHand {
    pub action: [SigAction; NSIG],
}

impl SigHand {
    pub fn new() -> Self {
        Self {
            action: [SigAction::default(); NSIG],
        }
    }
}

#[derive(Default)]
pub struct Cred {
    pub uid:    u32,    // real UID of the task
    pub gid:    u32,    // real GID of the task
    pub suid:   u32,    // saved UID of the task
    pub sgid:   u32,    // saved GID of the task
    pub euid:   u32,    // effective UID of the task
    pub egid:   u32,    // effective GID of the task
    pub fsuid:   u32,   // UID for filesystem
    pub fsgid:   u32,   // GID for filesystem
}

pub struct TaskStruct {
    pub mm: Option<Arc<SpinNoIrq<MmStruct>>>,
    pub fs: Arc<SpinLock<FsStruct>>,
    pub filetable: Arc<SpinLock<FileTable>>,
    pub sigpending: SpinLock<SigPending>,
    pub sighand: Arc<SpinLock<SigHand>>,
    pub rlim: [RLimit64; RLIM_NLIMITS],
    pub blocked: AtomicU64,
    pub sched_info: Arc<SchedInfo>,
    pub cred: Arc<SpinLock<Cred>>,

    pub exit_state: AtomicUsize,
    pub exit_code: AtomicU32,
    pub vfork_done: Option<WaitQueue>,
}

unsafe impl Send for TaskStruct {}
unsafe impl Sync for TaskStruct {}

impl TaskStruct {
    pub fn new() -> Self {
        Self {
            mm: None,
            fs: fstree::init_fs(),
            filetable: filetable::init_files(),
            sigpending: SpinLock::new(SigPending::new()),
            sighand: Arc::new(SpinLock::new(SigHand::new())),
            rlim: rlimit_init(),
            blocked: AtomicU64::new(0),
            sched_info: taskctx::init_thread(),
            cred: Arc::new(SpinLock::new(Cred::default())),

            exit_state: AtomicUsize::new(0),
            exit_code: AtomicU32::new(0),
            vfork_done: None,
        }
    }

    pub fn fsuid(&self) -> u32 {
        self.cred.lock().fsuid
    }

    pub fn fsgid(&self) -> u32 {
        self.cred.lock().fsgid
    }

    pub fn tid(&self) -> Tid {
        self.sched_info.tid()
    }

    pub fn tgid(&self) -> usize {
        self.sched_info.tgid()
    }

    pub fn pt_regs_addr(&self) -> usize {
        self.sched_info.pt_regs_addr()
    }

    pub fn try_mm(&self) -> Option<Arc<SpinNoIrq<MmStruct>>> {
        self.mm.as_ref().and_then(|mm| Some(mm.clone()))
    }

    pub fn mm(&self) -> Arc<SpinNoIrq<MmStruct>> {
        self.mm.as_ref().expect("NOT a user process.").clone()
    }

    // Safety: makesure to be under NoPreempt
    pub fn alloc_mm(&mut self) {
        info!("alloc_mm...");
        //assert!(self.mm.is_none());
        let mm = MmStruct::new();
        let mm_id = mm.id();
        self.mm.replace(Arc::new(SpinNoIrq::new(mm)));
        info!("================== mmid {}", mm_id);
        let mut ctx = taskctx::current_ctx();
        ctx.mm_id.store(mm_id, Ordering::Relaxed);
        ctx.active_mm_id.store(mm_id, Ordering::Relaxed);
        ctx.as_ctx_mut().pgd = Some(self.mm().lock().pgd().clone());
        switch_mm(0, mm_id, self.mm().lock().pgd());
    }

    pub fn dup_task_struct(&self) -> Self {
        info!("dup_task_struct ...");
        let task = Self::new();
        task.blocked.store(self.blocked.load(Ordering::Relaxed), Ordering::Relaxed);
        task
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.sched_info.ctx_mut_ptr()
    }

    #[inline]
    pub fn set_state(&self, state: TaskState) {
        self.sched_info.set_state(state)
    }

    pub fn init_vfork_done(&mut self) {
        self.vfork_done = Some(WaitQueue::new());
    }

    pub fn wait_for_vfork_done(&self) {
        match self.vfork_done {
            Some(ref done) => {
                done.wait();
            },
            None => panic!("vfork_done hasn't been inited yet!"),
        }
    }

    pub fn complete_vfork_done(&self) {
        if let Some(done) = &self.vfork_done {
            done.notify_one(true);
        }
    }

    pub fn has_vfork_done(&self) -> bool {
        self.vfork_done.is_some()
    }
}

// Todo: It is unsafe extremely. We must remove it!!!
// Now it's just for fork.copy_process.
// In fact, we can prepare everything and then init task in the end.
// At that time, we can remove as_task_mut.
pub fn as_task_mut(task: TaskRef) -> &'static mut TaskStruct {
    unsafe {
        &mut (*(Arc::as_ptr(&task) as *mut TaskStruct))
    }
}

/// The reference type of a task.
pub type TaskRef = Arc<TaskStruct>;

/// A wrapper of [`TaskRef`] as the current task.
pub struct CurrentTask(ManuallyDrop<TaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        if let Some(ctx) = taskctx::try_current_ctx() {
            let tid = ctx.tid();
            let task = get_task(tid).expect("try_get None");
            Some(Self(ManuallyDrop::new(task)))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    pub fn ptr_eq(&self, other: &TaskRef) -> bool {
        Arc::ptr_eq(&self, other)
    }

    /// Converts [`CurrentTask`] to [`TaskRef`].
    pub fn as_task_ref(&self) -> &TaskRef {
        &self.0
    }

    pub fn as_task_mut(&mut self) -> &mut TaskStruct {
        unsafe {
            Arc::get_mut_unchecked(&mut self.0)
        }
    }

    /*
    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        info!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task.sched_info.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }
    */

    pub unsafe fn set_current(prev: Self, next: TaskRef) {
        info!("CurrentTask::set_current...");
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next.sched_info.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskRef;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    let cur = current();
    let rq = run_queue::task_rq(&cur.sched_info);
    rq.lock().resched(false);
}

pub fn activate(task: TaskRef) {
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().activate_task(task.sched_info.clone());
}

pub fn alloc_mm() {
    let _ = NoPreempt::new();
    let mut task = current();
    task.as_task_mut().alloc_mm();
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();
    info!("Initialize schedule system ...");

    //run_queue::init(cpu_id, dtb_pa);
    fstree::init(cpu_id, dtb_pa);

    let init_task = TaskStruct::new();
    init_task.set_state(TaskState::Running);
    let init_task = Arc::new(init_task);
    let tid = alloc_tid();
    assert_eq!(tid, 0);
    register_task(init_task.clone());
    //unsafe { CurrentTask::init_current(init_task.clone()) }
}

fn rlimit_init() -> [RLimit64; RLIM_NLIMITS] {
    let mut ret = [RLimit64::default(); RLIM_NLIMITS];
    ret[RLIMIT_DATA] = RLimit64::new(u64::MAX, u64::MAX);
    ret[RLIMIT_STACK] = RLimit64::new(TASK_STACK_SIZE as u64, u64::MAX);
    ret[RLIMIT_CORE] = RLimit64::new(u64::MAX, u64::MAX);
    ret[RLIMIT_NOFILE] = RLimit64::new(0x400, 0x1000);
    ret
}
