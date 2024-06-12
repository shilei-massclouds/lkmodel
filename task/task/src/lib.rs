#![no_std]
#![feature(get_mut_unchecked)]
#![feature(const_trait_impl)]
#![feature(effects)]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{Ordering, AtomicUsize, AtomicU32};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

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
pub const SIGSEGV: usize = 11;
pub const SIGCHLD: usize = 17;
pub const SIGSTOP: usize = 19;

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

// Note: No restorer in sigaction for riscv64.
#[derive(Copy, Clone, Default)]
pub struct SigAction {
    pub handler: usize,
    pub flags: usize,
    pub mask: usize,
}

pub struct SigPending {
    pub list: Vec<SigInfo>,
    pub signal: usize,
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

pub struct TaskStruct {
    pub mm: Option<Arc<SpinNoIrq<MmStruct>>>,
    pub fs: Arc<SpinLock<FsStruct>>,
    pub filetable: Arc<SpinLock<FileTable>>,
    pub sigpending: SpinLock<SigPending>,
    pub sighand: Arc<SpinLock<SigHand>>,
    pub sched_info: Arc<SchedInfo>,

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
            sched_info: taskctx::init_sched_info(),

            exit_state: AtomicUsize::new(0),
            exit_code: AtomicU32::new(0),
            vfork_done: None,
        }
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
        let mut task = Self::new();
        task.fs = self.fs.clone();
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

    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        info!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task.sched_info.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }

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
    unimplemented!("yield_now");
}

pub fn init() {
    info!("task::init ...");
    let init_task = TaskStruct::new();
    init_task.set_state(TaskState::Running);
    let init_task = Arc::new(init_task);
    let tid = alloc_tid();
    assert_eq!(tid, 0);
    register_task(init_task.clone());//<  tid,Arc<TaskStruct>  > map
    unsafe { CurrentTask::init_current(init_task.clone()) }
    run_queue::init(init_task.sched_info.clone());
}
