#![no_std]
#![feature(get_mut_unchecked)]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::{alloc::Layout, cell::UnsafeCell, ptr::NonNull};
use core::sync::atomic::{AtomicUsize, AtomicU8, AtomicBool, Ordering};
use axhal::arch::TaskContext as ThreadStruct;
use axhal::arch::TrapFrame;
use axhal::trap::{TRAPFRAME_SIZE, STACK_ALIGN};
use memory_addr::{align_up_4k, align_down, PAGE_SIZE_4K};
use spinbase::SpinNoIrq;
use axhal::arch::write_page_table_root0;
use axhal::arch::irqs_enabled;
use page_table::paging::PageTable;
use lazy_init::LazyInit;

pub const THREAD_SIZE: usize = 32 * PAGE_SIZE_4K;

pub const TIF_SIGPENDING: usize     = 2;    // signal pending
pub const TIF_NOTIFY_SIGNAL: usize  = 9;    // signal notifications exist

pub const _TIF_SIGPENDING: usize = 1 << TIF_SIGPENDING;
pub const _TIF_NOTIFY_SIGNAL: usize = 1 << TIF_NOTIFY_SIGNAL;

pub type Tid = usize;

pub struct TaskStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl TaskStack {
    pub fn alloc(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).unwrap();
        Self {
            ptr: NonNull::new(unsafe { alloc::alloc::alloc(layout) }).unwrap(),
            layout,
        }
    }

    pub const fn top(&self) -> usize {
        unsafe { core::mem::transmute(self.ptr.as_ptr().add(self.layout.size())) }
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// The possible states of a task.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TaskState {
    Running = 1,
    Ready = 2,
    Blocked = 3,
    Dead = 4,
}

impl From<u8> for TaskState {
    #[inline]
    fn from(state: u8) -> Self {
        match state {
            1 => Self::Running,
            2 => Self::Ready,
            3 => Self::Blocked,
            4 => Self::Dead,
            _ => unreachable!(),
        }
    }
}

pub struct SchedInfo {
    tid:    Tid,
    tgid:   Tid,

    pub flags: AtomicUsize,

    pub real_parent:   Option<Arc<SchedInfo>>,
    pub group_leader:  Option<Arc<SchedInfo>>,

    pub children: SpinNoIrq<Vec<Tid>>,
    pub siblings: SpinNoIrq<Vec<Tid>>,

    pub set_child_tid: usize,
    pub clear_child_tid: usize,

    pub pgd: Option<Arc<SpinNoIrq<PageTable>>>,
    pub mm_id: AtomicUsize,
    pub active_mm_id: AtomicUsize,

    pub entry: Option<*mut dyn FnOnce()>,
    pub kstack: Option<TaskStack>,
    state: AtomicU8,
    in_wait_queue: AtomicBool,
    in_timer_list: AtomicBool,

    need_resched: AtomicBool,
    preempt_disable_count: AtomicUsize,

    /* CPU-specific state of this task: */
    pub thread: UnsafeCell<ThreadStruct>,
}

unsafe impl Send for SchedInfo {}
unsafe impl Sync for SchedInfo {}

impl SchedInfo {
    pub fn new() -> Self {
        Self {
            tid: 0,
            tgid: 0,

            flags: AtomicUsize::new(0),
            real_parent: None,
            group_leader: None,

            children: SpinNoIrq::new(Vec::new()),
            siblings: SpinNoIrq::new(Vec::new()),

            set_child_tid: 0,
            clear_child_tid: 0,

            pgd: None,
            mm_id: AtomicUsize::new(0),
            active_mm_id: AtomicUsize::new(0),

            entry: None,
            kstack: Some(TaskStack::alloc(align_up_4k(THREAD_SIZE))),
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            in_timer_list: AtomicBool::new(false),
            need_resched: AtomicBool::new(false),
            preempt_disable_count: AtomicUsize::new(0),

            thread: UnsafeCell::new(ThreadStruct::new()),
        }
    }

    pub fn init_tid(&mut self, tid: Tid) {
        self.tid = tid;
    }

    pub fn init_tgid(&mut self, tgid: Tid) {
        self.tgid = tgid;
    }

    pub fn tid(&self) -> Tid {
        self.tid
    }

    pub fn tgid(&self) -> usize {
        self.tgid
    }

    #[inline]
    pub fn set_tsk_thread_flag(&self, flag: usize) {
        self.flags.fetch_or(1<<flag, Ordering::Relaxed);
    }

    #[inline]
    pub fn clear_tsk_thread_flag(&self, flag: usize) {
        self.flags.fetch_and(!(1<<flag), Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn state(&self) -> TaskState {
        self.state.load(Ordering::Acquire).into()
    }

    #[inline]
    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u8, Ordering::Release)
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        matches!(self.state(), TaskState::Running)
    }

    #[inline]
    pub fn is_ready(&self) -> bool {
        matches!(self.state(), TaskState::Ready)
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self.state(), TaskState::Blocked)
    }

    #[inline]
    pub fn in_wait_queue(&self) -> bool {
        self.in_wait_queue.load(Ordering::Acquire)
    }

    #[inline]
    pub fn in_timer_list(&self) -> bool {
        self.in_timer_list.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_in_wait_queue(&self, in_wait_queue: bool) {
        self.in_wait_queue.store(in_wait_queue, Ordering::Release);
    }

    #[inline]
    pub fn set_in_timer_list(&self, in_timer_list: bool) {
        self.in_timer_list.store(in_timer_list, Ordering::Release);
    }

    pub fn try_pgd(&self) -> Option<Arc<SpinNoIrq<PageTable>>> {
        self.pgd.as_ref().and_then(|pgd| Some(pgd.clone()))
    }

    /*
    pub fn dup_sched_info(
        &self, tid: Tid, set_child_tid: usize, clear_child_tid: usize,
    ) -> Arc<Self> {
        info!("dup_sched_info...");
        let mut info = SchedInfo::new();
        info.tid = tid;
        info.tgid = tid;
        info.set_child_tid = set_child_tid;
        info.clear_child_tid = clear_child_tid;
        //assert!(self.kstack.is_some());
        info.kstack = Some(TaskStack::alloc(align_up_4k(THREAD_SIZE)));
        //info.kstack = self.kstack;
        info.pgd = self.pgd.clone();
        info.mm_id = AtomicUsize::new(0);
        info.active_mm_id = AtomicUsize::new(0);
        Arc::new(info)
    }
    */

    pub fn set_mm(&mut self, mm_id: usize, pgd: Arc<SpinNoIrq<PageTable>>) {
        assert!(mm_id != 0);
        self.mm_id = AtomicUsize::new(mm_id);
        self.active_mm_id = AtomicUsize::new(mm_id);
        self.pgd = Some(pgd.clone());
    }

    pub fn pt_regs_addr(&self) -> usize {
        self.kstack.as_ref().unwrap().top() - align_down(TRAPFRAME_SIZE, STACK_ALIGN)
    }

    pub fn pt_regs(&self) -> &mut TrapFrame {
        unsafe { &mut (*(self.pt_regs_addr() as *mut TrapFrame)) }
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.thread.get()
    }

    #[inline]
    pub fn set_preempt_pending(&self, pending: bool) {
        self.need_resched.store(pending, Ordering::Release)
    }

    #[inline]
    pub fn get_preempt_pending(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    #[inline]
    pub fn can_preempt(&self, current_disable_count: usize) -> bool {
        self.preempt_disable_count.load(Ordering::Acquire) == current_disable_count
    }

    #[inline]
    pub fn disable_preempt(&self) {
        self.preempt_disable_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn enable_preempt(&self) -> bool {
        self.preempt_disable_count.fetch_sub(1, Ordering::Relaxed) == 1
    }
}

/// The reference type of a task.
pub type CtxRef = Arc<SchedInfo>;

/// A wrapper of [`TaskCtxRef`] as the current task contex.
pub struct CurrentCtx(ManuallyDrop<CtxRef>);

impl CurrentCtx {
    pub fn try_get() -> Option<Self> {
        let ptr: *const SchedInfo = axhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(CtxRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current sched info is uninitialized")
    }

    pub fn ptr_eq(&self, other: &CtxRef) -> bool {
        Arc::ptr_eq(&self, other)
    }

    /// Converts [`CurrentTask`] to [`TaskRef`].
    pub fn as_ctx_ref(&self) -> &CtxRef {
        &self.0
    }

    pub fn as_ctx_mut(&mut self) -> &mut SchedInfo {
        unsafe {
            Arc::get_mut_unchecked(&mut self.0)
        }
    }

    pub unsafe fn set_current(prev: Self, next: CtxRef) {
        info!("CurrentCtx::set_current {} -> {}... irqs {}",
            prev.tid(), next.tid(), irqs_enabled());
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next.clone());
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentCtx {
    type Target = CtxRef;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn current_ctx() -> CurrentCtx {
    CurrentCtx::get()
}

pub fn try_current_ctx() -> Option<CurrentCtx> {
    CurrentCtx::try_get()
}

pub fn switch_mm(prev_mm_id: usize, next_mm_id: usize, next_pgd: Arc<SpinNoIrq<PageTable>>) {
    if prev_mm_id == next_mm_id {
        return;
    }
    debug!("###### switch_mm prev {} next {}; paddr {:#X}",
        prev_mm_id, next_mm_id, next_pgd.lock().root_paddr());
    unsafe {
        write_page_table_root0(next_pgd.lock().root_paddr().into());
    }
}

/*
pub fn init_sched_info() -> Arc<SchedInfo> {
    Arc::new(SchedInfo::new())
}
*/

static INIT_THREAD: LazyInit<CtxRef> = LazyInit::new();

pub fn init(_cpu_id: usize, _dtb_pa: usize) {
    axconfig::init_once!();

    let ctx = Arc::new(SchedInfo::new());
    INIT_THREAD.init_by(ctx);

    let ptr = Arc::into_raw(INIT_THREAD.clone());
    unsafe {
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

pub fn init_thread() -> Arc<SchedInfo> {
    INIT_THREAD.clone()
}
