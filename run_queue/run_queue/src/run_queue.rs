use alloc::sync::Arc;
use lazy_init::LazyInit;
use scheduler::BaseScheduler;
use taskctx::switch_mm;
use taskctx::TaskState;
use taskctx::SchedInfo;
/*
use alloc::collections::VecDeque;

use crate::{AxTaskRef, Scheduler, TaskInner, WaitQueue};
*/
use core::sync::atomic::Ordering;
use spinbase::SpinNoIrq;
use taskctx::{CtxRef, CurrentCtx};

type SchedItem = scheduler::CFSTask<CtxRef>;
type Scheduler = scheduler::CFScheduler<CtxRef>;

// TODO: per-CPU
pub(crate) static RUN_QUEUE: LazyInit<SpinNoIrq<AxRunQueue>> = LazyInit::new();

/*
// TODO: per-CPU
static EXITED_TASKS: SpinNoIrq<VecDeque<AxTaskRef>> = SpinNoIrq::new(VecDeque::new());

static WAIT_FOR_EXIT: WaitQueue = WaitQueue::new();

#[percpu::def_percpu]
static IDLE_TASK: LazyInit<AxTaskRef> = LazyInit::new();
*/

pub struct AxRunQueue {
    scheduler: Scheduler,
    idle: Arc<SchedItem>,
}

impl AxRunQueue {
    pub fn new(idle: Arc<SchedInfo>) -> SpinNoIrq<Self> {
        let idle = Arc::new(SchedItem::new(idle));
        let scheduler = Scheduler::new();
        SpinNoIrq::new(Self { scheduler, idle })
    }

    pub fn activate_task(&mut self, task: CtxRef) {
        self.add_task(task)
    }

    pub fn add_task(&mut self, task: CtxRef) {
        info!("task spawn: {}", task.tid());
        assert!(task.tid() != 0);
        assert!(task.is_ready());
        let item = Arc::new(SchedItem::new(task.clone()));
        self.scheduler.add_task(item);
    }

    pub fn scheduler_timer_tick(&mut self) {
        let curr = taskctx::current_ctx();
        if self.scheduler.task_tick(&Arc::new(SchedItem::new(curr.as_ctx_ref().clone()))) {
            curr.set_preempt_pending(true);
        }
    }

    /*
    pub fn set_current_priority(&mut self, prio: isize) -> bool {
        self.scheduler
            .set_priority(crate::current().as_task_ref(), prio)
    }
    */

    pub fn preempt_resched(&mut self) {
        let curr = taskctx::current_ctx();
        if curr.tid() == 0 {
            return;
        }
        assert!(curr.is_running());

        // When we get the mutable reference of the run queue, we must
        // have held the `SpinNoIrq` lock with both IRQs and preemption
        // disabled. So we need to set `current_disable_count` to 1 in
        // `can_preempt()` to obtain the preemption permission before
        //  locking the run queue.
        let can_preempt = curr.can_preempt(0);

        debug!(
            "current task is to be preempted: {}, allow={}",
            curr.tid(),
            can_preempt
        );
        if can_preempt {
            self.resched(true);
        } else {
            curr.set_preempt_pending(true);
        }
    }

    /*
    pub fn exit_current(&mut self, exit_code: i32) -> ! {
        let curr = crate::current();
        debug!("task exit: {}, exit_code={}", curr.id_name(), exit_code);
        assert!(curr.is_running());
        assert!(!curr.is_idle());
        if curr.is_init() {
            EXITED_TASKS.lock().clear();
            axhal::misc::terminate();
        } else {
            curr.set_state(TaskState::Exited);
            curr.notify_exit(exit_code, self);
            EXITED_TASKS.lock().push_back(curr.clone());
            WAIT_FOR_EXIT.notify_one_locked(false, self);
            self.resched(false);
        }
        unreachable!("task exited!");
    }
    */

    pub fn block_current<F>(&mut self, wait_queue_push: F)
    where
        F: FnOnce(CtxRef),
    {
        let curr = taskctx::current_ctx();
        assert!(curr.tid() != 0);
        info!("task block: {}", curr.tid());
        assert!(curr.is_running());
        //assert!(!curr.is_idle());

        // we must not block current task with preemption disabled.
        //assert!(curr.can_preempt(1));

        curr.set_state(TaskState::Blocked);
        wait_queue_push(curr.clone());
        self.resched(false);
    }

    pub fn unblock_task(&mut self, task: CtxRef, resched: bool) {
        info!("task unblock: {}", task.tid());
        assert!(task.tid() != 0);
        if task.is_blocked() {
            task.set_state(TaskState::Ready);
            self.scheduler.add_task(Arc::new(SchedItem::new(task))); // TODO: priority
            if resched {
                taskctx::current_ctx().set_preempt_pending(true);
            }
        }
    }

    /*
    #[cfg(feature = "irq")]
    pub fn sleep_until(&mut self, deadline: axhal::time::TimeValue) {
        let curr = crate::current();
        debug!("task sleep: {}, deadline={:?}", curr.id_name(), deadline);
        assert!(curr.is_running());
        assert!(!curr.is_idle());

        let now = axhal::time::current_time();
        if now < deadline {
            crate::timers::set_alarm_wakeup(deadline, curr.clone());
            curr.set_state(TaskState::Blocked);
            self.resched(false);
        }
    }
    */
}

impl AxRunQueue {
    /// Common reschedule subroutine. If `preempt`, keep current task's time
    /// slice, otherwise reset it.
    pub fn resched(&mut self, preempt: bool) {
        let prev = taskctx::current_ctx();
        if prev.is_running() {
            prev.set_state(TaskState::Ready);
            // Todo: imitate linux kernel to deal with idle task(tid == 0)
            if prev.tid() != 0 {
                self.scheduler
                    .put_prev_task(Arc::new(SchedItem::new(prev.clone())), preempt);
            }
        }
        let next = self.scheduler.pick_next_task().unwrap_or_else(|| {
            self.idle.clone()
        });
        self.switch_to(prev, next.inner().clone());
    }

    fn switch_to(&mut self, prev_task: CurrentCtx, next_task: CtxRef) {
        debug!("============ context switch: {} -> {} irqs {}",
            prev_task.tid(), next_task.tid(), axhal::arch::irqs_enabled());
        next_task.set_preempt_pending(false);
        next_task.set_state(TaskState::Running);
        if prev_task.ptr_eq(&next_task) {
            return;
        }

        // Switch mm from prev to next
        // kernel ->   user   switch + mmdrop_lazy_tlb() active
        //   user ->   user   switch
        // kernel -> kernel   lazy + transfer active
        //   user -> kernel   lazy + mmgrab_lazy_tlb() active
        match next_task.try_pgd() {
            Some(ref next_pgd) => {
                switch_mm(
                    prev_task.active_mm_id.load(Ordering::SeqCst),
                    next_task.mm_id.load(Ordering::SeqCst),
                    next_pgd.lock().root_paddr().into(),
                );
            }
            None => {
                info!(
                    "###### {} {};",
                    prev_task.active_mm_id.load(Ordering::SeqCst),
                    next_task.active_mm_id.load(Ordering::SeqCst)
                );

                next_task.active_mm_id.store(
                    prev_task.active_mm_id.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                );
            }
        }
        if prev_task.try_pgd().is_none() {
            prev_task.active_mm_id.store(0, Ordering::SeqCst);
        }

        unsafe {
            let prev_ctx_ptr = prev_task.ctx_mut_ptr();
            let next_ctx_ptr = next_task.ctx_mut_ptr();

            // The strong reference count of `prev_task` will be decremented by 1,
            // but won't be dropped until `gc_entry()` is called.
            assert!(Arc::strong_count(&prev_task) > 1);
            assert!(Arc::strong_count(&next_task) >= 1);

            CurrentCtx::set_current(prev_task, next_task);
            (*prev_ctx_ptr).switch_to(&*next_ctx_ptr);
        }
    }
}

/*

fn gc_entry() {
    loop {
        // Drop all exited tasks and recycle resources.
        let n = EXITED_TASKS.lock().len();
        for _ in 0..n {
            // Do not do the slow drops in the critical section.
            let task = EXITED_TASKS.lock().pop_front();
            if let Some(task) = task {
                if Arc::strong_count(&task) == 1 {
                    // If I'm the last holder of the task, drop it immediately.
                    drop(task);
                } else {
                    // Otherwise (e.g, `switch_to` is not compeleted, held by the
                    // joiner, etc), push it back and wait for them to drop first.
                    EXITED_TASKS.lock().push_back(task);
                }
            }
        }
        WAIT_FOR_EXIT.wait();
    }
}
*/

/*
pub(crate) fn init_secondary() {
    let idle_task = TaskInner::new_init("idle".into());
    idle_task.set_state(TaskState::Running);
    IDLE_TASK.with_current(|i| i.init_by(idle_task.clone()));
    unsafe { CurrentTask::init_current(idle_task) }
}
*/
