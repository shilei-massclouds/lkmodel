#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::collections::VecDeque;
use spinbase::SpinRaw;

use taskctx::CtxRef;
use taskctx::CurrentCtx;
use run_queue::AxRunQueue;

mod timers;

pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffffffff;

struct WaitItem {
    task: CtxRef,
    bitset: u32,
}

impl WaitItem {
    fn new(task: CtxRef, bitset: u32) -> Self {
        Self { task, bitset }
    }
}

/// A queue to store sleeping tasks.
///
/// # Examples
///
/// ```
/// use axtask::WaitQueue;
/// use core::sync::atomic::{AtomicU32, Ordering};
///
/// static VALUE: AtomicU32 = AtomicU32::new(0);
/// static WQ: WaitQueue = WaitQueue::new();
///
/// axtask::init_scheduler();
/// // spawn a new task that updates `VALUE` and notifies the main task
/// axtask::spawn(|| {
///     assert_eq!(VALUE.load(Ordering::Relaxed), 0);
///     VALUE.fetch_add(1, Ordering::Relaxed);
///     WQ.notify_one(true); // wake up the main task
/// });
///
/// WQ.wait(); // block until `notify()` is called
/// assert_eq!(VALUE.load(Ordering::Relaxed), 1);
/// ```
pub struct WaitQueue {
    queue: SpinRaw<VecDeque<WaitItem>>, // we already disabled IRQs when lock the `RUN_QUEUE`
}

impl WaitQueue {
    /// Creates an empty wait queue.
    pub const fn new() -> Self {
        Self {
            queue: SpinRaw::new(VecDeque::new()),
        }
    }

    /// Creates an empty wait queue with space for at least `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            queue: SpinRaw::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn count(&self) -> usize {
        self.queue.lock().len()
    }

    fn cancel_events(&self, curr: CurrentCtx) {
        info!("cancel_events ...");
        // A task can be wake up only one events (timer or `notify()`), remove
        // the event from another queue.
        if curr.in_wait_queue() {
            // wake up by timer (timeout).
            // `RUN_QUEUE` is not locked here, so disable IRQs.
            let _guard = kernel_guard_base::IrqSave::new();
            self.queue.lock().retain(|item| !curr.ptr_eq(&item.task));
            curr.set_in_wait_queue(false);
        }
        if curr.in_timer_list() {
            // timeout was set but not triggered (wake up by `WaitQueue::notify()`)
            crate::timers::cancel_alarm(curr.as_ctx_ref());
        }
    }

    /// Blocks the current task and put it into the wait queue, until other task
    /// notifies it.
    pub fn wait(&self, bitset: u32) {
        let curr = taskctx::current_ctx();
        let mut rq = run_queue::task_rq(&curr).lock();
        rq.block_current(|task| {
            task.set_in_wait_queue(true);
            let item = WaitItem::new(task, bitset);
            self.queue.lock().push_back(item)
        });
        self.cancel_events(taskctx::current_ctx());
    }

    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the condition becomes true.
    pub fn wait_until<F>(&self, condition: F, bitset: u32)
    where
        F: Fn() -> bool,
    {
        loop {
            let curr = taskctx::current_ctx();
            let mut rq = run_queue::task_rq(&curr).lock();
            if condition() {
                break;
            }
            rq.block_current(|task| {
                task.set_in_wait_queue(true);
                let item = WaitItem::new(task, bitset);
                self.queue.lock().push_back(item);
            });
        }
        self.cancel_events(taskctx::current_ctx());
    }

    /// Blocks the current task and put it into the wait queue, until other tasks
    /// notify it, or the given duration has elapsed.
    pub fn wait_timeout(&self, dur: core::time::Duration, bitset: u32) -> bool {
        let curr = taskctx::current_ctx();
        let deadline = axhal::time::current_time() + dur;
        info!(
            "task wait_timeout: {} deadline={:?}",
            curr.tid(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        run_queue::task_rq(&curr).lock().block_current(|task| {
            task.set_in_wait_queue(true);
            let item = WaitItem::new(task, bitset);
            self.queue.lock().push_back(item)
        });
        let timeout = curr.in_wait_queue(); // still in the wait queue, must have timed out
        self.cancel_events(curr);
        timeout
    }

    /*
    /// Blocks the current task and put it into the wait queue, until the given
    /// `condition` becomes true, or the given duration has elapsed.
    ///
    /// Note that even other tasks notify this task, it will not wake up until
    /// the above conditions are met.
    pub fn wait_timeout_until<F>(&self, dur: core::time::Duration, condition: F) -> bool
    where
        F: Fn() -> bool,
    {
        let curr = crate::current();
        let deadline = axhal::time::current_time() + dur;
        debug!(
            "task wait_timeout: {}, deadline={:?}",
            curr.id_name(),
            deadline
        );
        crate::timers::set_alarm_wakeup(deadline, curr.clone());

        let mut timeout = true;
        while axhal::time::current_time() < deadline {
            let mut rq = RUN_QUEUE.lock();
            if condition() {
                timeout = false;
                break;
            }
            rq.block_current(|task| {
                task.set_in_wait_queue(true);
                self.queue.lock().push_back(task);
            });
        }
        self.cancel_events(curr);
        timeout
    }
    */

    /// Wakes up one task in the wait queue, usually the first one.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_one(&self, resched: bool) -> bool {
        debug!("notify_one ...");
        let curr = taskctx::current_ctx();
        let mut rq = run_queue::task_rq(&curr).lock();
        if !self.queue.lock().is_empty() {
            self.notify_one_locked(resched, &mut rq)
        } else {
            false
        }
    }

    pub fn notify_bitset(&self, nr_wake: usize, bitset: u32, resched: bool) -> usize {
        let mut num = 0;
        let curr = taskctx::current_ctx();
        let mut rq = run_queue::task_rq(&curr).lock();
        self.queue.lock().retain(|item| {
            if num >= nr_wake {
                return true;
            }
            error!("notify_bitset ...");
            // Check if one of the bits is set in both bitsets
            let miss = (item.bitset & bitset) == 0;
            if !miss {
                item.task.set_in_wait_queue(false);
                rq.unblock_task(item.task.clone(), resched);
                num += 1;
            }
            miss
        });
        num
    }

    /*
    /// Wakes all tasks in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_all(&self, resched: bool) {
        loop {
            let mut rq = RUN_QUEUE.lock();
            if let Some(task) = self.queue.lock().pop_front() {
                task.set_in_wait_queue(false);
                rq.unblock_task(task, resched);
            } else {
                break;
            }
            drop(rq); // we must unlock `RUN_QUEUE` after unlocking `self.queue`.
        }
    }

    /// Wake up the given task in the wait queue.
    ///
    /// If `resched` is true, the current task will be preempted when the
    /// preemption is enabled.
    pub fn notify_task(&mut self, resched: bool, task: &AxTaskRef) -> bool {
        let mut rq = RUN_QUEUE.lock();
        let mut wq = self.queue.lock();
        if let Some(index) = wq.iter().position(|t| Arc::ptr_eq(t, task)) {
            task.set_in_wait_queue(false);
            rq.unblock_task(wq.remove(index).unwrap(), resched);
            true
        } else {
            false
        }
    }
    */

    pub(crate) fn notify_one_locked(&self, resched: bool, rq: &mut AxRunQueue) -> bool {
        if let Some(item) = self.queue.lock().pop_front() {
            item.task.set_in_wait_queue(false);
            rq.unblock_task(item.task, resched);
            true
        } else {
            false
        }
    }

    /*
    pub(crate) fn notify_all_locked(&self, resched: bool, rq: &mut AxRunQueue) {
        while let Some(task) = self.queue.lock().pop_front() {
            task.set_in_wait_queue(false);
            rq.unblock_task(task, resched);
        }
    }
    */
}

/// Handles periodic timer ticks for the task manager.
///
/// For example, advance scheduler states, checks timed events, etc.
pub fn on_timer_tick() {
    timers::check_events();
}

pub fn init(_cpu_id: usize, _dtb_pa: usize) {
    axconfig::init_once!();
    timers::init();
}
