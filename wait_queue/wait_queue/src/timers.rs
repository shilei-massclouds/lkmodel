use alloc::sync::Arc;
use spinbase::SpinNoIrq;
use lazy_init::LazyInit;
use taskctx::CtxRef;
use timer_list::{TimeValue, TimerEvent, TimerList};
use axhal::time::current_time;

// TODO: per-CPU
static TIMER_LIST: LazyInit<SpinNoIrq<TimerList<TaskWakeupEvent>>> = LazyInit::new();

struct TaskWakeupEvent(CtxRef);

impl TimerEvent for TaskWakeupEvent {
    fn callback(self, _now: TimeValue) {
        let curr = taskctx::current_ctx();
        let mut rq = run_queue::task_rq(&curr).lock();
        self.0.set_in_timer_list(false);
        rq.unblock_task(self.0, true);
    }
}

pub fn set_alarm_wakeup(deadline: TimeValue, task: CtxRef) {
    let mut timers = TIMER_LIST.lock();
    task.set_in_timer_list(true);
    timers.set(deadline, TaskWakeupEvent(task));
}

pub fn cancel_alarm(task: &CtxRef) {
    let mut timers = TIMER_LIST.lock();
    task.set_in_timer_list(false);
    timers.cancel(|t| Arc::ptr_eq(&t.0, task));
}

pub fn check_events() {
    loop {
        let now = current_time();
        let event = TIMER_LIST.lock().expire_one(now);
        if let Some((_deadline, event)) = event {
            event.callback(now);
        } else {
            break;
        }
    }
}

pub fn init() {
    TIMER_LIST.init_by(SpinNoIrq::new(TimerList::new()));
}
