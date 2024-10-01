use alloc::collections::BTreeMap;
use spinpreempt::SpinLock;
use crate::TaskRef;
use crate::Tid;

static TID_MAP: SpinLock<BTreeMap<Tid, TaskRef>> = SpinLock::new(BTreeMap::new());

pub fn get_task(tid: Tid) -> Option<TaskRef> {
    TID_MAP.lock().get(&tid).cloned()
}

pub fn register_task(task: TaskRef) {
    let tid = task.tid();
    TID_MAP.lock().insert(tid, task);
}

pub fn unregister_task(tid: Tid) {
    TID_MAP.lock().remove(&tid);
}

pub fn get_tid_map() -> &'static SpinLock<BTreeMap<Tid, TaskRef>> {
    &TID_MAP
}
