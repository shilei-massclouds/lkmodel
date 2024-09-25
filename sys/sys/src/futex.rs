//! futex

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use axerrno::{linux_err, LinuxError};
use mutex::Mutex;
use wait_queue::WaitQueue;
use axtype::TimeSpec;
use axhal::time::TimeValue;

pub const FUTEX_WAIT: usize = 0;
pub const FUTEX_WAKE: usize = 1;
pub const FUTEX_WAIT_BITSET: usize = 9;
pub const FUTEX_WAKE_BITSET: usize = 10;
pub const FUTEX_WAIT_REQUEUE_PI: usize = 11;
pub const FUTEX_LOCK_PI2: usize = 13;

const FUTEX_PRIVATE_FLAG:   usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;
const FUTEX_CMD_MASK: usize = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

const FLAGS_SHARED:     usize = 0x01;
const FLAGS_CLOCKRT:    usize = 0x02;
//const FLAGS_HAS_TIMEOUT:usize = 0x04;

//
// bitset with all bits set for the FUTEX_xxx_BITSET OPs to request a
// match of any bit.
//
const FUTEX_BITSET_MATCH_ANY: usize = 0xffffffff;

static FUTEX_MAP: Mutex<BTreeMap<usize, Arc<WaitQueue>>> = Mutex::new(BTreeMap::new());

pub fn do_futex(
    uaddr: usize, op: usize, val: usize, timeout_or_val2: usize,
    uaddr2: usize, mut val3: usize
) -> usize {
    assert_eq!(uaddr2, 0);

    let cmd = op & FUTEX_CMD_MASK;
    let mut flags = 0;

    if (op & FUTEX_PRIVATE_FLAG) == 0 {
        flags |= FLAGS_SHARED;
    }

    if (op & FUTEX_CLOCK_REALTIME) != 0 {
        flags |= FLAGS_CLOCKRT;
        if cmd != FUTEX_WAIT_BITSET &&
            cmd != FUTEX_WAIT_REQUEUE_PI &&
            cmd != FUTEX_LOCK_PI2 {
            return linux_err!(ENOSYS);
        }
    }

    match cmd {
        FUTEX_WAIT => {
            val3 = FUTEX_BITSET_MATCH_ANY;
            return futex_wait(uaddr, flags, val, timeout_or_val2, val3);
        },
        FUTEX_WAIT_BITSET => {
            return futex_wait(uaddr, flags, val, timeout_or_val2, val3);
        },
        FUTEX_WAKE => {
            val3 = FUTEX_BITSET_MATCH_ANY;
            return futex_wake(uaddr, flags, val, val3);
        },
        FUTEX_WAKE_BITSET => {
            return futex_wake(uaddr, flags, val, val3);
        },
        _ => {
            error!("cmd: {:#x}", cmd);
        },
    }

    panic!("uaddr: {:#x} op: {:#x} val {:#x} timeout_or_val2 {:#x} uaddr2 {:#x} val3 {:#x}",
        uaddr, op, val, timeout_or_val2, uaddr2, val3);
}

fn futex_wait(
    uaddr: usize, _flags: usize, val: usize, abs_time: usize, bitset: usize
) -> usize {
    info!("futex_wait ...");
    assert_eq!(bitset, FUTEX_BITSET_MATCH_ANY);
    if bitset == 0 {
        return linux_err!(EINVAL);
    }

    // Todo: use atomic operations. We might need asm code.
    let ptr = uaddr as *const u32;
    if unsafe { *ptr } != val as u32 {
        return linux_err!(EAGAIN);
    }

    let wq = {
        let mut futex_map = FUTEX_MAP.lock();
        if let Some(q) = futex_map.get(&uaddr) {
            q.clone()
        } else {
            futex_map.insert(uaddr, Arc::new(WaitQueue::new()));
            futex_map.get(&uaddr).unwrap().clone()
        }
    };

    if abs_time != 0 {
        let abs_time = abs_time as *const TimeSpec;
        let timeout = unsafe { *abs_time };
        info!("timeout: {} : {}", timeout.tv_sec, timeout.tv_nsec);
        let timeout = TimeValue::new(
            timeout.tv_sec as u64,
            timeout.tv_nsec as u32
        );
        wq.wait_timeout(timeout);
    } else {
        wq.wait();
    }
    debug!("futex_wait ok!");
    return 0;
}

fn futex_wake(
    uaddr: usize, _flags: usize, nr_wake: usize, bitset: usize
) -> usize {
    assert_eq!(nr_wake, 1);
    assert_eq!(bitset, FUTEX_BITSET_MATCH_ANY);
    if bitset == 0 {
        return linux_err!(EINVAL);
    }

    let mut futex_map = FUTEX_MAP.lock();
    if let Some(wq) = futex_map.get(&uaddr) {
        wq.notify_one(true);
        if wq.count() == 0 {
            futex_map.remove(&uaddr);
        }
    } else {
        error!("futex_wake no wq uaddr {:#x}", uaddr);
    }
    return nr_wake;
}
