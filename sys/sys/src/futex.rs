//! futex

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use axerrno::{linux_err, LinuxError};
use mutex::Mutex;
use wait_queue::{WaitQueue, FUTEX_BITSET_MATCH_ANY};

type UTimeSpec = axtype::TimeSpec;
type KTimeSpec = axhal::time::TimeValue;

pub const FUTEX_WAIT: usize = 0;
pub const FUTEX_WAKE: usize = 1;
pub const FUTEX_LOCK_PI: usize = 6;
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

static FUTEX_MAP: Mutex<BTreeMap<usize, Arc<WaitQueue>>> = Mutex::new(BTreeMap::new());

pub fn do_futex(
    uaddr: usize, op: usize, val: usize, timeout_or_val2: usize,
    uaddr2: usize, mut val3: u32
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

    let mut timeout = None;
    if timeout_or_val2 != 0 && futex_cmd_has_timeout(cmd) {
        let utimeout = timeout_or_val2 as *const UTimeSpec;
        let utimeout = unsafe { *utimeout };
        info!("utimeout: {} : {}", utimeout.tv_sec, utimeout.tv_nsec);
        let mut ktimeout = KTimeSpec::new(
            utimeout.tv_sec as u64,
            utimeout.tv_nsec as u32
        );
        if cmd != FUTEX_WAIT {
            use axhal::time::current_time;
            if let Some(t) = ktimeout.checked_sub(current_time()) {
                ktimeout = t;
            } else {
                panic!("timeout is negative or overflow!");
            }
        }
        timeout = Some(ktimeout);
    }

    match cmd {
        FUTEX_WAIT => {
            val3 = FUTEX_BITSET_MATCH_ANY;
            return futex_wait(uaddr, flags, val, timeout, val3);
        },
        FUTEX_WAIT_BITSET => {
            return futex_wait(uaddr, flags, val, timeout, val3);
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

#[inline]
fn futex_cmd_has_timeout(cmd: usize) -> bool {
    match cmd {
        FUTEX_WAIT => true,
        FUTEX_LOCK_PI => true,
        FUTEX_LOCK_PI2 => true,
        FUTEX_WAIT_BITSET => true,
        FUTEX_WAIT_REQUEUE_PI => true,
        _ => false,
    }
}

fn futex_wait(
    uaddr: usize, _flags: usize, val: usize, timeout: Option<KTimeSpec>, bitset: u32
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

    if let Some(timeout) = timeout {
        if wq.wait_timeout(timeout, bitset) {
            return linux_err!(ETIMEDOUT);
        }
    } else {
        wq.wait(bitset);
    }
    debug!("futex_wait ok!");
    return 0;
}

fn futex_wake(
    uaddr: usize, flags: usize, nr_wake: usize, bitset: u32
) -> usize {
    error!("futex_wake: uaddr {:#x} flags {:#x} nr_wake {} bitset {:#x}",
        uaddr, flags, nr_wake, bitset);
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
        // TODO: noop as success!
        error!("futex_wake no wq uaddr {:#x}", uaddr);
        return 0;
    }
    return nr_wake;
}
