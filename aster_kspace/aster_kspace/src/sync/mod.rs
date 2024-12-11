// SPDX-License-Identifier: MPL-2.0

//! Useful synchronization primitives.

mod spin;
mod mutex;
mod wait;
// TODO: refactor this rcu implementation
// Comment out this module since it raises lint error
// mod rcu;
mod rwlock;
mod rwmutex;

// pub use self::rcu::{pass_quiescent_state, OwnerPtr, Rcu, RcuReadGuard, RcuReclaimer};
pub use self::{
    mutex::{ArcMutexGuard, Mutex, MutexGuard},
    rwmutex::{
        ArcRwMutexReadGuard, ArcRwMutexUpgradeableGuard, ArcRwMutexWriteGuard, RwMutex,
        RwMutexReadGuard, RwMutexUpgradeableGuard, RwMutexWriteGuard,
    },
    spin::{
        ArcSpinLockGuard, GuardTransfer, LocalIrqDisabled, PreemptDisabled, SpinLock, SpinLockGuard,
    },
    rwlock::{
        ArcRwLockReadGuard, ArcRwLockUpgradeableGuard, ArcRwLockWriteGuard, RwLock,
        RwLockReadGuard, RwLockUpgradeableGuard, RwLockWriteGuard,
    },
    wait::{WaitQueue, Waiter, Waker},
};
