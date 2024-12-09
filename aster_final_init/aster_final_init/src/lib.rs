// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![allow(dead_code)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![feature(negative_impls)]
#![feature(sync_unsafe_cell)]
#![feature(specialization)]

//! The architecture-independent boot module, which provides
//!  1. a universal information getter interface from the bootloader to the
//!     rest of OSTD;
//!  2. the routine booting into the actual kernel;
//!  3. the routine booting the other processors in the SMP context.

extern crate alloc;

pub mod boot;
pub mod cpu;
pub mod error;
pub mod logger;
pub mod mm;
pub mod prelude;
pub mod kcmdline;
pub mod sync;
pub mod task;
pub mod timer;
pub mod trap;
pub mod memory_region;
mod arch;

//pub mod smp;

use alloc::{string::String, vec::Vec};

use kcmdline::KCmdlineArg;
use spin::Once;

use self::memory_region::MemoryRegion;

/// The initialization method of the boot module.
///
/// After initializing the boot module, the get functions could be called.
/// The initialization must be done after the heap is set and before physical
/// mappings are cancelled.
pub fn init(hart_id: usize, device_tree_paddr: usize) {
    arch::arch_init(hart_id, device_tree_paddr);

    arch::enable_cpu_features();
    arch::serial::init();

    // SAFETY: This function is called only once and only on the BSP.
    unsafe { cpu::local::early_init_bsp_local_base() };

    // SAFETY: This function is called only once and only on the BSP.
    unsafe { mm::heap_allocator::init() };

    boot::init();
    logger::init();
}
