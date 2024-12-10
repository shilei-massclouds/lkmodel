// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![allow(dead_code)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![feature(negative_impls)]
#![feature(sync_unsafe_cell)]
#![feature(specialization)]
#![feature(generic_const_exprs)]
#![feature(fn_traits)]
#![feature(let_chains)]
#![feature(btree_cursors)]
#![feature(stmt_expr_attributes)]
#![feature(core_intrinsics)]
#![feature(pointer_is_aligned)]
#![feature(ptr_sub_ptr)]
#![feature(const_ptr_sub_ptr)]
#![feature(linkage)]

//! The architecture-independent boot module, which provides
//!  1. a universal information getter interface from the bootloader to the
//!     rest of OSTD;
//!  2. the routine booting into the actual kernel;
//!  3. the routine booting the other processors in the SMP context.

extern crate alloc;

pub mod boot;
pub mod bus;
pub mod cpu;
pub mod error;
pub mod io_mem;
pub mod logger;
pub mod mm;
pub mod prelude;
pub mod kcmdline;
pub mod sync;
pub mod task;
pub mod timer;
pub mod trap;
pub mod arch;
pub mod user;
pub mod panic;

//pub mod smp;

use core::sync::atomic::AtomicBool;
use alloc::{string::String, vec::Vec};
pub use self::{error::Error, prelude::Result};
pub use ostd_pod::Pod;
pub use ostd_macros::{main, panic_handler};

use kcmdline::KCmdlineArg;
use spin::Once;

use boot::memory_region::MemoryRegion;

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

    let s = String::from("Hello, String!");
    aster_boot::early_println!("String: {}", s);

    let bootloader_name = boot::bootloader_name();
    aster_boot::early_println!("bootloader: {}", bootloader_name);
    let memory_regions = boot::memory_regions();
    aster_boot::early_println!("memory_regions: {:?}", memory_regions);

    log::info!("test logging!");

    mm::page::allocator::init();
    mm::kspace::init_kernel_page_table(mm::init_page_meta());
    mm::dma::init();

    arch::init_on_bsp();

    //smp::init();

    // SAFETY: This function is called only once on the BSP.
    unsafe {
        mm::kspace::activate_kernel_page_table();
    }

    bus::init();

    arch::irq::enable_local();

    invoke_ffi_init_funcs();
}

/// Indicates whether the kernel is in bootstrap context.
pub static IN_BOOTSTRAP_CONTEXT: AtomicBool = AtomicBool::new(true);

/// Invoke the initialization functions defined in the FFI.
/// The component system uses this function to call the initialization functions of
/// the components.
fn invoke_ffi_init_funcs() {
    extern "C" {
        fn __sinit_array();
        fn __einit_array();
    }
    let call_len = (__einit_array as usize - __sinit_array as usize) / 8;
    for i in 0..call_len {
        unsafe {
            let function = (__sinit_array as usize + 8 * i) as *const fn();
            (*function)();
        }
    }
}
