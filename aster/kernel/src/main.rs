#![no_std]
#![no_main]
#![feature(register_tool)]
#![register_tool(component_access_control)]

//extern crate #TARGET_NAME#;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    extern "Rust" {
        pub fn __ostd_panic_handler(info: &core::panic::PanicInfo) -> !;
    }
    unsafe { __ostd_panic_handler(info); }
}
/*

/// The entry point of the Rust code portion of Asterinas.
#[no_mangle]
pub extern "C" fn main(_hart_id: usize, device_tree_paddr: usize) -> ! {
    //let package = option_env!("CARGO_PKG_NAME").unwrap_or("Unknown");
    //early_println!("[{}]: ok!", package);
    ostd::abort()
}
*/

#[macro_use]
extern crate controlled;

#[ostd::main]
#[controlled]
pub fn main() {
    ostd::early_println!("[kernel] OSTD initialized. Preparing components.");
    todo!("Normally exit!");
    //component::init_all(component::parse_metadata!()).unwrap();
    //init();

    // Spawn all AP idle threads.
    //ostd::boot::smp::register_ap_entry(ap_init);

    // Spawn the first kernel thread on BSP.
    /*
    ThreadOptions::new(init_thread)
        .priority(Priority::idle())
        .spawn();
        */
}
