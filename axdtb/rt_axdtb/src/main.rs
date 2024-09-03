#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, dtb_pa: usize) {
    axlog2::init("info");
    info!("[rt_axdtb]: ...");

    axalloc::init();

    test_dtb(dtb_pa);

    info!("[rt_axdtb]: ok!");
    axhal::misc::terminate();
}

#[cfg(target_arch = "riscv64")]
fn test_dtb(dtb_pa: usize) {
    let mut cb = |name: String,
                  _addr_cells: usize,
                  _size_cells: usize,
                  props: Vec<(String, Vec<u8>)>| {
        match name.as_str() {
            "chosen" => {
                for prop in props {
                    match prop.0.as_str() {
                        "bootargs" => {
                            if let Ok(cmd) = core::str::from_utf8(&prop.1) {
                                let cmd = cmd.trim_end_matches(char::from(0));
                                assert!(cmd.len() > 0);
                                assert!(cmd.starts_with("init="));
                                let cmd = cmd.strip_prefix("init=").unwrap();
                                assert_eq!(cmd, "/sbin/init");
                            }
                        }
                        _ => (),
                    }
                }
            },
            _ => (),
        }
    };

    axdtb::parse(dtb_pa, &mut cb);
}

#[cfg(not(target_arch = "riscv64"))]
fn test_dtb(_dtb_pa: usize) {
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}
