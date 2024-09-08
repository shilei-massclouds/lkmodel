#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use core::panic::PanicInfo;

/// Entry
#[no_mangle]
pub extern "Rust" fn runtime_main(cpu_id: usize, dtb_pa: usize) {
    assert_eq!(cpu_id, 0);

    axlog2::init("debug");
    info!("[rt_axmount]: ... cpuid {}", cpu_id);

    axhal::cpu::init_primary(cpu_id);

    info!("Initialize global memory allocator...");
    axalloc::init();

    info!("Initialize kernel page table...");
    page_table::init();

    fstree::init(cpu_id, dtb_pa);
    let fs = fstree::init_fs();
    let locked_fs = fs.lock();
    match axfile::api::create_dir("/testcases/abc", &locked_fs, 0, 0) {
        Ok(_) => info!("create /testcases/abc ok!"),
        Err(e) => error!("create /testcases/abc failed {}", e),
    }

    let fname = "/testcases/abc/new-file.txt";
    info!("test create file {:?}:", fname);
    //assert_err!(axfile::api::metadata(fname), NotFound);
    let contents = "create a new file!\n";
    axfile::api::write(fname, contents, &locked_fs, 0, 0).unwrap();

    let ret = axfile::api::read_to_string(fname, &locked_fs, 0, 0).unwrap();
    info!("read test file: \"{}\"", ret);
    assert_eq!(contents, ret);

    assert!(axfile::api::remove_file(fname, &locked_fs).is_ok());
    assert!(axfile::api::remove_dir("/testcases/abc", &locked_fs).is_ok());

    info!("[rt_axmount]: ok!");
    axhal::misc::terminate();
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}

extern "C" {
    fn _ekernel();
}
