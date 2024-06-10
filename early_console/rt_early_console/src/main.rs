#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    axtrap::early_init();
    axtrap::final_init();

    let stvec_value: u64;
    
    unsafe {
        asm!(
            "csrr {0}, stvec",  // 读取stvec寄存器的值
            out(reg) stvec_value,
        );
    }
    
    axlog2::ax_println!("stvec register value: {:#x}", stvec_value);
    let msg = "\n[early_console]: Hello, ArceOS!\n";
    early_console::write_bytes(msg.as_bytes());
    panic!("Reach here!");
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}
