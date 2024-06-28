#![no_std]
#![no_main]
#![feature(asm_const)]
use core::panic::PanicInfo;
use axlog2::info;
const PLASH_START: usize = 0x22000000;


use axstd::println;
#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    axlog2::init("debug");
    axhal::arch_init_early(_cpu_id);

    info!("Initialize global memory allocator...");
    axalloc::init();

    info!("Initialize kernel page table...");
    page_table::init();

    info!("Initialize schedule system ...");
    task::init();
    axtrap::early_init();
    axtrap::final_init();
    let apps_start = PLASH_START as *const u8;
    let apps_size = 32; // Dangerous!!! We need to get accurate size of apps.

    println!("Execute lab4 ...");
    const RUN_START: usize = 0x44000000;
    let code = unsafe { core::slice::from_raw_parts(apps_start , 73552) };
    let run_code = unsafe {
        core::slice::from_raw_parts_mut(RUN_START as *mut u8, 73552)
    };
    run_code.copy_from_slice(code);

    let address: *const u32 = 0x44004046 as *const u32;

    // 使用不安全代码块读取该地址处的值
    let instruction: u32 = unsafe { *address };

    // 输出该值
    println!("Instruction at 0x44004046: 0x{:08X}", instruction);


    unsafe { core::arch::asm!("
        addi sp, sp, -16*8
        sd ra, 120(sp)
        sd t0, 112(sp)
        sd t1, 104(sp)
        sd t2, 96(sp)
        sd t3, 88(sp)
        sd t4, 80(sp)
        sd t5, 72(sp)
        sd t6, 64(sp)
        sd a0, 56(sp)
        sd a1, 48(sp)
        sd a2, 40(sp)
        sd a3, 32(sp)
        sd a4, 24(sp)
        sd a5, 16(sp)
        sd a6, 8(sp)
        sd a7, 0(sp)

        li x0 , 0
        li x1 , 0
        li x2 , 0
        li x3 , 0
        li x4 , 0
        li x5 , 0
        li x6 , 0
        li x7 , 0
        li x8 , 0
        li x9 , 0
        li x11 , 0
        li x12 , 0
        li x13 , 0
        li x14 , 0
        li x15 , 0
        li x16 , 0
        li x17 , 0
        li x18 , 0
        li x19 , 0
        li x20 , 0
        li x21 , 0
        li x22 , 0
        li x23 , 0
        li x24 , 0
        li x25 , 0
        li x26 , 0
        li x27 , 0
        li x28 , 0
        li x29 , 0
        li x30 , 0
        li x31 , 0

        li sp , 0x44009000 + 0x1000*15
        li      t2, {run_start}
        jalr    ra , t2 , 0

        ld ra, 120(sp)
        ld t0, 112(sp)
        ld t1, 104(sp)
        ld t2, 96(sp)
        ld t3, 88(sp)
        ld t4, 80(sp)
        ld t5, 72(sp)
        ld t6, 64(sp)
        ld a0, 56(sp)
        ld a1, 48(sp)
        ld a2, 40(sp)
        ld a3, 32(sp)
        ld a4, 24(sp)
        ld a5, 16(sp)
        ld a6, 8(sp)
        ld a7, 0(sp)
        addi sp, sp, 16*8",
        run_start = const RUN_START,
    )}

}

#[inline]
fn bytes_to_usize(bytes: &[u8]) -> usize {
    usize::from_be_bytes(bytes.try_into().unwrap())
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}
