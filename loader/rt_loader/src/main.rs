#![feature(asm_const)]
#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;





use axerrno::{LinuxError, LinuxResult};
use axhal::mem::{memory_regions, phys_to_virt};
use axtype::DtbInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use fork::{user_mode_thread, CloneFlags};


mod abi;
use abi::{register_all_abi, ABI_TABLE};

const PLASH_START: usize = 0x22000000;
// app running aspace
// SBI(0x80000000) -> App <- Kernel(0x80200000)
// 0xffff_ffc0_0000_0000
// const RUN_START: usize = 0xffff_ffc0_8010_0000;

// 注意：这个 0x4010_0000 所在的 1G 空间在原始的内核地址空间中是不存在的。
const RUN_START: usize = 0x4010_0000;



#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(cpu_id: usize, _dtb_pa: usize) {


    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    // trap初始化
    axtrap::early_init();
    info!("1 Initialize global memory allocator...");
    axalloc::init();
    info!("2 Initialize kernel page table...");
    page_table::init();
    info!("3 Initialize platform devices...");
    axhal::platform_init();
    info!("4 Initialize schedule system ...");
    task::init();
    info!("5 Initialize schedule system ...");
    axtrap::final_init();
    info!("6 Initialize");





    let apps_start = PLASH_START as *const u8;

    //1. 注册所有abi
    register_all_abi();

    // app 在文件中的偏移
    let mut offset = 0;
    let mut app_id = 1;
    while let Some(app) = load_app(unsafe { apps_start.offset(offset) }) {
        //2. 初始化页表
        unsafe {
            init_app_page_table(app_id);
        }
        //3. 切换空间  switch aspace from kernel to app
        unsafe {
            switch_app_aspace(app_id);
        }

        // 应用长度=2字节魔数 +2字节长度+ 内容长度
        offset += app.len() as isize + 4;
        //4.加载应用  拷贝app 到地址空间
        copy_app(app, RUN_START);


        //5. lab5运行app
        run_apps_with_abi_table_lab5(app_id);

        app_id += 1;
    }
    println!("Load payload ok!");
}



fn bytes_to_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}

/// APP 生成格式参考 payload/makebin.sh
/// # 文件格式
/// # 字节序大端法
/// # 2字节魔数 ABCD
/// # 2字节长度
/// # 文件内容
fn load_app(start: *const u8) -> Option<&'static [u8]> {
    println!();
    println!("[=============LOAD_APP================]");
    //1. 读取魔数 0xABCD
    let magic_bin = unsafe { core::slice::from_raw_parts(start, 2) };
    let magic = bytes_to_u16(&magic_bin[..2]);
    println!("app_magic: {:#x}", magic);

    // 可以判断魔数是否正确
    if magic != 0xABCD {
        println!("no more apps find !!! ");
        return None;
    }
    //2. 读取app size
    let size_bin = unsafe { core::slice::from_raw_parts(start.offset(2), 2) };
    let size = bytes_to_u16(&size_bin[..2]) as usize;
    println!("app_size: {:#x}", size);
    //3. 读取app 内容
    let code = unsafe { core::slice::from_raw_parts(start.offset(4), size) };
   
    println!();
    Some(code)
}

/// 拷贝app 到目的地址
fn copy_app(app_bytes: &[u8], to_addr: usize) {
    let run_code = unsafe { core::slice::from_raw_parts_mut(to_addr as *mut u8, app_bytes.len()) };
    run_code.copy_from_slice(app_bytes);
   
}

fn run_apps_with_abi_table_lab5(_index: u16) -> () {
    // println!("Execute app {} ...", index);
    unsafe {
        core::arch::asm!("

        addi sp, sp, -16*8
        sd ra, 8*15 (sp)
        sd t0, 8*14 (sp)
        sd t1, 8*13 (sp)
        sd t2, 8*12 (sp)
        sd t3, 8*11 (sp)
        sd t4, 8*10 (sp)
        sd t5, 8*9  (sp)
        sd t6, 8*8  (sp)
        sd a0, 8*7  (sp)
        sd a1, 8*6  (sp)
        sd a2, 8*5  (sp)
        sd a3, 8*4  (sp)
        sd a4, 8*3  (sp)
        sd a5, 8*2  (sp)
        sd a6, 8*1  (sp)
        sd a7, 8*0  (sp)


        la      a7, {abi_table} # abi_table开始地址用a7传递
        li      t2, {run_start} # 加载ABI_TABLE 到t2
        jalr    t2              # 跳转到t2中值所指定的位置,返回地址保存在 x1(ra)
        

        ld ra, 8*15 (sp)
        ld t0, 8*14 (sp)
        ld t1, 8*13 (sp)
        ld t2, 8*12 (sp)
        ld t3, 8*11 (sp)
        ld t4, 8*10 (sp)
        ld t5, 8*9  (sp)
        ld t6, 8*8  (sp)
        ld a0, 8*7  (sp)
        ld a1, 8*6  (sp)
        ld a2, 8*5  (sp)
        ld a3, 8*4  (sp)
        ld a4, 8*3  (sp)
        ld a5, 8*2  (sp)
        ld a6, 8*1  (sp)
        ld a7, 8*0  (sp)
        addi sp, sp, 16*8

        ",
          run_start = const RUN_START,
          abi_table = sym ABI_TABLE,
        //   clobber_abi("C"),
        //   options(noreturn),
        );
    };
    ()
}

//
// App aspace
//
// 在 modules/axhal/linker.lds.S 中配置
// APP1的页表
#[link_section = ".data.app1_page_table"]
static mut APP1_PT_SV39: [u64; 512] = [0; 512];
// APP2的页表
#[link_section = ".data.ap2_page_table"]
static mut APP2_PT_SV39: [u64; 512] = [0; 512];

/// 初始化应用的页表
unsafe fn init_app_page_table(app_id: u16) {
    match app_id {
        1 => {
            APP1_PT_SV39[2] = (0x80000 << 10) | 0xef;
            APP1_PT_SV39[0x102] = (0x80000 << 10) | 0xef;
            APP1_PT_SV39[0] = (0x00000 << 10) | 0xef;
            APP1_PT_SV39[1] = (0x80000 << 10) | 0xef;
        }
        2 => {
            APP2_PT_SV39[2] = (0x80000 << 10) | 0xef;
            APP2_PT_SV39[0x102] = (0x80000 << 10) | 0xef;
            APP2_PT_SV39[0] = (0x00000 << 10) | 0xef;
            APP2_PT_SV39[1] = (0x80000 << 10) | 0xef;
        }
        _ => (),
    }
}

/// 切换应用空间
unsafe fn switch_app_aspace(app_id: u16) {
    use riscv::register::satp;

    let page_table_root = match app_id {
        1 => APP1_PT_SV39.as_ptr() as usize - axconfig::PHYS_VIRT_OFFSET,
        2 => APP2_PT_SV39.as_ptr() as usize - axconfig::PHYS_VIRT_OFFSET,
        _ => 0,
    };
    satp::set(satp::Mode::Sv39, 0, page_table_root >> 12);
    riscv::asm::sfence_vma_all();
}


use core::panic::PanicInfo;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}