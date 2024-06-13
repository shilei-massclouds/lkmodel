#![feature(asm_const)]
#![no_std]
#![no_main]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

mod abi;
use abi::{register_all_abi, ABI_TABLE};

const PLASH_START: usize = 0x22000000;
// app running aspace
// SBI(0x80000000) -> App <- Kernel(0x80200000)
// 0xffff_ffc0_0000_0000
// const RUN_START: usize = 0xffff_ffc0_8010_0000;

// 注意：这个 0x4010_0000 所在的 1G 空间在原始的内核地址空间中是不存在的。
const RUN_START: usize = 0x4010_0000;

/*


外部的app 项目 在  apps/other/hello_app/src/main.rs

构建应用的脚本 在 payload/makebin.sh


*/

#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
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
    // 十六进制表示
    // println!("app_content:");
    // for &byte in code {
    //     print!("{:02X} ", byte);
    // }
    println!();
    // println!("load code {:?}; address [{:?}]", code, code.as_ptr());
    Some(code)
}

/// 拷贝app 到目的地址
fn copy_app(app_bytes: &[u8], to_addr: usize) {
    let run_code = unsafe { core::slice::from_raw_parts_mut(to_addr as *mut u8, app_bytes.len()) };
    run_code.copy_from_slice(app_bytes);
    // println!(
    //     "run  code {:?}; address [{:?}]",
    //     run_code,
    //     run_code.as_ptr()
    // );
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
            // 页表项参考 https://learningos.cn/rCore-Tutorial-Guide-2024S/chapter4/3sv39-implementation-1.html
            // 0xef =1  1  1  0  1  1  1  1
            //       D  A  G  U  X  W  R  V
            // 仅当 V(Valid) 位为 1 时，页表项才是合法的；
            // R/W/X 分别控制索引到这个页表项的对应虚拟页面是否允许读/写/取指；
            // U 控制索引到这个页表项的对应虚拟页面是否在 CPU 处于 U 特权级的情况下是否被允许访问；
            // G 我们不理会；
            // A(Accessed) 记录自从页表项上的这一位被清零之后，页表项的对应虚拟页面是否被访问过；
            // D(Dirty) 则记录自从页表项上的这一位被清零之后，页表项的对应虚拟页表是否被修改过。
            
            
            // 物理页帧PPN 在页表项目中偏移位10 ,所以得左移10位  <<10


            // 0x8000_0000..0xc000_0000, VRWX_GAD, 1G block 恒等隐射
            // 恒等映射保证虚拟空间与物理空间有一个相等范围的地址空间映射(0x80000000~0xC0000000)。切换前后地址范围不变，但地址空间已经从物理空间切换到虚拟空间
            // 虚拟地址除以1G => 0x8000_0000 >> 30   ，对应pgd_idx = 2
            APP1_PT_SV39[2] = (0x80000 << 10) | 0xef;


            // 0xffff_ffc0_8000_0000..0xffff_ffc0_c000_0000, VRWX_GAD, 1G block

            // 完成Paging切换后，建立从虚拟空间0xffff_ffc0_8000_0000 ~ 0xffff_ffc0_8000_0000到物理空间0x8000_0000~0xC000_0000 的映射，范围1G
            // 初始化根页表BOOT_PT_SV39，只有一级，即每个页表项直接映射到1G的地址空间。
            // 1G = 2^30 因此pgd_idx = (VA>>30)&(512-1) 
            // 0x8000_0000 >> 30          ，对应pgd_idx = 2
            // 0xffff_ffc0_8000_0000 >> 30，只保留低9位，对应pgd_idx = 0x102
            // 物理页帧号 = 物理地址 >> 12，故0x80000
            APP1_PT_SV39[0x102] = (0x80000 << 10) | 0xef;

            // ArceOS 目前没有对 pflash 所在的地址空间进行映射，增加映射
            // qemu 有两个 pflash，其中第一个被保留做扩展的 bios，我们只能用第二个，它的开始地址 0x22000000。
            // 下行是我们新增的映射，这样 ArceOS 就可以访问 pflash 所在的地址空间了
            // 恒等映射从 0 开始的 1G 空间
            // 0x0000_0000..0x4000_0000, VRWX_GAD, 1G block
            APP1_PT_SV39[0] = (0x00000 << 10) | 0xef;

            // For App aspace!
            // 0x4000_0000..0x8000_0000, VRWX_GAD, 1G block
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
