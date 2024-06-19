#![feature(asm_const)]
#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

use axhal::mem::memory_regions; //phys_to_virt
use core::sync::atomic::{AtomicUsize, Ordering};
use mm::MmStruct;
use memory_addr::{PAGE_SIZE_4K, align_down_4k, align_up_4k};
use page_table::MappingFlags;
use std::{vec::Vec,string::String,thread};


use core::panic::PanicInfo;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}

// use axerrno::{LinuxError, LinuxResult};
// use axtype::DtbInfo;
// use fork::{user_mode_thread, CloneFlags};




const PAGE_SHIFT: usize = 12;
//const PLASH_START: usize = 0x22000000;
//axconfig/axconfig/platforms/riscv64-qemu-virt.toml
//["0x2200_0000", "0x200_0000"],    # PFLASH#2 开始位置和长度
//[PA:0x22000000, PA:0x24000000) mmio (READ | WRITE | DEVICE | RESERVED)
//map_region(PA:0x802a1000): [VA:0xffffffc022000000, VA:0xffffffc024000000) -> [PA:0x22000000, PA:0x24000000) MappingFlags(READ | WRITE | DEVICE)
const PFLASH_START: usize = 0xffff_ffc0_2200_0000;


// app running aspace
// SBI(0x80000000) -> App <- Kernel(0x80200000)
// 0xffff_ffc0_0000_0000
const RUN_START: usize = 0xffff_ffc0_8010_0000;
// 注意：这个 0x4010_0000 所在的 1G 空间在原始的内核地址空间中是不存在的。
// const RUN_START: usize = 0x4010_0000;



#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(cpu_id: usize, _dtb_pa: usize) {

    // 初始化日志
    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    // 对于 riscv 在 axhal/axhal/src/arch/riscv/mod.rs
    // gp->tp
    axhal::arch_init_early(cpu_id);
    // trap初始化
    axtrap::early_init();

    info!("Found physcial memory regions:");
    for r in memory_regions() {
        info!(
            "  [{:x?}, {:x?}) {} ({:?})",
            r.paddr,
            r.paddr + r.size,
            r.name,
            r.flags
        );
    }

    info!("1 Initialize global memory allocator...");
    //[PA:0x80298000, PA:0x88000000) free memory (READ | WRITE | FREE)
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

    info!("7 Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Relaxed);

    while !is_init_ok() {
        core::hint::spin_loop();
    }


    let apps_start = PFLASH_START ;
    
    load_app(apps_start);
    
/* 
    // app 在文件中的偏移
    let mut offset = 0;
    let mut app_id = 1;
    while let Some(app) = load_app1(apps_start+offset ) {
       println!("--------app--------------");
       let mut vm = MmStruct::new();
       //let (entry, end) = parse_elf(app,& mut  vm);
       // //2. 初始化页表
       // unsafe {
        //     init_app_page_table(app_id);
        // }
        // //3. 切换空间  switch aspace from kernel to app
        // unsafe {
        //     switch_app_aspace(app_id);
        // }
        // // 应用长度=2字节魔数 +2字节长度+ 内容长度
        offset += app.len()  + 4;
        // //4.加载应用  拷贝app 到地址空间
        // copy_app(app, RUN_START);
        // //5. lab5运行app
        // run_apps_with_abi_table_lab5(app_id);

        app_id += 1;
    }
*/    
    println!("Load payload ok!");
    // loop {
    //     println!("yield!");
    //     thread::yield_now();
    // }
    axhal::misc::terminate()
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
fn load_app1(start: usize) -> Option<&'static [u8]> {
    let start= start as *const u8;
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
   
    Some(code)
}

fn parse_literal_hex(pos: usize) -> usize {
    let hex = unsafe { core::slice::from_raw_parts(pos as *const u8, 8) };
    let hex = String::from_utf8(hex.into()).expect("bad hex number.");
    usize::from_str_radix(&hex, 16).expect("NOT hex number.")
}

fn load_app(start: usize)  {
    let mut pos = start;
    let app_num = parse_literal_hex(pos);
    assert_eq!(app_num, 2);
    pos += 8;

    for _ in 0..app_num {
        let size = parse_literal_hex(pos);
        println!("app size: {}", size);
        pos += 8;

        let code = unsafe {
            core::slice::from_raw_parts(pos as *const u8, size)
        };
        pos += size;
        println!("app pos: {:#X}", pos);


        // thread::spawn(move || {
        //     println!("\n=====thread::spawn=========");
        //     // let mut vm = MmStruct::new();
        //     // let (entry, end) = parse_elf(code,& mut  vm);
        //     // println!("App: entry: {:#X}", entry);

        //     // run_app(entry, end,& mut vm);
        //     axhal::misc::terminate()
        //     // thread::yield_now()
        // });


       
    }
}


/// 拷贝app 到目的地址
fn copy_app(app_bytes: &[u8], to_addr: usize) {
    let run_code = unsafe { core::slice::from_raw_parts_mut(to_addr as *mut u8, app_bytes.len()) };
    run_code.copy_from_slice(app_bytes);
   
}

fn run_apps_with_abi_table_lab5(index: u16) -> () {
    println!("Execute app {} ...", index);
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




static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);
fn is_init_ok() -> bool {
    INITED_CPUS.load(Ordering::Acquire) == axconfig::SMP
}





fn elfflags_to_mapflags(flags: usize) -> usize {
    const PF_X: usize = 1 << 0; // Segment is executable
    const PF_W: usize =	1 << 1; // Segment is writable
    const PF_R: usize = 1 << 2; // Segment is readable

    let mut mapflags = MappingFlags::empty();
    if flags & PF_X == PF_X {
        mapflags |= MappingFlags::EXECUTE;
    }
    if flags & PF_W == PF_W {
        mapflags |= MappingFlags::WRITE;
    }
    if flags & PF_R == PF_R {
        mapflags |= MappingFlags::READ;
    }
    mapflags.bits()
}

fn parse_elf(code: &[u8],vm:& MmStruct) -> (usize, usize) {
    use elf::abi::PT_LOAD;
    use elf::endian::AnyEndian;
    use elf::ElfBytes;
    use elf::segment::ProgramHeader;

    let file = ElfBytes::<AnyEndian>::minimal_parse(code).unwrap();
    println!("e_entry: {:#X}", file.ehdr.e_entry);

    let phdrs: Vec<ProgramHeader> = file.segments().unwrap()
        .iter()
        .filter(|phdr|{phdr.p_type == PT_LOAD})
        .collect();

    let mut end = 0;

    println!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in phdrs {
        println!("phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}, flags {:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags);

        let fdata = file.segment_data(&phdr).unwrap();
        println!("fdata: {:#x}", fdata.len());

        let va_end = align_up_4k((phdr.p_vaddr + phdr.p_memsz) as usize);
        let va = align_down_4k(phdr.p_vaddr as usize);
        let num_pages = (va_end - va) >> PAGE_SHIFT;
        // let pa = vm::alloc_pages(num_pages, PAGE_SIZE_4K);
        let pa: usize = axalloc::global_allocator().alloc_pages(num_pages, PAGE_SIZE_4K) .unwrap();
        println!("va: {:#x} pa: {:#x} num {}", va, pa, num_pages);

        let flags = elfflags_to_mapflags(phdr.p_flags as usize);
        println!("flags: {:#X} => {:#X}", phdr.p_flags, flags);
        // Whatever we need vm::WRITE for initialize segment.
        // Fix it in future.
        // vm.map_region(va, pa, num_pages << PAGE_SHIFT, flags|vm::WRITE);
        vm.map_region(va, pa, num_pages << PAGE_SHIFT, 0);

        let mdata = unsafe {
            core::slice::from_raw_parts_mut(phdr.p_vaddr as *mut u8, phdr.p_filesz as usize)
        };
        mdata.copy_from_slice(fdata);
        println!("mdata: {:#x}", mdata.len());

        if phdr.p_memsz != phdr.p_filesz {
            let edata = unsafe {
                core::slice::from_raw_parts_mut((phdr.p_vaddr+phdr.p_filesz) as *mut u8, (phdr.p_memsz - phdr.p_filesz) as usize)
            };
            edata.fill(0);
            println!("edata: {:#x}", edata.len());
        }

        if end < va_end {
            end = va_end;
        }
    }

    (file.ehdr.e_entry as usize, end)
}

fn run_app(entry: usize, end: usize,vm:& mut MmStruct) {
    const TASK_SIZE: usize = 0x40_0000_0000;
    // let pa = vm::alloc_pages(1, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator().alloc_pages(1, PAGE_SIZE_4K) .unwrap();
    let va = TASK_SIZE - PAGE_SIZE_4K;
    println!("va: {:#x} pa: {:#x}", va, pa);
    

  
    let _flag=MappingFlags::READ | MappingFlags::WRITE;
    
    vm.map_region(va, pa, PAGE_SIZE_4K, 0);
    let sp = TASK_SIZE - 32;
    let stack = unsafe {
        core::slice::from_raw_parts_mut(
            sp as *mut usize, 4
        )
    };
    stack[0] = 0;
    stack[1] = TASK_SIZE - 16;
    stack[2] = 0;
    stack[3] = 0;

    println!("set brk...");
    vm.set_brk(end);

    // let pa = vm::alloc_pages(4, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator().alloc_pages(1, PAGE_SIZE_4K) .unwrap();
    vm.map_region(end, pa, 4*PAGE_SIZE_4K, 0);
    println!("### app end: {:#X}; {:#X}", end, vm.brk());

    setup_zero_page( vm);

    println!("Start app ...\n");
    // execute app
    unsafe { core::arch::asm!("
        jalr    t2
        j       .",
        in("t0") entry,
        in("t1") sp,
        in("t2") start_app,
    )};

    extern "C" {
        fn start_app();
    }
}

fn setup_zero_page(vm:& MmStruct) {
    // let pa = vm::alloc_pages(1, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator().alloc_pages(1, PAGE_SIZE_4K) .unwrap();
    let _flag=MappingFlags::READ ;
    vm.map_region(0x0, pa, PAGE_SIZE_4K, 0);
}


