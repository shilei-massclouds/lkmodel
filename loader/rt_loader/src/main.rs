#![feature(asm_const)]
#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

use axhal::mem::memory_regions; //phys_to_virt
use core::{
    ops::BitOr,
    sync::atomic::{AtomicUsize, Ordering},
};
use memory_addr::{align_down_4k, align_up_4k, PAGE_SIZE_4K};
use mm::MmStruct;
use page_table::MappingFlags;
use std::{string::String, thread, vec::Vec};

use core::panic::PanicInfo;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    arch_boot::panic(info)
}

use fork::{user_mode_thread, CloneFlags};

const PAGE_SHIFT: usize = 12;
const PFLASH_START: usize = 0xffff_ffc0_2200_0000;
const RUN_START: usize = 0xffff_ffc0_8010_0000;

#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(cpu_id: usize, _dtb_pa: usize) {
    // 初始化
    init();
    // 加载后运行
    load_and_run_app(PFLASH_START);

    println!("Load payload ok!");
    axhal::misc::terminate()
}

fn init() {
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
    info!("5 final_init ...");
    axtrap::final_init();

    info!("6 Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Relaxed);

    while !is_init_ok() {
        core::hint::spin_loop();
    }
}

fn bytes_to_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}

fn parse_literal_hex(pos: usize) -> usize {
    let hex = unsafe { core::slice::from_raw_parts(pos as *const u8, 8) };
    let hex = String::from_utf8(hex.into()).expect("bad hex number.");
    usize::from_str_radix(&hex, 16).expect("NOT hex number.")
}

fn load_and_run_app(start: usize) {
    let mut pos = start;
    let app_num = parse_literal_hex(pos);
    assert_eq!(app_num, 2);
    pos += 8;

    for _ in 0..app_num {
        let size = parse_literal_hex(pos);
        println!("app size: {}", size);
        pos += 8;

        let code = unsafe { core::slice::from_raw_parts(pos as *const u8, size) };
        pos += size;
        println!("app pos: {:#X}", pos);

        // thread::spawn(move || {
        //        // println!("\n=====thread::spawn=========");
        //        //let mut vm = MmStruct::new();
        //        //let (entry, end) = parse_elf(code,& mut  vm);
        //        //println!("App: entry: {:#X}", entry);

        //        // run_app(entry, end,& mut vm);
        //        // axhal::misc::terminate()
        //        // thread::yield_now()
        // });

        let mut vm = MmStruct::new();
        let (entry, end) = parse_elf(code, &mut vm);
        let tid = user_mode_thread(
            move || {
                // println!("\n=====user_mode_thread=========");
                run_app(entry, end, &mut vm);
            },
            CloneFlags::CLONE_FS,
        );
    }
}

static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);
fn is_init_ok() -> bool {
    INITED_CPUS.load(Ordering::Acquire) == axconfig::SMP
}

fn elfflags_to_mapflags(flags: usize) -> usize {
    const PF_X: usize = 1 << 0; // Segment is executable
    const PF_W: usize = 1 << 1; // Segment is writable
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

fn parse_elf(code: &[u8], vm: &MmStruct) -> (usize, usize) {
    use elf::abi::PT_LOAD;
    use elf::endian::AnyEndian;
    use elf::segment::ProgramHeader;
    use elf::ElfBytes;

    let file = ElfBytes::<AnyEndian>::minimal_parse(code).unwrap();
    println!("e_entry: {:#X}", file.ehdr.e_entry);

    let phdrs: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    let mut end = 0;

    println!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in phdrs {
        println!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}, flags {:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags
        );

        let fdata = file.segment_data(&phdr).unwrap();
        println!("fdata: {:#x}", fdata.len());

        let va_end = align_up_4k((phdr.p_vaddr + phdr.p_memsz) as usize);
        let va = align_down_4k(phdr.p_vaddr as usize);
        let num_pages = (va_end - va) >> PAGE_SHIFT;
        // let pa = vm::alloc_pages(num_pages, PAGE_SIZE_4K);
        let pa: usize = axalloc::global_allocator()
            .alloc_pages(num_pages, PAGE_SIZE_4K)
            .unwrap();
        println!("va: {:#x} pa: {:#x} num {}", va, pa, num_pages);

        let flags = elfflags_to_mapflags(phdr.p_flags as usize);
        println!("flags: {:#X} => {:#X}", phdr.p_flags, flags);
        // Whatever we need vm::WRITE for initialize segment.
        // Fix it in future.
        // vm.map_region(va, pa, num_pages << PAGE_SHIFT, flags|vm::WRITE);
        vm.map_region(
            va,
            pa,
            num_pages << PAGE_SHIFT,
            MappingFlags::from_bits(flags)
                .unwrap()
                .union(MappingFlags::WRITE)
                .bits(),
        );

        let mdata = unsafe {
            core::slice::from_raw_parts_mut(phdr.p_vaddr as *mut u8, phdr.p_filesz as usize)
        };
        mdata.copy_from_slice(fdata);
        println!("mdata: {:#x}", mdata.len());

        if phdr.p_memsz != phdr.p_filesz {
            let edata = unsafe {
                core::slice::from_raw_parts_mut(
                    (phdr.p_vaddr + phdr.p_filesz) as *mut u8,
                    (phdr.p_memsz - phdr.p_filesz) as usize,
                )
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

fn run_app(entry: usize, end: usize, vm: &mut MmStruct) {
    const TASK_SIZE: usize = 0x40_0000_0000;
    // let pa = vm::alloc_pages(1, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .unwrap();
    let va = TASK_SIZE - PAGE_SIZE_4K;
    println!("va: {:#x} pa: {:#x}", va, pa);

    let flag = MappingFlags::READ | MappingFlags::WRITE;

    vm.map_region(va, pa, PAGE_SIZE_4K, flag.bits());
    let sp = TASK_SIZE - 32;
    let stack = unsafe { core::slice::from_raw_parts_mut(sp as *mut usize, 4) };
    stack[0] = 0;
    stack[1] = TASK_SIZE - 16;
    stack[2] = 0;
    stack[3] = 0;

    println!("set brk...");
    vm.set_brk(end);

    // let pa = vm::alloc_pages(4, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .unwrap();
    vm.map_region(end, pa, 4 * PAGE_SIZE_4K, flag.bits());
    println!("### app end: {:#X}; {:#X}", end, vm.brk());

    setup_zero_page(vm);

    println!("Start app ...\n");
    // execute app
    unsafe {
        core::arch::asm!("
        jalr    t2
        j       .",
            in("t0") entry,
            in("t1") sp,
            in("t2") start_app,
        )
    };

    extern "C" {
        fn start_app();
    }
}

fn setup_zero_page(vm: &MmStruct) {
    // let pa = vm::alloc_pages(1, PAGE_SIZE_4K);
    let pa: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .unwrap();
    let flag = MappingFlags::READ;
    vm.map_region(0x0, pa, PAGE_SIZE_4K, flag.bits());
}
