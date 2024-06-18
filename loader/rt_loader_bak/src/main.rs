#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::{println, thread,  vec::Vec};//vm,

extern crate alloc;
use alloc::string::String;

use memory_addr::{PAGE_SIZE_4K, align_down_4k, align_up_4k};

use mm::{MmStruct, VmAreaStruct};
use  page_table::{MappingFlags};

const PAGE_SHIFT: usize = 12;
const PFLASH_START: usize = 0xffff_ffc0_2200_0000;



#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    let mut pos = PFLASH_START;
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

        thread::spawn(move || {
            let mut vm = MmStruct::new();
            println!("\n==============");
            let (entry, end) = parse_elf(code,&vm);
            println!("App: entry: {:#X}", entry);

            run_app(entry, end,&vm);
        });
    }

    loop {
        thread::yield_now();
    }
}

// Note: Length of literal hex must be 8.
fn parse_literal_hex(pos: usize) -> usize {
    let hex = unsafe { core::slice::from_raw_parts(pos as *const u8, 8) };
    let hex = String::from_utf8(hex.into()).expect("bad hex number.");
    usize::from_str_radix(&hex, 16).expect("NOT hex number.")
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

fn run_app(entry: usize, end: usize,vm:& MmStruct) {
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

    setup_zero_page(&mut vm);

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
