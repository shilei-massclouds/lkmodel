#![no_std]
#![no_main]
#![feature(asm_const)]
use axhal::console::task_id;
use mm::VmAreaStruct;
use task::current;
use core::panic::PanicInfo;
use fork::user_mode_thread;
use axhal::mem::{ virt_to_phys , phys_to_virt };
use axlog2::{ debug , error ,info };
const PLASH_START: usize = 0xffff_ffc022000000;
const PAGE_SIZE: usize = 0x1000;
use axstd::println;
use core::slice;
use elf::ElfBytes;
use elf::endian::{AnyEndian, LittleEndian};
use elf::abi::{PF_R, PF_W, PF_X};
use elf::segment::ProgramHeader;
use page_table::paging;
use axhal::mem::MemRegionFlags;
use core::arch::asm;
use core::mem::transmute;
fn get_elf_data() -> &'static [u8] {
    unsafe { slice::from_raw_parts(PLASH_START as *const u8, 0x2000000) }
}


#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    init(_cpu_id);
    let elf_data = get_elf_data();
    let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_data).expect("Failed to parse ELF");
    let entry = elf.ehdr.e_entry as usize;
    let program_headers = elf.segments().ok_or("Failed to read program headers").unwrap();
    let mut max_addr:usize = 0;
    for ph in program_headers.iter() {
        if ph.p_type == elf::abi::PT_LOAD {
            let flags = convert_flags( ph.p_flags );

            let segment = elf.segment_data(&ph).map_err(|_| "Failed to read segment data").unwrap();
            let map_start = axtype::align_down_4k(ph.p_paddr as usize);//align_down;
            let map_size = (ph.p_paddr as usize - map_start) + ph.p_memsz as usize;
            let page_num: usize = axtype::align_up_4k(map_size) / PAGE_SIZE;
            match axalloc::global_allocator().alloc_pages(page_num, PAGE_SIZE ){
                Ok(memory_addr) => {
                    let pa : usize = virt_to_phys(memory_addr.into()).into();
                    let mm = task::current().mm();
                    mm.lock().map_region(map_start, pa, page_num * PAGE_SIZE, 0);
                    //paging::add_app_vm_page(map_start  , pa  as usize , page_num * PAGE_SIZE ,flags | MemRegionFlags::WRITE, true );
                }
                Err(err) => {
                    info!("Failed to allocate memory: {:?}", err);
                }
            }

            if map_start  + page_num * PAGE_SIZE > max_addr {
                max_addr = map_start + page_num * PAGE_SIZE;
            }

            copy_slice_to_address( segment , ph.p_paddr as usize  );

            if ph.p_filesz < ph.p_memsz{
                let bss_start = ph.p_vaddr + ph.p_filesz;
                let bss_size = ph.p_memsz - ph.p_filesz;

                let bss_ptr = (bss_start as usize) as *mut u8;

                unsafe {
                    core::ptr::write_bytes(bss_ptr, 0, bss_size as usize);
                }
            }
        }
    }
    match axalloc::global_allocator().alloc_pages(20, PAGE_SIZE ){
        Ok(memory_addr) => {
            let pa : usize = virt_to_phys(memory_addr.into()).into();
            let mm = task::current().mm();
            mm.lock().map_region(max_addr as usize, pa as usize, 20 * PAGE_SIZE, 0);
            //paging::add_app_vm_page(max_addr as usize  , pa as usize , 20 * PAGE_SIZE ,MemRegionFlags::READ | MemRegionFlags::WRITE, true );
        }
        Err(err) => {
            panic!("Failed to allocate memory");
        }
    }


    {
        match axalloc::global_allocator().alloc_pages(16, PAGE_SIZE ){
            Ok(memory_addr) => {
                let pa : usize = virt_to_phys(memory_addr.into()).into();
                let mm = task::current().mm();
                mm.lock().map_region(0 as usize, pa as usize, 10 * PAGE_SIZE, 0);
                //paging::add_app_vm_page(max_addr as usize  , pa as usize , 20 * PAGE_SIZE ,MemRegionFlags::READ | MemRegionFlags::WRITE, true );
            }
            Err(err) => {
                panic!("Failed to allocate memory");
            }
        }
        task::current().mm().lock().set_brk(max_addr + 20 * PAGE_SIZE);
    }

    print_bytes_at(0xFFFFFFC0802A0BB0, 3);

    unsafe{
        info!("start thread ...");
        let func : fn() = transmute(entry);
        let tid = user_mode_thread(
            move || {
                func()
            },
            fork::CloneFlags::CLONE_FS,
        );
    }
    //let x = task::get_task(tid).unwrap();


    //let task = task::current();
    let rq = run_queue::task_rq(&task.sched_info);
    info!("sp_top:0x{:0x}" , max_addr + 19 * PAGE_SIZE );
    rq.lock().resched(false);
    //sp = sp_top
    let sp_top = max_addr + 19 * PAGE_SIZE ;
    let program_name = b"./a\0";
    let argv = [program_name.as_ptr(), core::ptr::null()];
    let envp:[*const u8;1] = [core::ptr::null()];
    info!("----------------------------------");
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

        mv t0, {0}
        mv t2, {1}
        mv sp, t0

        li x0 , 0
        li x1 , 0

        li x3 , 0
        li x4 , 0
        li x5 , 0
        li x6 , 0

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
        in(reg) sp_top,
        in(reg) entry
    )}
    info!("0x:{:0x}" , max_addr );


    info!("end");
}


fn print_bytes_at(address: usize, num_bytes: usize) {
    unsafe {
        let bytes = core::slice::from_raw_parts(address as *const u8, num_bytes);
        info!("Bytes at address 0x{:x}:", address);
        for byte in bytes.iter() {
            info!("{:02x} ", byte);
        }
    }
}

fn copy_slice_to_address(slice: &[u8], address: usize) {
    println!("Start Copy");
    unsafe {
        let dst_ptr = address as *mut u8;

        for (i, &byte) in slice.iter().enumerate() {
            *dst_ptr.add(i) = byte;
        }
    }

    println!("Copied {} bytes to address 0x{:x}", slice.len(), address);
}



fn convert_flags( fplags : u32 ) -> MemRegionFlags {
    let mut prot = MemRegionFlags::empty();

    if (fplags & PF_R) != 0 {
        prot |= MemRegionFlags::READ;
    }
    if (fplags & PF_W) != 0 {
        prot |= MemRegionFlags::WRITE;
    }
    if (fplags & PF_X) != 0 {
        prot |= MemRegionFlags::EXECUTE;
    }

    prot
}





fn init(_cpu_id:usize){
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
    paging::set_app_vm_page( task::current().mm().lock().root_paddr().into())
}


#[panic_handler]
pub fn panic(info: &PanicInfo) -> !{
    error!("{}", info);
    axhal::misc::terminate();
    arch_boot::panic(info);
}
