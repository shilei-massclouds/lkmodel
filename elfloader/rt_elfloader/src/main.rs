#![no_std]
#![no_main]
#![feature(asm_const)]
use axalloc::global_allocator;
use axhal::console::task_id;
use axhal::misc;
use axtype::PAGE_SIZE;
use mm::VmAreaStruct;
use task::current;
use core::iter::Scan;
use core::panic::PanicInfo;
use fork::user_mode_thread;
use axhal::mem::{ virt_to_phys , phys_to_virt };
use axlog2::{ debug , error ,info };
const PLASH_START: usize = 0xffff_ffc022000000;
use axstd::{print, println};
use core::slice;
use elf::ElfBytes;
use elf::endian::{AnyEndian, LittleEndian};
use elf::abi::{PF_R, PF_W, PF_X};
use elf::segment::ProgramHeader;
use page_table::paging;
use axhal::mem::MemRegionFlags;
use core::arch::asm;
use core::mem::transmute;


const MARKERS: [&str; 3] = ["APP1_START", "APP2_START","APP3_START"];

fn get_elf_data( offset:usize , len:usize ) -> &'static [u8] {
    unsafe { slice::from_raw_parts(offset as *const u8, len) }
}

fn find_marker(base_addr: *const u8, length: usize, marker: &str) -> Option<usize> {
    let marker_bytes = marker.as_bytes();
    let marker_len = marker_bytes.len();

    for i in 0..(length - marker_len) {
        let mut match_found = true;
        for j in 0..marker_len {
            unsafe {
                if *base_addr.add(i + j) != marker_bytes[j] {
                    match_found = false;
                    break;
                }
            }
        }
        if match_found {
            return Some(i);
        }
    }

    None
}



#[no_mangle]
pub extern "Rust" fn runtime_main(_cpu_id: usize, _dtb_pa: usize) {
    init(_cpu_id);

    let app_num = 3;
    for i in 0..app_num {
        start_app(i);
        println!("APP_{} START RUN!!!!!" , i + 1 );
        let task = task::current();
        let rq = run_queue::task_rq(&task.sched_info);
        rq.lock().resched(false);
    }
    misc::terminate();
}

fn start_app( app_id:usize ){
    let apps_bin = PLASH_START as *const u8;
    let apps_bin_len = 32 * 1024 * 1024; 
    if let Some(app_pos) = find_marker(apps_bin, apps_bin_len, MARKERS[app_id]) {
        let app_start_address = PLASH_START as u64 + app_pos as u64 + MARKERS[app_id].len() as u64;
        print_bytes_at(app_start_address as usize, 5);
        load_app(app_start_address as usize, 0x2000000);
    } else {
        println!("App1 marker not found.");
    }
}

fn load_app( offset : usize , len : usize) {
    let elf_data = get_elf_data(offset,len);
    let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_data).expect("Failed to parse ELF");
    let entry = elf.ehdr.e_entry as usize;
    let mut app_tid:usize = 0;
    unsafe{
        info!("start thread ...");
        app_tid = user_mode_thread(
            move || {
                run_app(entry)
            },
            fork::CloneFlags::CLONE_FS | fork::CloneFlags::NOT_CLONE_VM,
        );
    }

    let user_task = task::get_task(app_tid).unwrap();

    let program_headers = elf.segments().ok_or("Failed to read program headers").unwrap();
    let mut max_addr:usize = 0;
    for ph in program_headers.iter() {
        if ph.p_type == elf::abi::PT_LOAD {
            let flags = convert_flags( ph.p_flags );

            let segment = elf.segment_data(&ph).map_err(|_| "Failed to read segment data").unwrap();
            let map_start = axtype::align_down_4k(ph.p_paddr as usize);//align_down;
            let map_size = (ph.p_paddr as usize - map_start) + ph.p_memsz as usize;
            let page_num: usize = axtype::align_up_4k(map_size) / PAGE_SIZE;
            let mut cpaddr = ph.p_paddr as usize  - map_start;
            match axalloc::global_allocator().alloc_pages(page_num, PAGE_SIZE ){
                Ok(memory_addr) => {
                    cpaddr = memory_addr + cpaddr;
                    let pa : usize = virt_to_phys(memory_addr.into()).into();
                    let mm = user_task.mm();
                    mm.lock().map_region(map_start, pa, page_num * PAGE_SIZE, 0);
                }
                Err(err) => {
                    info!("Failed to allocate memory: {:?}", err);
                }
            }

            if map_start  + page_num * PAGE_SIZE > max_addr {
                max_addr = map_start + page_num * PAGE_SIZE;
            }
            copy_slice_to_address( segment , cpaddr  );

            if ph.p_filesz < ph.p_memsz{
                let bss_start = cpaddr as u64 + ph.p_filesz;
                let bss_size = ph.p_memsz - ph.p_filesz;
                let bss_ptr = (bss_start as usize) as *mut u8;
                unsafe {
                    core::ptr::write_bytes(bss_ptr, 0, bss_size as usize);
                }
            }
        }
    }
    
    user_task.mm().lock().set_brk(max_addr);

    {
        match axalloc::global_allocator().alloc_pages(1, PAGE_SIZE ){
            Ok(memory_addr) => {
                let pa : usize = virt_to_phys(memory_addr.into()).into();
                let mm = user_task.mm();
                mm.lock().map_region(0 as usize, pa as usize, 1 * PAGE_SIZE, 0);
            }
            Err(err) => {
                panic!("Failed to allocate memory");
            }
        }
    }
}

fn set_zero_page(){
    match axalloc::global_allocator().alloc_pages(16, PAGE_SIZE ){
        Ok(memory_addr) => {
            let pa : usize = virt_to_phys(memory_addr.into()).into();
            let mm = task::current().mm();
                        mm.lock().map_region(0 as usize, pa as usize, 1 * PAGE_SIZE, 0);
            //paging::add_app_vm_page(max_addr as usize  , pa as usize , 20 * PAGE_SIZE ,MemRegionFlags::READ | MemRegionFlags::WRITE, true );
        }
        Err(err) => {
            panic!("Failed to allocate memory");
        }
    }
}

fn run_app( entry:usize ) {
    let sp_top =  axalloc::global_allocator().alloc_pages(20, 4096 ).unwrap() + 19 * 4096;
    info!("sp_top:{:0x}" , sp_top );
    unsafe {
        core::arch::asm!("
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
            li a0 , 0
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
        )
    }
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
    unsafe {
        let dst_ptr = address as *mut u8;

        for (i, &byte) in slice.iter().enumerate() {
            *dst_ptr.add(i) = byte;
        }
    }
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
    axlog2::init("error");
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
