#![no_std]
#![no_main]
#![feature(asm_const)]
use axhal::console::task_id;
use axhal::misc;
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
use page_table::paging::{self, setup_page_table_root};
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

    let mut xt:usize = 0;
    unsafe{
        info!("start thread ...");
        let func : fn() = transmute(entry);
        let tid = user_mode_thread(
            move || {
                func()
            },
            fork::CloneFlags::CLONE_FS,
        );
        xt = tid;
    }
    info!("sssssssssss:{:0x}" , xt );
    let user_task = task::get_task(xt).unwrap();

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
                    let cmm = task::current().mm();
                    let mm = user_task.mm();
                    info!("task_o root:0x{:0x} , task_1 root:0x{:0x} " , cmm.lock().root_paddr() , mm.lock().root_paddr() );
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
            
            copy_slice_to_address( segment , cpaddr  );

            if ph.p_filesz < ph.p_memsz{
                let bss_start = cpaddr as u64 + ph.p_filesz;
                let bss_size = ph.p_memsz - ph.p_filesz;

                let bss_ptr = (bss_start as usize) as *mut u8;
                info!("bss_start:0x{:0x} ,,, end:0x{:0x} , memsize:0x{:0x}" , ph.p_vaddr+ph.p_filesz  , ph.p_vaddr +ph.p_filesz+ bss_size as u64 , ph.p_memsz );
                unsafe {
                    core::ptr::write_bytes(bss_ptr, 0, bss_size as usize);
                }
            }
        }
    }

    {
        match axalloc::global_allocator().alloc_pages(1, PAGE_SIZE ){
            Ok(memory_addr) => {
                let pa : usize = virt_to_phys(memory_addr.into()).into();
                //let mm = task::current().mm();
                let mm = user_task.mm();
                mm.lock().map_region(0 as usize, pa as usize, 1 * PAGE_SIZE, 0);
                //paging::add_app_vm_page(max_addr as usize  , pa as usize , 20 * PAGE_SIZE ,MemRegionFlags::READ | MemRegionFlags::WRITE, true );
            }
            Err(err) => {
                panic!("Failed to allocate memory");
            }
        }
        user_task.mm().lock().set_brk(max_addr);
    }

    info!("--------------------------");

    let task = task::current();
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().resched(false);
    misc::terminate();
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
