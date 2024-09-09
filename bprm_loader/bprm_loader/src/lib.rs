#![no_std]
#![feature(cstr_count_bytes)]

#[macro_use]
extern crate log;
extern crate alloc;

use core::ptr::null;
use core::str::from_utf8;
use alloc::vec::Vec;
use alloc::string::String;

use axerrno::LinuxResult;
use axhal::arch::STACK_SIZE;
use elf::abi::{PT_INTERP, PT_LOAD};
use elf::endian::AnyEndian;
use elf::parse::ParseAt;
use elf::segment::ProgramHeader;
use elf::segment::SegmentTable;
use elf::ElfBytes;
use axio::SeekFrom;
use axtype::{align_down, align_down_4k, align_up_4k, PAGE_SIZE};
use axtype::is_aligned;
use mmap::FileRef;
use mmap::{MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE};
use user_stack::UserStack;
use axhal::arch::TASK_SIZE;
use mmap::{PROT_READ, PROT_WRITE, PROT_EXEC};
use elf::abi::{PF_R, PF_W, PF_X};
use axhal::arch::ELF_ET_DYN_BASE;

const ELF_HEAD_BUF_SIZE: usize = 256;

/// executes a new program.
pub fn execve(
    filename: &str, flags: usize, argv: Vec<String>, envp: Vec<String>
) -> LinuxResult<(usize, usize)> {
    debug!("bprm_execve: {}", filename);
    let file = do_open_execat(filename, flags)?;
    exec_binprm(filename, file, argv, envp)
}

fn do_open_execat(filename: &str, _flags: usize) -> LinuxResult<FileRef> {
    fileops::do_open(filename, _flags as i32)
}

fn exec_binprm(filename: &str, file: FileRef, argv: Vec<String>, envp: Vec<String>) -> LinuxResult<(usize, usize)> {
    load_elf_binary(filename, file, argv, envp)
}

fn total_mapping_size(phdrs: &Vec<ProgramHeader>) -> usize {
    let mut first = usize::MAX;
    let mut last = usize::MAX;
    for (idx, phdr) in phdrs.iter().enumerate() {
        if phdr.p_type == PT_LOAD {
            if first == usize::MAX {
                first = idx;
            }
            last = idx;
        }
    }
    assert_ne!(first, usize::MAX);
    assert_ne!(last, usize::MAX);
    let start = align_down_4k(phdrs[0].p_vaddr as usize);
    (phdrs[last].p_vaddr + phdrs[last].p_memsz) as usize - start
}

fn load_elf_interp(
    file: FileRef,
    _app_entry: usize,
) -> LinuxResult<(usize, usize)> {
    let no_base: usize = 1;
    let mut load_addr = 0;
    let mut load_addr_set = false;
    let (phdrs, entry, _, _) = load_elf_phdrs(file.clone())?;

    let mut elf_bss: usize = 0;
    let mut elf_brk: usize = 0;

    let mut total_size = total_mapping_size(&phdrs);

    //info!("interp: args: {:?}", args);
    info!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in &phdrs {
        let mut elf_type = MAP_PRIVATE;
        info!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
        );

        let va = align_down_4k(phdr.p_vaddr as usize);

        if load_addr_set {
            elf_type |= MAP_FIXED;
        } else if no_base != 0 {
            debug!("no_base {:#x}", no_base);
            load_addr = va.wrapping_neg();
            assert_eq!(load_addr+va, 0);
        }

        let map_addr = elf_map(
            &phdr,
            va + load_addr,
            total_size,
            make_prot(phdr.p_flags),
            elf_type,
            Some(file.clone())
        )?;
        total_size = 0;

        if !load_addr_set {
            load_addr = map_addr - align_down_4k(va);
            debug!("load_addr {:#x}", load_addr);
            load_addr_set = true;
        }

        let pos = (phdr.p_vaddr + phdr.p_filesz) as usize;
        if elf_bss < pos {
            elf_bss = pos;
        }
        let pos = (phdr.p_vaddr + phdr.p_memsz) as usize;
        if elf_brk < pos {
            elf_brk = pos;
        }
    }

    //let entry = entry + load_addr;
    elf_bss += load_addr;
    //elf_brk += load_addr;

    //info!("set brk...");
    //set_brk(elf_bss, elf_brk);

    info!("pad bss...");
    padzero(elf_bss);
    //Ok((entry, sp))
    Ok((load_addr, entry))
}

fn elf_page_offset(va: u64) -> u64 {
    va & (PAGE_SIZE-1) as u64
}

fn bad_addr(va: usize) -> bool {
    va >= TASK_SIZE
}

fn elf_map(
    phdr: &ProgramHeader,
    mut va: usize,
    mut total_size: usize,
    prot: usize,
    flags: usize,
    file: Option<FileRef>,
) -> LinuxResult<usize> {
    let mut size = (phdr.p_filesz + elf_page_offset(phdr.p_vaddr)) as usize;
    let off = (phdr.p_offset - elf_page_offset(phdr.p_vaddr)) as usize;
    va = align_down_4k(va);
    size = align_up_4k(size);

    /* mmap() will return -EINVAL if given a zero size, but a
     * segment with zero filesize is perfectly valid */
    if size == 0 {
        return Ok(va);
    }

    if total_size > 0 {
        total_size = align_up_4k(total_size);
        debug!("elf_map1: addr {:#x}, total_size {:#x}, prot {:#x}, type {:#x}, off {:#x}\n",
               va, total_size, prot, flags, off);
        let map_addr = mmap::_mmap(va, total_size, prot, flags, file, off)?;
        if !bad_addr(map_addr) {
            debug!("elf_map: unmap\n");
            mmap::munmap(map_addr+size, total_size-size);
        }
        Ok(map_addr)
    } else {
        debug!("elf_map2: addr {:#x}, size {:#x}, prot {:#x}, type {:#x}, off {:#x}\n",
               va, size, prot, flags, off);
        mmap::_mmap(va, size, prot, flags, file, off)
    }
}

fn load_elf_binary(
    filename: &str, file: FileRef, argv: Vec<String>, envp: Vec<String>
) -> LinuxResult<(usize, usize)> {
    let mut interp_file = None;
    let mut load_addr_set = false;
    let mut load_bias = 0;
    let (phdrs, entry, e_phoff, e_phnum) = load_elf_phdrs(file.clone())?;

    for phdr in &phdrs {
        if phdr.p_type == PT_INTERP {
            info!(
                "Interp: phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
                phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
            );
            let mut path: [u8; 256] = [0; 256];
            let _ = file.lock().seek(SeekFrom::Start(phdr.p_offset as u64));
            let ret = file.lock().read(&mut path).unwrap();
            let path = &path[0..phdr.p_filesz as usize];
            let path = from_utf8(&path).expect("Interpreter path isn't valid UTF-8");
            let path = path.trim_matches(char::from(0));
            info!("PT_INTERP ret {} {:?}!", ret, path);
            let file = do_open_execat(path, 0)?;
            interp_file = Some(file);
        }
    }

    let mut elf_bss: usize = 0;
    let mut elf_brk: usize = 0;
    let mut phdr_addr: usize = 0;

    for phdr in &phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        debug!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
        );
        let mut elf_type = MAP_PRIVATE;
        let mut total_size = 0;
        let va = phdr.p_vaddr as usize;

        if load_addr_set {
            elf_type |= MAP_FIXED;
        } else {
            assert!(interp_file.is_some());
            load_bias = align_down_4k(ELF_ET_DYN_BASE);
            debug!("load_bias: {:#x}", load_bias);
            elf_type |= MAP_FIXED;

            /*
             * Since load_bias is used for all subsequent loading
             * calculations, we must lower it by the first vaddr
             * so that the remaining calculations based on the
             * ELF vaddrs will be correctly offset. The result
             * is then page aligned.
             */
            load_bias = align_down_4k(load_bias - va);

            total_size = total_mapping_size(&phdrs);
            assert_ne!(total_size, 0);
        }

        debug!("=== binary elf_map load_bias: {:#x}, va: {:#x}, total: {:#x}\n",
               load_bias, va, total_size);

        let map_addr = elf_map(
            &phdr,
            va + load_bias,
            total_size,
            make_prot(phdr.p_flags),
            elf_type,
            Some(file.clone())
        )?;

        if !load_addr_set {
            load_addr_set = true;
            load_bias += map_addr - align_down_4k(load_bias + va);
        }

        /*
         * Figure out which segment in the file contains the Program
         * Header table, and map to the associated memory address.
         */
        if phdr.p_offset as usize <= e_phoff && e_phoff < (phdr.p_offset + phdr.p_filesz) as usize {
            phdr_addr = e_phoff - phdr.p_offset as usize + phdr.p_vaddr as usize;
            debug!("===> phdr_addr {:#x}", phdr_addr);
        }

        let pos = (phdr.p_vaddr + phdr.p_filesz) as usize;
        if elf_bss < pos {
            elf_bss = pos;
        }
        let pos = (phdr.p_vaddr + phdr.p_memsz) as usize;
        if elf_brk < pos {
            elf_brk = pos;
        }
    }

    let entry = entry + load_bias;
    phdr_addr += load_bias;
    elf_bss += load_bias;
    elf_brk += load_bias;
    debug!("entry {:#x} elf_bss {:#x} elf_brk {:#x}", entry, elf_bss, elf_brk);

    info!("set brk...");
    set_brk(elf_bss, elf_brk);
    padzero(elf_bss);

    let (mut elf_entry, interp_e_entry) = if let Some(file) = interp_file {
        load_elf_interp(file, entry)?
    } else {
        panic!("No interpret file!");
    };

    // Todo: setup vdso pages for riscv64. vdso_len = 0x2000.
    arch_setup_additional_pages();

    let interp_load_addr = elf_entry;
    elf_entry += interp_e_entry;

    create_elf_tables(e_phnum, interp_load_addr, entry, phdr_addr);

    let sp = get_arg_page(filename, e_phnum, interp_load_addr, entry, phdr_addr, elf_entry, argv, envp)?;
    Ok((elf_entry, sp))
}

fn arch_setup_additional_pages() {
    // Todo: implement it. setup vdso pages.
    let _ = mmap::_mmap(0, 0x2000, PROT_READ | PROT_EXEC, MAP_ANONYMOUS, None, 0);
}

fn create_elf_tables(e_phnum: usize, interp_load_addr: usize, e_entry: usize, phdr_addr: usize) {
    debug!("create_elf_tables: e_phum {:#x}, interp_load_addr {:#x} e_entry {:#x} phdr_addr {:#x}",
           e_phnum, interp_load_addr, e_entry, phdr_addr);
}

fn padzero(elf_bss: usize) {
    let nbyte = elf_bss & (PAGE_SIZE - 1);
    info!("padzero nbyte: {:#X} ...", elf_bss);
    if nbyte != 0 {
        let nbyte = PAGE_SIZE - nbyte;
        unsafe { core::slice::from_raw_parts_mut(elf_bss as *mut u8, nbyte) }.fill(0);
        info!("padzero nbyte: {:#X} {:#X}", elf_bss, nbyte);
    }
}

fn set_brk(elf_bss: usize, elf_brk: usize) {
    let elf_bss = align_up_4k(elf_bss);
    let elf_brk = align_up_4k(elf_brk);
    if elf_bss < elf_brk {
        warn!("{:#X} < {:#X}", elf_bss, elf_brk);
        mmap::_mmap(
            elf_bss,
            elf_brk - elf_bss,
            PROT_READ | PROT_WRITE,
            MAP_FIXED | MAP_ANONYMOUS,
            None,
            0,
        )
        .unwrap();
    }

    task::current().mm().lock().set_brk(elf_brk as usize)
}

#[inline]
fn make_prot(pflags: u32) -> usize {
    let mut prot = 0;

    if (pflags & PF_R) != 0 {
        prot |= PROT_READ;
    }
    if (pflags & PF_W) != 0 {
        prot |= PROT_WRITE;
    }
    if (pflags & PF_X) != 0 {
        prot |= PROT_EXEC;
    }

    prot
}

fn load_elf_phdrs(file: FileRef) -> LinuxResult<(Vec<ProgramHeader>, usize, usize, usize)> {
    let mut file = file.lock();
    let mut buf: [u8; ELF_HEAD_BUF_SIZE] = [0; ELF_HEAD_BUF_SIZE];
    file.read(&mut buf)?;

    let ehdr = ElfBytes::<AnyEndian>::parse_elf_header(&buf[..]).unwrap();
    info!("e_entry: {:#X}", ehdr.e_entry);

    let phnum = ehdr.e_phnum as usize;
    // Validate phentsize before trying to read the table so that we can error early for corrupted files
    let entsize = ProgramHeader::validate_entsize(ehdr.class, ehdr.e_phentsize as usize).unwrap();
    let size = entsize.checked_mul(phnum).unwrap();
    assert!(size > 0 && size <= PAGE_SIZE);
    let phoff = ehdr.e_phoff;
    let mut buf = alloc::vec![0u8; size];
    let _ = file.seek(SeekFrom::Start(phoff));
    file.read(&mut buf)?;
    let phdrs = SegmentTable::new(ehdr.endianness, ehdr.class, &buf[..]);

    let phdrs: Vec<ProgramHeader> = phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD || phdr.p_type == PT_INTERP)
        .collect();
    Ok((phdrs, ehdr.e_entry as usize, ehdr.e_phoff as usize, ehdr.e_phnum as usize))
}

/// entries in ARCH_DLINFO
const AT_VECTOR_SIZE_ARCH: usize = 7;
const AT_VECTOR_SIZE_BASE: usize = 20;
const AT_VECTOR_SIZE: usize = 2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1);

/// Symbolic values for the entries in the auxiliary table
/// put on the initial stack
const AT_NULL   : usize = 0;    /* end of vector */
#[allow(unused)]
const AT_IGNORE : usize = 1;    /* entry should be ignored */
#[allow(unused)]
const AT_EXECFD : usize = 2;    /* file descriptor of program */
const AT_PHDR   : usize = 3;    /* program headers for program */
const AT_PHENT  : usize = 4;    /* size of program header entry */
const AT_PHNUM  : usize = 5;    /* number of program headers */
const AT_PAGESZ : usize = 6;    /* system page size */
const AT_BASE   : usize = 7;    /* base address of interpreter */
const AT_FLAGS  : usize = 8;    /* flags */
const AT_ENTRY  : usize = 9;    /* entry point of program */
#[allow(unused)]
const AT_NOTELF : usize = 10;   /* program is not ELF */
#[allow(unused)]
const AT_UID    : usize = 11;   /* real uid */
#[allow(unused)]
const AT_EUID   : usize = 12;   /* effective uid */
#[allow(unused)]
const AT_GID    : usize = 13;   /* real gid */
#[allow(unused)]
const AT_EGID   : usize = 14;   /* effective gid */
#[allow(unused)]
const AT_PLATFORM: usize = 15; /* string identifying CPU for optimizations */
const AT_HWCAP  : usize = 16;   /* arch dependent hints at CPU capabilities */
const AT_CLKTCK : usize = 17;   /* frequency at which times() increments */
/* AT_* values 18 through 22 are reserved */
#[allow(unused)]
const AT_SECURE : usize = 23;   /* secure mode boolean */
#[allow(unused)]
const AT_BASE_PLATFORM: usize = 24;       /* string identifying real platform, may differ from AT_PLATFORM. */
const AT_RANDOM : usize = 25;   /* address of 16 random bytes */
#[allow(unused)]
const AT_HWCAP2 : usize = 26;   /* extension of AT_HWCAP */
const AT_EXECFN : usize = 31;   /* filename of program */

const MAX_ARG_STRLEN: usize = PAGE_SIZE;

fn new_aux_ent(elf_info: &mut Vec<usize>, id: usize, val: usize) {
    elf_info.push(id);
    elf_info.push(val);
}

fn get_arg_page(
    filename: &str,
    e_phnum: usize, interp_load_addr: usize, entry: usize, phdr_addr: usize,
    _entry: usize, argv: Vec<String>, envp: Vec<String>
) -> LinuxResult<usize> {
    //let auxv = : usize = get_auxv_vector(entry);

    let va = TASK_SIZE - STACK_SIZE;
    mmap::_mmap(va, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS, None, 0)?;
    // Todo: set proper cause for faultin_page.
    let mut _fixup = 0;
    let direct_va = mmap::faultin_page(TASK_SIZE - PAGE_SIZE, 0, 0, &mut _fixup).unwrap();
    let mut stack = UserStack::new(TASK_SIZE, direct_va + PAGE_SIZE);
    stack.push(&[null::<u64>()]);
    debug!("initial: {:#x}", stack.get_sp());

    assert!(argv.len() > 0);
    stack.push_str(filename);
    let exec_fname = stack.get_sp();
    debug!("exec {:#x}", stack.get_sp());

    for env in envp.iter().rev() {
        stack.push_str(&env);
    }
    let mut env_start = stack.get_sp();
    debug!("envp {:#x}", stack.get_sp());

    for arg in argv.iter().rev() {
        stack.push_str(&arg);
    }
    let mut arg_start = stack.get_sp();
    debug!("argv {:#x}", stack.get_sp());

    let random_str: &[usize; 2] = &[0, 0];
    stack.push(random_str.as_slice());
    let u_rand_bytes = stack.get_sp();
    debug!("random {:#x} AT_VECTOR_SIZE {:#x}", stack.get_sp(), AT_VECTOR_SIZE);

    // Note: Just for riscv64
    const ELF_HWCAP: usize = 0x112d;
    const ELF_EXEC_PAGESIZE: usize = 0x1000;
    const CLOCKS_PER_SEC: usize = 0x64;

    let mut saved_auxv: Vec<usize> = Vec::with_capacity(AT_VECTOR_SIZE);
    new_aux_ent(&mut saved_auxv, AT_HWCAP, ELF_HWCAP);
    new_aux_ent(&mut saved_auxv, AT_PAGESZ, ELF_EXEC_PAGESIZE);
    new_aux_ent(&mut saved_auxv, AT_CLKTCK, CLOCKS_PER_SEC);
    new_aux_ent(&mut saved_auxv, AT_PHDR, phdr_addr);
    new_aux_ent(&mut saved_auxv, AT_PHENT, core::mem::size_of::<ProgramHeader>());
    new_aux_ent(&mut saved_auxv, AT_PHNUM, e_phnum);
    new_aux_ent(&mut saved_auxv, AT_BASE, interp_load_addr);
    new_aux_ent(&mut saved_auxv, AT_FLAGS, 0);
    new_aux_ent(&mut saved_auxv, AT_ENTRY, entry);
    new_aux_ent(&mut saved_auxv, AT_UID, 0);
    new_aux_ent(&mut saved_auxv, AT_EUID, 0);
    new_aux_ent(&mut saved_auxv, AT_GID, 0);
    new_aux_ent(&mut saved_auxv, AT_EGID, 0);
    new_aux_ent(&mut saved_auxv, AT_SECURE, 0);
    new_aux_ent(&mut saved_auxv, AT_RANDOM, u_rand_bytes);
    new_aux_ent(&mut saved_auxv, AT_EXECFN, exec_fname);
    new_aux_ent(&mut saved_auxv, AT_NULL, 0);

    let mut sp = stack.get_sp() - saved_auxv.len() * 8;
    debug!("ei_index: {}; sp {:#x}, orig {:#x}", saved_auxv.len(), sp, stack.get_sp());

    // For X86_64, Stack must be aligned to 16-bytes.
    // E.g., there're some SSE instructions like 'movaps %xmm0,-0x70(%rbp)'.
    // When we call these, X86_64 requires that memory-alignment aligned to 16-bytes.
    // Or mmu causes #GP.
    let items = (argv.len() + 1) + (envp.len() + 1) + 1;
    sp = align_down(sp - items * 8, 16);
    debug!("sp {:#x}", sp);

    // Todo: Check whether there's enough space for CURRENT stack.

    let mut pos = sp;

    /* Now, let's put argc (and argv, envp if appropriate) on the stack */
    pos = put_user(argv.len(), pos);

    /* Populate list of argv pointers back to argv strings. */
    for _ in 0..argv.len() {
        pos = put_user(arg_start, pos);
        let len = strnlen_user(arg_start, MAX_ARG_STRLEN);
        if len == 0 || len > MAX_ARG_STRLEN {
            panic!("EINVAL");
        }
        arg_start += len;
    }
    pos = put_user(0, pos);

    /* Populate list of envp pointers back to envp strings. */
    for _ in 0..envp.len() {
        debug!("env: {:#x}", env_start);
        pos = put_user(env_start, pos);
        let len = strnlen_user(env_start, MAX_ARG_STRLEN);
        if len == 0 || len > MAX_ARG_STRLEN {
            panic!("EINVAL");
        }
        debug!("len: {:#x}", len);
        env_start += len;
    }
    pos = put_user(0, pos);

    /* Put the elf_info on the stack in the right place.  */
    let _ = copy_to_user(pos, &saved_auxv);

    //show_mem(sp);
    assert!(is_aligned(sp, 16));
    warn!("stack sp {:#x}", sp);
    Ok(sp)
}

/*
fn show_mem(mut pos: usize) {
    assert!(is_aligned(pos, 16));
    for _ in 0..4 {
        let ptr = pos as *const usize;
        unsafe {
            debug!("[{:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x}]",
               *ptr.add(0), *ptr.add(1), *ptr.add(2), *ptr.add(3),
               *ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7));
        }
        pos += 8 * 8;
    }
}
*/

fn put_user(val: usize, pos: usize) -> usize {
    let ptr = pos as *mut usize;
    unsafe { *ptr = val; }
    pos + 8
}

fn strnlen_user(pos: usize, max: usize) -> usize {
    use core::ffi::CStr;
    use core::ffi::c_char;
    unsafe {
        let s = CStr::from_ptr(pos as *const c_char);
        assert!(s.count_bytes() < max);
        debug!("s = {:?} {}", s, s.count_bytes());
        s.count_bytes() + 1
    }
}

fn copy_to_user(pos: usize, vsrc: &Vec<usize>) -> usize {
    let ptr = pos as *mut usize;
    unsafe {
        core::slice::from_raw_parts_mut(ptr, vsrc.len())
            .copy_from_slice(&vsrc);
    }
    pos + vsrc.len() * 8
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init();
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);
    user_stack::init();
    fileops::init(cpu_id, dtb_pa);
}
