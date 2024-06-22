#![no_std]

#[macro_use]
extern crate axlog2;
extern crate alloc;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use alloc::string::String;
use core::str::from_utf8;
use core::{mem::align_of, mem::size_of_val, ptr::null};

use axerrno::LinuxResult;
use axfile::fops::File;
use axfile::fops::OpenOptions;
use axhal::arch::start_thread;
use axhal::arch::STACK_SIZE;
use axhal::arch::{ELF_ET_DYN_BASE, TASK_SIZE};
use axio::SeekFrom;
use elf::abi::{PT_INTERP, PT_LOAD};
use elf::endian::AnyEndian;
use elf::parse::ParseAt;
use elf::segment::ProgramHeader;
use elf::segment::SegmentTable;
use elf::ElfBytes;
use preempt_guard::NoPreempt;
use axtype::{align_down_4k, align_up_4k, PAGE_SIZE};
use mmap::FileRef;
use mmap::{MAP_ANONYMOUS, MAP_FIXED};
use mutex::Mutex;
use axtype::get_user_str_vec;
use elf::abi::{PF_R, PF_W, PF_X};
use mmap::{PROT_READ, PROT_WRITE, PROT_EXEC};
use axtype::is_aligned;

const ELF_HEAD_BUF_SIZE: usize = 256;

pub fn kernel_execve(filename: &str) -> LinuxResult {
    info!("kernel_execve... {}", filename);

    let mut task = task::current();
    {
        let _ = NoPreempt::new();
        task.as_task_mut().alloc_mm();
    }

    // TODO: Move it into kernel_init().
    setup_zero_page()?;
    let args = vec![filename.into()];
    bprm_execve(filename, 0, 0, args)
}

#[allow(unused)]
fn setup_zero_page() -> LinuxResult {
    info!("setup_zero_page ...");
    mmap::_mmap(0x0, PAGE_SIZE, PROT_READ, MAP_FIXED | MAP_ANONYMOUS, None, 0)?;
    Ok(())
}

//////////////////////////////////////////////

struct UserStack {
    _base: usize,
    sp: usize,
    ptr: usize,
}

impl UserStack {
    pub fn new(base: usize, ptr: usize) -> Self {
        Self {
            _base: base,
            sp: base,
            ptr,
        }
    }

    pub fn get_sp(&self) -> usize {
        self.sp
    }

    pub fn push<T: Copy>(&mut self, data: &[T]) {
        let origin = self.sp;
        self.sp -= size_of_val(data);
        self.sp -= self.sp % align_of::<T>();
        self.ptr -= origin - self.sp;
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut T, data.len()) }
            .copy_from_slice(data);
    }
    pub fn push_str(&mut self, str: &str) -> usize {
        self.push(&[b'\0']);
        self.push(str.as_bytes());
        self.sp
    }
}

//////////////////////////////////////////////

/*
const AT_PHDR: u8 = 3;
const AT_PHENT: u8 = 4;
const AT_PHNUM: u8 = 5;
const AT_PAGESZ: u8 = 6;
const AT_ENTRY: u8 = 9;
const AT_RANDOM: u8 = 25;

pub fn get_auxv_vector(
    entry: usize
) -> BTreeMap<u8, usize> {
    let mut map = BTreeMap::new();
    map.insert(
        AT_PHDR,
        40,
    );
    map.insert(AT_PHENT, 38);
    map.insert(AT_PHNUM, 2);
    map.insert(AT_ENTRY, entry);
    map.insert(AT_RANDOM, 0);
    map.insert(AT_PAGESZ, PAGE_SIZE);
    map
}
*/

fn get_arg_page(_entry: usize, args: Vec<String>) -> LinuxResult<usize> {
    //let auxv = get_auxv_vector(entry);

    let va = TASK_SIZE - STACK_SIZE;
    mmap::_mmap(va, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS, None, 0)?;
    // Todo: set proper cause for faultin_page.
    let direct_va = mmap::faultin_page(TASK_SIZE - PAGE_SIZE, 0);
    let mut stack = UserStack::new(TASK_SIZE, direct_va + PAGE_SIZE);
    stack.push(&[null::<u64>()]);

    let random_str: &[usize; 2] = &[3703830112808742751usize, 7081108068768079778usize];
    stack.push(random_str.as_slice());
    //let random_str_pos = stack.get_sp();

    let argv_slice: Vec<_> = args.iter().map(|arg| stack.push_str(arg)).collect();

    stack.push(&[null::<u8>(), null::<u8>()]);
    /*
    for (key, value) in auxv.iter() {
        if (*key) == 25 {
            // AT RANDOM
            stack.push(&[*key as usize, random_str_pos]);
        } else {
            stack.push(&[*key as usize, *value]);
        }
    }
    */

    // Todo: refine the code.
    // We can study from Linux's code just like:
    //   'items = (argc + 1) + (envc + 1) + 1;'
    //   'sp = STACK_ROUND(sp, items);'
    // And then, store argc, pointers of argv&envs.
    {
        if !is_aligned(stack.get_sp(), 16) {
            stack.push(&[null::<u8>()]);
        }
    }

    // pointers to envs
    stack.push(&[null::<u8>()]);
    stack.push(&[null::<u8>()]);
    // pointers to argv
    stack.push(&[null::<u8>()]);
    stack.push(argv_slice.as_slice());
    // argc
    stack.push(&[args.len()]);

    let sp = stack.get_sp();

    // For X86_64, Stack must be aligned to 16-bytes.
    // E.g., there're some SSE instructions like 'movaps %xmm0,-0x70(%rbp)'.
    // When we call these, X86_64 requires that memory-alignment aligned to 16-bytes.
    // Or mmu causes #GP.
    assert!(is_aligned(sp, 16));
    Ok(sp)
}

/// sys_execve() executes a new program.
fn bprm_execve(
    filename: &str, flags: usize, load_bias: usize, args: Vec<String>
) -> LinuxResult {
    info!("bprm_execve: {}", filename);
    let file = do_open_execat(filename, flags)?;
    exec_binprm(file, load_bias, args)
}

fn do_open_execat(filename: &str, _flags: usize) -> LinuxResult<FileRef> {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let file = File::open(filename, &opts, &fs)?;
    Ok(Arc::new(Mutex::new(file)))
}

fn exec_binprm(file: FileRef, load_bias: usize, args: Vec<String>) -> LinuxResult {
    load_elf_binary(file, load_bias, args)
}

fn load_elf_interp(
    file: FileRef,
    load_bias: usize,
    app_entry: usize,
    args: Vec<String>,
) -> LinuxResult {
    let (phdrs, entry) = load_elf_phdrs(file.clone())?;

    let mut elf_bss: usize = 0;
    let mut elf_brk: usize = 0;

    info!("interp: args: {:?}", args);
    info!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in &phdrs {
        info!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
        );

        let va = align_down_4k(phdr.p_vaddr as usize);
        let va_end = align_up_4k((phdr.p_vaddr + phdr.p_filesz) as usize);
        mmap::_mmap(
            va + load_bias,
            va_end - va,
            make_prot(phdr.p_flags),
            MAP_FIXED,
            Some(file.clone()),
            phdr.p_offset as usize,
        )?;

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
    elf_bss += load_bias;
    elf_brk += load_bias;

    let sp = get_arg_page(app_entry, args)?;

    info!("set brk...");
    set_brk(elf_bss, elf_brk);

    info!("pad bss...");
    padzero(elf_bss);

    info!("start thread...");
    start_thread(task::current().pt_regs_addr(), entry, sp);
    Ok(())
}

fn load_elf_binary(
    file: FileRef, load_bias: usize, mut args: Vec<String>
) -> LinuxResult {
    let (phdrs, entry) = load_elf_phdrs(file.clone())?;

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
            // Todo: check elf_ex->e_type == ET_DYN
            let load_bias = align_down_4k(ELF_ET_DYN_BASE);
            let file = do_open_execat(path, 0)?;
            args.insert(0, path.into());
            return load_elf_interp(file, load_bias, entry, args);
        }
    }

    let mut elf_bss: usize = 0;
    let mut elf_brk: usize = 0;

    info!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in &phdrs {
        info!(
            "phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
        );

        let va = align_down_4k(phdr.p_vaddr as usize);
        let va_end = align_up_4k((phdr.p_vaddr + phdr.p_filesz) as usize);
        mmap::_mmap(
            va + load_bias,
            va_end - va,
            make_prot(phdr.p_flags),
            MAP_FIXED,
            Some(file.clone()),
            phdr.p_offset as usize,
        )?;

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
    elf_bss += load_bias;
    elf_brk += load_bias;

    let sp = get_arg_page(entry, args)?;

    info!("set brk...");
    set_brk(elf_bss, elf_brk);

    padzero(elf_bss);

    info!("start thread...");
    start_thread(task::current().pt_regs_addr(), entry, sp);
    Ok(())
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
        info!("{:#X} < {:#X}", elf_bss, elf_brk);
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

fn load_elf_phdrs(file: FileRef) -> LinuxResult<(Vec<ProgramHeader>, usize)> {
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
    //let mut buf: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    let mut buf: [u8; 2 * 1024] = [0; 2 * 1024];
    info!("phoff: {:#X}", ehdr.e_phoff);
    let _ = file.seek(SeekFrom::Start(phoff));
    file.read(&mut buf)?;
    let phdrs = SegmentTable::new(ehdr.endianness, ehdr.class, &buf[..]);

    let phdrs: Vec<ProgramHeader> = phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD || phdr.p_type == PT_INTERP)
        .collect();
    Ok((phdrs, ehdr.e_entry as usize))
}

pub fn execve(path: &str, argv: usize, envp: usize) -> usize {
    info!("execve: {}", path);

    let mut args = get_user_str_vec(argv);
    assert!(args.len() > 0);
    args[0] = String::from(path);
    for arg in &args {
        info!("arg: {}", arg);
    }
    let envp = get_user_str_vec(envp);
    for env in &envp {
        info!("env: {}", env);
    }
    assert_eq!(envp.len(), 0);

    let mut task = task::current();
    {
        let _ = NoPreempt::new();
        task.as_task_mut().alloc_mm();
    }

    // TODO: Move it into kernel_init().
    let _ = setup_zero_page();

    match bprm_execve(path, 0, 0, args) {
        Ok(_) => info!("bprm_execve ok!"),
        Err(e) => panic!("bprm_execve: {:?}", e),
    }
    0
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
