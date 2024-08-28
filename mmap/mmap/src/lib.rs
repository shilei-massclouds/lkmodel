#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;
use axerrno::LinuxResult;
use axfile::fops::File;
use axhal::arch::STACK_TOP;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axio::SeekFrom;
use core::ops::Bound;
use memory_addr::{align_up_4k, align_down_4k, is_aligned_4k, PAGE_SHIFT, PAGE_SIZE_4K};
pub use mm::FileRef;
use mm::VmAreaStruct;
use axerrno::LinuxError;
use axhal::arch::TASK_SIZE;
use mm::{VM_READ, VM_WRITE, VM_EXEC, VM_SHARED, VM_MAYSHARE};
use mm::{VM_MAYREAD, VM_MAYWRITE, VM_MAYEXEC};
use mm::{VM_GROWSDOWN, VM_LOCKED, VM_SYNC};
#[cfg(target_arch = "riscv64")]
use axhal::arch::{EXC_INST_PAGE_FAULT, EXC_LOAD_PAGE_FAULT, EXC_STORE_PAGE_FAULT};
#[cfg(target_arch = "riscv64")]
use signal::force_sig_fault;
use capability::Cap;

/// enforced gap between the expanding stack and other mappings.
const STACK_GUARD_GAP: usize = 256 << PAGE_SHIFT;

pub const PROT_READ: usize = 0x1;
pub const PROT_WRITE: usize = 0x2;
pub const PROT_EXEC: usize = 0x4;
pub const PROT_SEM: usize = 0x8;
pub const PROT_NONE: usize = 0x0;
pub const PROT_GROWSDOWN: usize = 0x01000000;
pub const PROT_GROWSUP: usize = 0x02000000;

/// Mask for type of mapping
const MAP_TYPE: usize = 0x0f;
/// Share changes
pub const MAP_SHARED: usize = 0x01;
/// Changes are private
pub const MAP_PRIVATE: usize = 0x02;
/// share + validate extension flags
const MAP_SHARED_VALIDATE: usize = 0x03;

/// Interpret addr exactly.
pub const MAP_FIXED: usize = 0x10;
/// Don't use a file.
pub const MAP_ANONYMOUS: usize = 0x20;

/// stack-like segment
const MAP_GROWSDOWN: usize = 0x0100;
/// ETXTBSY
const MAP_DENYWRITE: usize = 0x0800;
/// mark it as an executable */
const MAP_EXECUTABLE: usize= 0x1000;
/// pages are locked */
const MAP_LOCKED: usize    = 0x2000;
/// don't check for reservations */
const MAP_NORESERVE: usize = 0x4000;
/// perform synchronous page faults for the mapping
const MAP_SYNC: usize = 0x080000;

const MAP_32BIT: usize = 0;
const MAP_HUGE_2MB: usize = 0;
const MAP_HUGE_1GB: usize = 0;

/* 0x0100 - 0x4000 flags are defined in asm-generic/mman.h */
/// populate (prefault) pagetables
const MAP_POPULATE: usize = 0x008000;
/// do not block on IO
const MAP_NONBLOCK: usize = 0x010000;
/// give out an address that is best suited for process/thread stacks
const MAP_STACK: usize =    0x020000;
/// create a huge page mapping
const MAP_HUGETLB: usize =  0x040000;
/// perform synchronous page faults for the mapping
//const MAP_SYNC: usize =     0x080000;

/// MAP_FIXED which doesn't unmap underlying mapping
pub const MAP_FIXED_NOREPLACE: usize = 0x100000;

/// For anonymous mmap, memory could be uninitialized
const MAP_UNINITIALIZED: usize = 0x4000000;

pub const VM_FAULT_OOM:     usize = 0x000001;
pub const VM_FAULT_SIGBUS:  usize = 0x000002;
pub const VM_FAULT_HWPOISON:usize = 0x000010;
pub const VM_FAULT_HWPOISON_LARGE: usize = 0x000020;
pub const VM_FAULT_SIGSEGV: usize = 0x000040;
pub const VM_FAULT_FALLBACK:usize = 0x000800;

pub const VM_FAULT_ERROR: usize =
    VM_FAULT_OOM | VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |
    VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK;

const LEGACY_MAP_MASK: usize =
    MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE |
    MAP_EXECUTABLE | MAP_UNINITIALIZED | MAP_GROWSDOWN | MAP_LOCKED | MAP_NORESERVE |
    MAP_POPULATE | MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_32BIT |
    MAP_HUGE_2MB | MAP_HUGE_1GB;

pub fn mmap(
    va: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> LinuxResult<usize> {
    if (flags & MAP_ANONYMOUS) == 0 {
        if fd == usize::MAX {
            return Err(LinuxError::EBADF);
        }
    }
    if len == 0 {
        return Err(LinuxError::EINVAL);
    }
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = if (flags & MAP_ANONYMOUS) != 0 {
        None
    } else {
        if (flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE {
            // Todo: flags_mask also includes file->f_op->mmap_supported_flags
            let flags_mask = LEGACY_MAP_MASK;
            if (flags & !flags_mask) != 0 {
                return Err(LinuxError::EOPNOTSUPP);
            }
        }
        let f = filetable.get_file(fd);
        check_file_mode(flags, prot, f.clone())?;
        f
    };
    let va = _mmap(va, len, prot, flags, file, offset)?;

    if (flags & MAP_POPULATE) != 0 {
        assert!(is_aligned_4k(va));
        assert!(is_aligned_4k(len));
        error!("MAP_POPULATE");
        let mut pos = 0;
        while pos < len {
            let _ = faultin_page(va + pos, 0);
            pos += PAGE_SIZE_4K;
        }
    }
    Ok(va)
}

fn check_file_mode(flags: usize, prot: usize, file: Option<FileRef>) -> LinuxResult {
    let cap = file.unwrap().lock().get_cap();
    let mut flags = flags & MAP_TYPE;
    if flags == MAP_SHARED {
        /*
         * Force use of MAP_SHARED_VALIDATE with non-legacy
         * flags. E.g. MAP_SYNC is dangerous to use with
         * MAP_SHARED as you don't know which consistency model
         * you will get. We silently ignore unsupported flags
         * with MAP_SHARED to preserve backward compatibility.
         */
        flags &= LEGACY_MAP_MASK;
    }
    if flags == MAP_SHARED_VALIDATE {
        if (prot & PROT_WRITE) != 0 {
            if !cap.contains(Cap::WRITE) {
                return Err(LinuxError::EACCES);
            }
        }
    }
    if flags == MAP_PRIVATE || flags == MAP_SHARED || flags == MAP_SHARED_VALIDATE {
        if !cap.contains(Cap::READ) {
            return Err(LinuxError::EACCES);
        }
    } else {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub fn _mmap(
    mut va: usize,
    mut len: usize,
    prot: usize,
    mut flags: usize,
    file: Option<FileRef>,
    offset: usize,
) -> LinuxResult<usize> {
    assert!(is_aligned_4k(va));
    len = align_up_4k(len);
    debug!("mmap va {:#X} offset {:#X} flags {:#X} prot {:#X}", va, offset, flags, prot);

    /* force arch specific MAP_FIXED handling in get_unmapped_area */
    if (flags & MAP_FIXED_NOREPLACE) != 0 {
        flags |= MAP_FIXED;
    }

    if (flags & MAP_FIXED) == 0 {
        va = get_unmapped_vma(va, len);
        debug!("Get unmapped vma {:#X}", va);
    }

    if va > TASK_SIZE - len {
        return Err(LinuxError::ENOMEM);
    }

    let mm = task::current().mm();
    if let Some(mut overlap) = find_overlap(va, len) {
        debug!("find overlap {:#X}-{:#X}", overlap.vm_start, overlap.vm_end);
        assert!(
            overlap.vm_start <= va && va + len <= overlap.vm_end,
            "{:#X}-{:#X}; overlap {:#X}-{:#X}",
            va,
            va + len,
            overlap.vm_start,
            overlap.vm_end
        );

        if (flags & MAP_FIXED_NOREPLACE) != 0 {
            return Err(LinuxError::EEXIST);
        }

        if va + len < overlap.vm_end {
            let bias = (va + len - overlap.vm_start) >> PAGE_SHIFT;
            let mut new = overlap.clone();
            new.vm_start = va + len;
            new.vm_pgoff += bias;
            mm.lock().vmas.insert(va + len, new);
        }
        if va > overlap.vm_start {
            overlap.vm_end = va;
            mm.lock().vmas.insert(overlap.vm_start, overlap);
        }
    }

    let mut vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags)
        | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

    if (flags & MAP_SHARED) != 0 {
        vm_flags |= VM_SHARED | VM_MAYSHARE;
    }
    debug!(
        "mmap region: {:#X} - {:#X}, vm_flags: {:#X}, prot {:#X}",
        va,
        va + len,
        vm_flags,
        prot
    );
    let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, file, vm_flags);
    mm.lock().vmas.insert(va, vma);

    if (flags & MAP_LOCKED) != 0 {
        mm.lock().locked_vm = len >> PAGE_SHIFT;
    }

    Ok(va)
}

/*
 * Combine the mmap "prot" argument into "vm_flags" used internally.
 */
fn calc_vm_prot_bits(prot: usize) -> usize {
    let mut flags = 0;
    if (prot & PROT_READ) != 0 {
        flags |= VM_READ;
    }
    if (prot & PROT_WRITE) != 0 {
        flags |= VM_WRITE;
    }
    if (prot & PROT_EXEC) != 0 {
        flags |= VM_EXEC;
    }
    flags
}

/*
 * Combine the mmap "flags" argument into "vm_flags" used internally.
 */
fn calc_vm_flag_bits(flags: usize) -> usize {
    let mut vm_flags = 0;
    if (flags & MAP_GROWSDOWN) != 0 {
        vm_flags |= VM_GROWSDOWN;
    }
    if (flags & MAP_LOCKED) != 0 {
        vm_flags |= VM_LOCKED;
    }
    if (flags & MAP_SYNC) != 0 {
        vm_flags |= VM_SYNC;
    }
    vm_flags
}

fn find_overlap(va: usize, len: usize) -> Option<VmAreaStruct> {
    debug!("find_overlap: va {:#X} len {:#X}", va, len);

    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let ret = locked_mm.vmas.iter().find(|(_, vma)| {
        in_vma(va, va + len, vma) || in_range(vma.vm_start, vma.vm_end, va, va + len)
    });

    if let Some((key, _)) = ret {
        warn!("### Removed!!!");
        mm.lock().vmas.remove(&key)
    } else {
        None
    }
}

#[inline]
const fn in_range(start: usize, end: usize, r_start: usize, r_end: usize) -> bool {
    (start >= r_start && start < r_end) || (end > r_start && end <= r_end)
}

#[inline]
const fn in_vma(start: usize, end: usize, vma: &VmAreaStruct) -> bool {
    in_range(start, end, vma.vm_start, vma.vm_end)
}

fn mmap_base() -> usize {
    const MIN_GAP: usize = 0x800_0000; // SZ_128M
    STACK_TOP - MIN_GAP
}

pub fn get_unmapped_vma(_va: usize, len: usize) -> usize {
    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let mut gap_end = mmap_base();
    for (_, vma) in locked_mm.vmas.iter().rev() {
        debug!(
            "get_unmapped_vma iterator: {:#X} {:#X} {:#X}",
            vma.vm_start, vma.vm_end, gap_end
        );
        if vma.vm_end > gap_end {
            continue;
        }
        if gap_end - vma.vm_end >= len {
            debug!(
                "get_unmapped_vma: {:#X} {:#X} {:#X}",
                vma.vm_start, vma.vm_end, gap_end - len
            );
            return gap_end - len;
        }
        gap_end = vma.vm_start;
    }

    if gap_end >= len {
        debug!("get_unmapped_vma: {:#X}", gap_end - len);
        return gap_end - len;
    }
    unimplemented!("NO available unmapped vma!");
}

// invalid permissions for mapped object
#[cfg(target_arch = "riscv64")]
const SEGV_ACCERR: usize = 2;

pub fn faultin_page(va: usize, cause: usize) -> Result<usize, usize> {
    let va = align_down_4k(va);
    info!("--------- faultin_page... va {:#X} cause {}", va, cause);
    let mm = task::current().mm();
    let mut locked_mm = mm.lock();
    if locked_mm.mapped.get(&va).is_some() {
        warn!("============== find page {:#X} already exists!", va);
        return Ok(0);
    }

    let cursor = locked_mm.vmas.upper_bound(Bound::Included(&va));
    let mut vma = cursor.value().unwrap();
    if va < vma.vm_start || va >= vma.vm_end {
        let (_, next_vma) = cursor.peek_next().unwrap();
        debug!("{:#X} - {:#X}; {:#x} pgoff {:#x}",
            next_vma.vm_start, next_vma.vm_end, next_vma.vm_flags, next_vma.vm_pgoff);

        if (next_vma.vm_flags & VM_GROWSDOWN) != 0 {
            // Todo: wrap these into a function 'expand_stack'
            assert!(next_vma.vm_file.get().is_none());
            assert_eq!(next_vma.vm_pgoff, 0);

            // Check that both stack segments have the same anon_vma?
            if (vma.vm_flags & VM_GROWSDOWN) == 0 {
                if va - vma.vm_end < STACK_GUARD_GAP {
                    error!("SEGV_ACCERR");
                    let tid = task::current().tid();
                    force_sig_fault(tid, task::SIGSEGV, SEGV_ACCERR, va);
                    return Err(usize::MAX);
                }
            }

            let stack = VmAreaStruct::new(va, next_vma.vm_start, 0, None, next_vma.vm_flags);
            locked_mm.vmas.insert(va, stack);
            vma = locked_mm.vmas.get(&va).unwrap();
        }
    }
    assert!(
        va >= vma.vm_start && va < vma.vm_end,
        "va {:#X} in {:#X} - {:#X}",
        va,
        vma.vm_start,
        vma.vm_end
    );

    #[cfg(target_arch = "riscv64")]
    {
        if access_error(cause, vma) {
            error!("SEGV_ACCERR");
            let tid = task::current().tid();
            force_sig_fault(tid, task::SIGSEGV, SEGV_ACCERR, va);
            return Err(usize::MAX);
        }
    }

    let delta = va - vma.vm_start;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    if let Some(f) = vma.vm_file.get() {
        let f = f.lock();
        if f.get_attr().unwrap().is_file() {
            let f_size = f.get_attr().unwrap().size() as usize;
            if offset >= f_size {
                debug!("offset {} >= f_size {}", offset, f_size);
                return Err(VM_FAULT_SIGBUS);
            }
        }
    }

    if (vma.vm_flags & VM_SHARED) != 0 {
        assert!(vma.vm_file.get().is_some());
        let f = vma.vm_file.get().unwrap().clone();
        let f = f.lock();
        if let Some(pa) = f.shared_map.get(&offset) {
            locked_mm.map_region(va, *pa, PAGE_SIZE_4K, 1)
                .unwrap_or_else(|e| { panic!("{:?}", e) });

            return Ok(phys_to_virt((*pa).into()).into());
        }
    }

    let direct_va: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .unwrap();

    // Todo: check whether we need to zero it.
    let buf = unsafe { core::slice::from_raw_parts_mut(direct_va as *mut u8, PAGE_SIZE_4K) };
    buf.fill(0);

    let pa = virt_to_phys(direct_va.into()).into();

    if vma.vm_file.get().is_some() {
        let f = vma.vm_file.get().unwrap().clone();
        fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
        if (vma.vm_flags & VM_SHARED) != 0 {
            f.lock().shared_map.insert(offset, pa);
        }
    }
    locked_mm.map_region(va, pa, PAGE_SIZE_4K, 1)
        .unwrap_or_else(|e| { panic!("{:?}", e) });

    if (vma.vm_flags & VM_SHARED) == 0 {
        // Todo: temporarily record mapped va->pa(direct_va)
        locked_mm.mapped.insert(va, direct_va);
    }

    Ok(phys_to_virt(pa.into()).into())
}

#[cfg(target_arch = "riscv64")]
fn access_error(cause: usize, vma: &VmAreaStruct) -> bool {
    // Todo: consider that the cause can be ZERO?!
    if cause == 0 {
        return false;
    }
    debug!("cause {} flags {:#X}", cause, vma.vm_flags);
    match cause {
        EXC_INST_PAGE_FAULT => {
            (vma.vm_flags & VM_EXEC) == 0
        },
        EXC_LOAD_PAGE_FAULT => {
            // Write implies read
            (vma.vm_flags & (VM_READ | VM_WRITE)) == 0
        },
        EXC_STORE_PAGE_FAULT => {
            (vma.vm_flags & VM_WRITE) == 0
        },
        _ => {
            panic!("Unhandled cause {}", cause);
        }
    }
}

fn fill_cache(pa: usize, len: usize, file: &mut File, offset: usize) {
    let offset = align_down_4k(offset);
    let va = phys_to_virt(pa.into()).as_usize();
    let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };

    debug!("fill_cache: offset {:#X} len {:#X}", offset, len);
    let _ = file.seek(SeekFrom::Start(offset as u64));

    let mut pos = 0;
    while pos < len {
        let ret = file.read(&mut buf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    buf[pos..].fill(0);
}

pub fn set_brk(va: usize) -> usize {
    // Have a guard for mm to lock this whole function,
    // because mm.brk() and mm.set_brk() should be in a atomic context.
    let mm = task::current().mm();
    let brk = mm.lock().brk();

    assert!(is_aligned_4k(brk));
    debug!("brk!!! {:#x}, {:#x}", va, brk);

    if va == 0 {
        brk
    } else {
        assert!(va > brk);
        let offset = va - brk;
        assert!(is_aligned_4k(offset));
        _mmap(brk, offset, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS, None, 0).unwrap();
        // Todo: set proper cause for faultin_page.
        let _ = faultin_page(brk, 0 /* cause */);
        mm.lock().set_brk(va);
        va
    }
}

pub fn msync(va: usize, len: usize, flags: usize) -> usize {
    debug!("msync: va {:#X} len {:#X} flags {:#X}", va, len, flags);

    let mm = task::current().mm();
    let locked_mm = mm.lock();

    let vma = locked_mm
        .vmas
        .upper_bound(Bound::Included(&va))
        .value()
        .unwrap();
    assert!(
        va >= vma.vm_start && va + len <= vma.vm_end,
        "va {:#X} in {:#X} - {:#X}",
        va,
        vma.vm_start,
        vma.vm_end
    );
    debug!("msync: {:#X} - {:#X}", va, va + len);

    let delta = va - vma.vm_start;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    if vma.vm_file.get().is_some() {
        let file = vma.vm_file.get().unwrap().clone();
        sync_file(va, len, &mut file.lock(), offset);
    }
    0
}

fn sync_file(va: usize, mut len: usize, file: &mut File, offset: usize) {
    let f_size = file.get_attr().unwrap().size() as usize;
    if len > f_size {
        // msync: length of msync cannot overflow the original file size.
        // LTP - mmap01
        len = f_size;
    }
    let buf = unsafe { core::slice::from_raw_parts(va as *const u8, len) };
    let _ = file.seek(SeekFrom::Start(offset as u64));

    let mut pos = 0;
    while pos < len {
        let ret = file.write(&buf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    debug!("msync: ok!");
}

pub fn munmap(va: usize, mut len: usize) -> usize {
    assert!(is_aligned_4k(va));
    len = align_up_4k(len);
    debug!("munmap {:#X} - {:#X}", va, va + len);

    while let Some(mut overlap) = find_overlap(va, len) {
        debug!("find overlap {:#X}-{:#X}", overlap.vm_start, overlap.vm_end);
        if va <= overlap.vm_start && overlap.vm_end <= va + len {
            let len = overlap.vm_end - overlap.vm_start;
            let _ = remove_region(overlap.vm_start, len);
            continue;
        }

        assert!(
            overlap.vm_start <= va && va + len <= overlap.vm_end,
            "{:#X}-{:#X}; overlap {:#X}-{:#X}",
            va,
            va + len,
            overlap.vm_start,
            overlap.vm_end
        );

        if va + len < overlap.vm_end {
            let bias = (va + len - overlap.vm_start) >> PAGE_SHIFT;
            let mut new = overlap.clone();
            new.vm_start = va + len;
            new.vm_pgoff += bias;
            let mm = task::current().mm();
            mm.lock().vmas.insert(va + len, new);
        }
        if va > overlap.vm_start {
            overlap.vm_end = va;
            let mm = task::current().mm();
            mm.lock().vmas.insert(overlap.vm_start, overlap);
        }
        let _ = remove_region(va, len);
    }

    0
}

fn remove_region(va: usize, len: usize) -> usize {
    let mm = task::current().mm();
    let mut locked_mm = mm.lock();
    // Todo: handle temporary mmaped.
    locked_mm.mapped.remove(&va);
    match locked_mm.unmap_region(va, len) {
        Ok(_) => 0,
        Err(e) => {
            warn!("unmap region err: {:#?}", e);
            0
        },
    }
}

pub fn mprotect(va: usize, len: usize, prot: usize) -> usize {
    info!("mprotect: va {:#X} len {:#X} prot {:#X}", va, len, prot);
    assert!(is_aligned_4k(va));

    let mut vma;
    let mm = task::current().mm();
    if let Some(mut overlap) = find_overlap(va, len) {
        debug!("find overlap {:#X}-{:#X}", overlap.vm_start, overlap.vm_end);
        assert!(
            overlap.vm_start <= va && va + len <= overlap.vm_end,
            "{:#X}-{:#X}; overlap {:#X}-{:#X} vm_flags {:#X} vm_offset {:#X}",
            va,
            va + len,
            overlap.vm_start,
            overlap.vm_end,
            overlap.vm_flags,
            overlap.vm_pgoff,
        );
        vma = overlap.clone();
        vma.vm_start = va;
        vma.vm_end = va + len;
        vma.vm_pgoff += (va - overlap.vm_start) >> PAGE_SHIFT;

        if va + len < overlap.vm_end {
            let bias = (va + len - overlap.vm_start) >> PAGE_SHIFT;
            let mut new = overlap.clone();
            new.vm_start = va + len;
            new.vm_pgoff += bias;
            mm.lock().vmas.insert(va + len, new);
        }
        if va > overlap.vm_start {
            overlap.vm_end = va;
            mm.lock().vmas.insert(overlap.vm_start, overlap);
        }
    } else {
        panic!("No such vma!");
    }

    /*
     * Each mprotect() call explicitly passes r/w/x permissions.
     * If a permission is not passed to mprotect(), it must be
     * cleared from the VMA.
     */
    let mask_off = VM_READ | VM_WRITE | VM_EXEC;
    let newflags = calc_vm_prot_bits(prot) | (vma.vm_flags & !mask_off);

    vma.vm_flags = newflags;
    mm.lock().vmas.insert(va, vma);
    info!("mprotect: newflags {:#X}", newflags);
    0
}
