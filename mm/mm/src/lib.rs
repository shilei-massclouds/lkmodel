#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::OnceCell;
use axfile::fops::File;
use page_table::paging::pgd_alloc;
use page_table::paging::MappingFlags;
use page_table::paging::PageTable;
use page_table::paging::PagingResult;
use axhal::mem::virt_to_phys;
use axtype::PAGE_SIZE;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use spinbase::SpinNoIrq;
use mutex::Mutex;

pub type FileRef = Arc<Mutex<File>>;

static MM_UNIQUE_ID: AtomicUsize = AtomicUsize::new(1);

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 * When changing, update also include/trace/events/mmflags.h
 */
pub const VM_NONE: usize =   0x00000000;
pub const VM_READ: usize =   0x00000001;
pub const VM_WRITE: usize =  0x00000002;
pub const VM_EXEC: usize =   0x00000004;
pub const VM_SHARED: usize = 0x00000008;
pub const VM_MAYREAD : usize = 0x00000010;
pub const VM_MAYWRITE: usize = 0x00000020;
pub const VM_MAYEXEC : usize = 0x00000040;
pub const VM_MAYSHARE: usize = 0x00000080;
pub const VM_GROWSDOWN: usize = 0x00000100;
pub const VM_LOCKED: usize = 0x00002000;
pub const VM_SYNC: usize = 0x00800000;

#[derive(Clone)]
pub struct VmAreaStruct {
    pub vm_start: usize,
    pub vm_end: usize,
    pub vm_pgoff: usize,
    pub vm_file: OnceCell<FileRef>,
    pub vm_flags: usize,
}

impl VmAreaStruct {
    pub fn new(
        vm_start: usize,
        vm_end: usize,
        vm_pgoff: usize,
        vm_file: Option<FileRef>,
        vm_flags: usize,
    ) -> Self {
        let vma = Self {
            vm_start,
            vm_end,
            vm_pgoff,
            vm_file: OnceCell::new(),
            vm_flags,
        };
        if let Some(f) = vm_file {
            let _ = vma.vm_file.set(f);
        }
        vma
    }
}

pub struct MmStruct {
    id: usize,
    pub vmas: BTreeMap<usize, VmAreaStruct>,
    pgd: Arc<SpinNoIrq<PageTable>>,
    brk: usize,

    // Todo: temprarily record mapped (va, pa)
    pub mapped: BTreeMap<usize, usize>,

    /// Pages that have PG_mlocked set
    pub locked_vm: usize,
}

impl MmStruct {
    pub fn new() -> Self {
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas: BTreeMap::new(),
            pgd: Arc::new(SpinNoIrq::new(pgd_alloc())),
            brk: 0,

            // Todo: temprarily record mapped (va, pa)
            mapped: BTreeMap::new(),
            locked_vm: 0,
        }
    }

    pub fn deep_dup(&self) -> Self {
        let mut pgd = pgd_alloc();

        let mut vmas = BTreeMap::new();
        for vma in self.vmas.values() {
            debug!("vma: {:#X} - {:#X}, {:#X}", vma.vm_start, vma.vm_end, vma.vm_pgoff);
            let new_vma = vma.clone();
            vmas.insert(vma.vm_start, new_vma);
        }

        let mut mapped = BTreeMap::<usize, usize>::new();
        for (va, dva) in &self.mapped {
            let va = *va;
            let old_page = *dva;
            debug!("mapped: {:#X} -> {:#X}", va, old_page);
            let new_page: usize = axalloc::global_allocator()
                .alloc_pages(1, PAGE_SIZE) .unwrap();

            unsafe {
                core::ptr::copy_nonoverlapping(
                    old_page as *const u8,
                    new_page as *mut u8,
                    PAGE_SIZE
                );
            }

            let pa = virt_to_phys(new_page.into());

            let flags = MappingFlags::READ | MappingFlags::WRITE |
                MappingFlags::EXECUTE | MappingFlags::USER;
            pgd.map_region(va.into(), pa.into(), PAGE_SIZE, flags, true).unwrap();
            mapped.insert(va, new_page);
        }
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas,
            pgd: Arc::new(SpinNoIrq::new(pgd)),
            brk: self.brk,

            mapped,
            locked_vm: self.locked_vm,
        }
    }

    pub fn pgd(&self) -> Arc<SpinNoIrq<PageTable>> {
        self.pgd.clone()
    }

    pub fn root_paddr(&self) -> usize {
        self.pgd.lock().root_paddr().into()
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    pub fn map_region(&self, va: usize, pa: usize, len: usize, _uflags: usize) -> PagingResult {
        let flags =
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER;
        self.pgd
            .lock()
            .map_region(va.into(), pa.into(), len, flags, true)
    }

    pub fn unmap_region(&self, va: usize, len: usize) -> PagingResult {
        self.pgd.lock().unmap_region(va.into(), len)
    }
}
