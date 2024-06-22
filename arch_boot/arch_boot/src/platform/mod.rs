//! Platform-specific operations.

cfg_if::cfg_if! {
if #[cfg(all(target_arch = "riscv64", platform_family = "riscv64-qemu-virt"))] {
    mod riscv64_qemu_virt;
} else if #[cfg(all(target_arch = "x86_64", platform_family = "x86-pc"))] {
    mod x86_pc;
} else if #[cfg(all(target_arch = "aarch64", platform_family = "aarch64-qemu-virt"))] {
    mod aarch64_qemu_virt;
} else if #[cfg(all(target_arch = "loongarch64", platform_family = "loongarch64-qemu-virt"))] {
    mod loongarch64_qemu_virt;
} else {
    mod um;
}
}

/// Fills the `.bss` section with zeros.
#[allow(dead_code)]
pub fn clear_bss() {
    unsafe {
        core::slice::from_raw_parts_mut(_sbss as usize as *mut u8, _ebss as usize - _sbss as usize)
            .fill(0);
    }
}

extern "C" {
    fn _sbss();
    fn _ebss();
}
