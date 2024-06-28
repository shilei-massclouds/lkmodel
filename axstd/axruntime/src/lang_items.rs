use core::panic::PanicInfo;
use axlog::error;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}