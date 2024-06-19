use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    // axhal::misc::terminate()
    arch_boot::panic(info)
}
