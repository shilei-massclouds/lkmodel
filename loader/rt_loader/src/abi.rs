// use std::io::{stdout, Write};
pub const SYS_HELLO: usize = 1;

pub static mut ABI_TABLE: [usize; 16] = [0; 16];

fn register_abi(num: usize, handle: usize) {
    unsafe {
        ABI_TABLE[num] = handle;
    }
}

///   注册所有abi
pub fn register_all_abi() {
    register_abi(SYS_HELLO, abi_hello as usize);
}

pub fn abi_hello() {
    // let _= stdout().write_all(b"[ABI:Hello] Hello, Apps!\n");
    println!("[ABI:Hello] Hello, Apps!")
}


