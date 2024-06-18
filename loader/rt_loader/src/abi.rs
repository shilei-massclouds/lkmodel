// use std::process::exit;
pub const SYS_HELLO: usize = 1;
pub const SYS_PUTCHAR: usize = 2;
pub const SYS_TERMINATE: usize = 3;

pub static mut ABI_TABLE: [usize; 16] = [0; 16];

fn register_abi(num: usize, handle: usize) {
    unsafe {
        ABI_TABLE[num] = handle;
    }
}

///   注册所有abi
pub fn register_all_abi() {
    register_abi(SYS_HELLO, abi_hello as usize);
    register_abi(SYS_PUTCHAR, abi_putchar as usize);
    register_abi(SYS_TERMINATE, abi_terminate as usize);
}

pub fn abi_hello() {
    println!("[ABI:Hello] Hello, Apps!");
}

pub fn abi_putchar(c: char) {
    print!("{}", c);
   
}

pub fn abi_terminate(code: i32) {
    println!("[ABI:Terminate]!");
    // exit(code);
}
