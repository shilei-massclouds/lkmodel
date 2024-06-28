#![no_std]
#![no_main]

extern crate core;

use core::{panic::PanicInfo, ptr::write};
use axstd::println;
struct SimpleStack {
    sp: usize,
    base: usize,
    size: usize,
}

impl SimpleStack {

    pub fn new(base: usize, size: usize) -> SimpleStack {
        SimpleStack { sp: base + size, base, size }
    }


    pub fn push<T>(&mut self, value: T) -> usize {
        let size = core::mem::size_of::<T>();
        self.sp = align_down(self.sp - size, core::mem::align_of::<T>());
        assert!(self.sp >= self.base, "Stack overflow");
        unsafe {
            let ptr = self.sp as *mut T;
            ptr.write(value);
        }
        self.sp
    }


    pub fn push_str(&mut self, s: &str) -> usize {
        self.push(0u8);
        let str_bytes = s.as_bytes();
        for &b in str_bytes.iter().rev() {
            self.push(b);
        } // Null terminator
        self.sp
    }


    pub fn get_sp(&self) -> usize {
        self.sp
    }
}

fn align_down(addr: usize, align: usize) -> usize {
    (addr / align) * align
}

pub fn setup_stack(base: usize, size: usize, args: &[&str], env: &[&str]) -> usize {
    let mut stack = SimpleStack::new(base, size);


    stack.push::<usize>(0);
    let mut env_ptrs = [0usize; 10]; //最多 10 个环境变量
    for (i, &var) in env.iter().enumerate() {
        if( var == "" ){
            break;
        }
        let ptr = stack.push_str(var);
        env_ptrs[i] = ptr;
    }



    stack.push::<usize>(0);
    let mut arg_ptrs = [0usize; 10]; // 最多 10 个参数
    for (i, &arg) in args.iter().enumerate() {
        if( arg == "" ){
            break;
        }
        let ptr = stack.push_str(arg);
        arg_ptrs[i] = ptr;
    }


    stack.push::<usize>(0);
    for i in 0..10{
        if( env_ptrs[9-i] == 0 ){
            continue;
        }
        stack.push(env_ptrs[9-i]);
    }


    stack.push::<usize>(0);
    for i in 0..10{
        if( arg_ptrs[9-i] == 0 ){
            continue;
        }
        stack.push(arg_ptrs[9-i]);
    }
    stack.push(args.len());

    // 返回新的栈指针
    stack.get_sp()
}