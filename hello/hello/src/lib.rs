#![cfg_attr(feature = "axstd", no_std)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;


pub fn say_hello(){
    println!("Hello, world!");
}