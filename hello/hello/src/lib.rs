// #![no_std]
#![cfg_attr(feature = "axstd", no_std)]
// #![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;

// #[cfg(feature = "axstd")]
pub fn say_hello(){
    println!("Hello, world!");
}