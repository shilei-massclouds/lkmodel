
#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(doc_cfg)]
#![feature(doc_auto_cfg)]

#[macro_use]
mod macros;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
#[doc(no_inline)]
pub use alloc::{boxed, collections, format, string, vec};

#[doc(no_inline)]
pub use core::{arch, cell, cmp, hint, marker, mem, ops, ptr, slice, str};

pub use axruntime::runtime_main;

pub mod io;
pub mod vm;