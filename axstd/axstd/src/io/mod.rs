//! Traits, helpers, and type definitions for core I/O functionality.

mod stdio;

// pub use axio::prelude;
// pub use axio::{BufRead, BufReader, Error, Read, Seek, SeekFrom, Write};

#[doc(hidden)]
pub use self::stdio::__print_impl;
// pub use self::stdio::{stdin, stdout, Stdin, StdinLock, Stdout, StdoutLock};

