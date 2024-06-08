#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::axlog2::__print_impl(format_args!($($arg)*));
    }
}

/// Prints to the standard output, with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {
        $crate::axlog2::__print_impl(format_args!("{}\n", format_args!($($arg)*)));
    }
}
