//! Path utility.

use alloc::str::Split;
use alloc::string::String;
use core::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct Path {
    inner: String,
}

impl Path {
    pub fn new(path: &str) -> Self {
        Self {
            inner: String::from(path.trim_end_matches('/')),
        }
    }

    pub fn components(&self) -> Split<'_, char> {
        self.inner.split('/').into_iter()
    }

    pub fn parent(&self) -> Option<&str> {
        let (parent, _) = self.inner.rsplit_once('/')?;
        Some(parent)
    }

    pub fn file_name(&self) -> Option<&str> {
        self.components().next_back()
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{}", self.inner)
    }
}
