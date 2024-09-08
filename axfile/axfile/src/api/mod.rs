//! [`std::fs`]-like high-level filesystem manipulation operations.

mod dir;
mod file;

pub use self::dir::{DirBuilder, DirEntry, ReadDir};
pub use self::file::{File, FileType, Metadata, OpenOptions, Permissions};

use alloc::{string::String, vec::Vec};
use axio::{self as io, prelude::*};
use fstree::FsStruct;

/// Returns an iterator over the entries within a directory.
pub fn read_dir<'a>(path: &'a str, fs: &'a FsStruct) -> io::Result<ReadDir<'a>> {
    ReadDir::new(path, fs)
}

/// Returns the canonical, absolute form of a path with all intermediate
/// components normalized.
pub fn canonicalize(path: &str, fs: &FsStruct) -> io::Result<String> {
    fs.absolute_path(path)
}

/// Returns the current working directory as a [`String`].
pub fn current_dir(fs: &FsStruct) -> io::Result<String> {
    fs.current_dir()
}

/// Changes the current working directory to the specified path.
pub fn set_current_dir(path: &str, fs: &mut FsStruct) -> io::Result<()> {
    fs.set_current_dir(path)
}

/// Read the entire contents of a file into a bytes vector.
pub fn read(path: &str, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<Vec<u8>> {
    let mut file = File::open(path, fs, uid, gid)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read the entire contents of a file into a string.
pub fn read_to_string(path: &str, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<String> {
    let mut file = File::open(path, fs, uid, gid)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut string = String::with_capacity(size as usize);
    file.read_to_string(&mut string)?;
    Ok(string)
}

/// Write a slice as the entire contents of a file.
pub fn write<C: AsRef<[u8]>>(path: &str, contents: C, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<()> {
    File::create(path, fs, uid, gid)?.write_all(contents.as_ref())
}

/// Given a path, query the file system to get information about a file,
/// directory, etc.
pub fn metadata(path: &str, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<Metadata> {
    File::open(path, fs, uid, gid)?.metadata()
}

/// Creates a new, empty directory at the provided path.
pub fn create_dir(path: &str, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<()> {
    DirBuilder::new().create(path, fs, uid, gid)
}

/// Recursively create a directory and all of its parent components if they
/// are missing.
pub fn create_dir_all(path: &str, fs: &FsStruct, uid: u32, gid: u32) -> io::Result<()> {
    DirBuilder::new().recursive(true).create(path, fs, uid, gid)
}

/// Removes an empty directory.
pub fn remove_dir(path: &str, fs: &FsStruct) -> io::Result<()> {
    fs.remove_dir(None, path)
}

/// Removes a file from the filesystem.
pub fn remove_file(path: &str, fs: &FsStruct) -> io::Result<()> {
    fs.remove_file(None, path)
}

/// Rename a file or directory to a new name.
/// Delete the original file if `old` already exists.
///
/// This only works then the new path is in the same mounted fs.
pub fn rename(old: &str, new: &str, fs: &FsStruct) -> io::Result<()> {
    fs.rename(old, new)
}
