use axfs_vfs::{VfsNodeType, VfsResult, VfsOps};
use axfs_ramfs::RamFileSystem;

const BUFSIZ: usize = axtype::PAGE_SIZE;

pub fn test_write() {
    info!("==============> cycle write test ...");
    cycle_write().unwrap();
    info!("==============> cycle write test ok!");
}

fn cycle_write() -> VfsResult {
    let ramfs = RamFileSystem::new();
    let root = ramfs.root_dir();
    root.create("test_file", VfsNodeType::File).unwrap();
    let node = root.lookup("test_file")?;
    assert_eq!(node.get_attr()?.file_type(), VfsNodeType::File);

    let buf: [u8; BUFSIZ] = [0; BUFSIZ];
    let mut offset = 0;
    let mut len = BUFSIZ;
    while len > 0 {
        info!("[{}]: ...", len);
        assert_eq!(node.write_at(offset, &buf[..len])?, len);
        offset += len as u64;
        len -= 1;
    }
    Ok(())
}
