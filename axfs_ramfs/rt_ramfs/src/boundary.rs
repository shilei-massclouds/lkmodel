extern crate alloc;
use alloc::sync::Arc;
use axfs_vfs::{VfsNodeType, VfsResult, VfsOps, VfsNodeOps};
use axfs_ramfs::RamFileSystem;
use axtype::PAGE_SIZE;

const BUF_SIZE: usize = 32;

pub fn test_boundary() -> VfsResult {
    info!("==============> boundary test ...");

    let ramfs = RamFileSystem::new(0, 0);
    let root = ramfs.root_dir();
    root.create("testfile", VfsNodeType::File, 0, 0).unwrap();
    let node = root.lookup("testfile")?;

    write_buf(1, node.clone())?;
    write_buf(3, node.clone())?;
    write_buf(5, node.clone())?;

    read_buf(1, 1, node.clone())?;
    read_buf(3, 3, node.clone())?;
    read_buf(5, 5, node.clone())?;

    read_buf(0, 0, node.clone())?;
    read_buf(2, 0, node.clone())?;
    read_buf(4, 0, node.clone())?;

    node.truncate(7 * PAGE_SIZE as u64)?;
    assert_eq!(node.get_attr()?.size(), 7 * PAGE_SIZE as u64);

    read_buf(6, 0, node.clone())?;

    node.truncate(3 * PAGE_SIZE as u64)?;
    assert_eq!(node.get_attr()?.size(), 3 * PAGE_SIZE as u64);

    read_buf(1, 1, node.clone())?;

    info!("==============> boundary test ok!");
    Ok(())
}

fn write_buf(index: usize, node: Arc<dyn VfsNodeOps>) -> VfsResult {
    let wbuf: [u8; BUF_SIZE] = [index as u8; BUF_SIZE];
    let pos = index*PAGE_SIZE - BUF_SIZE/2;
    assert_eq!(node.write_at(pos as u64, &wbuf)?, BUF_SIZE);
    Ok(())
}

fn read_buf(index: usize, expected: usize, node: Arc<dyn VfsNodeOps>) -> VfsResult {
    let mut rbuf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
    let pos = index*PAGE_SIZE - BUF_SIZE/2;
    assert_eq!(node.read_at(pos as u64, &mut rbuf)?, BUF_SIZE);
    assert_eq!(rbuf, [expected as u8; BUF_SIZE]);
    Ok(())
}
