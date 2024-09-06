use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult};

/// A console device behaves like `/dev/console`.
///
/// It always returns a chunk of `\0` bytes when read, and all writes are discarded.
pub struct ConsoleDev;

impl VfsNodeOps for ConsoleDev {
    fn get_ino(&self) -> usize {
        0
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new(
            VfsNodePerm::default_file(),
            VfsNodeType::CharDevice,
            0,
            0,
        ))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        assert!(buf.len() > 0);

        // try until we got something
        let mut index = 0;
        while index < buf.len() {
            if let Some(c) = axhal::console::getchar() {
                let c = if c == b'\r' { b'\n' } else { c };
                axhal::console::putchar(c);
                buf[index] = c;
                index += 1;
                if c == b'\n' {
                    break;
                }
            } else {
                run_queue::yield_now();
            }
        }
        Ok(index)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        axhal::console::write_bytes(buf);
        Ok(buf.len())
    }

    fn truncate(&self, _size: u64) -> VfsResult {
        Ok(())
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}
