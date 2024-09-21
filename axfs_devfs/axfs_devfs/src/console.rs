use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult};

/// A console device behaves like `/dev/console`.
///
/// It always returns a chunk of `\0` bytes when read, and all writes are discarded.
pub struct ConsoleDev;

// IOCTL
const TCGETS: usize = 0x5401;

const NCCS: usize = 19;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
struct Termios {
    c_iflag: u32,     /* input mode flags */
    c_oflag: u32,     /* output mode flags */
    c_cflag: u32,     /* control mode flags */
    c_lflag: u32,     /* local mode flags */
    c_line: u8,       /* line discipline */
    c_cc: [u8; NCCS], /* control characters */
}

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

    fn ioctl(&self, req: usize, data: usize) -> VfsResult<usize> {
        assert_eq!(req, TCGETS);
        let cc: [u8; NCCS] = [
            0x3, 0x1c, 0x7f, 0x15, 0x4, 0x0, 0x1, 0x0, 0x11, 0x13, 0x1a, 0x0, 0x12, 0xf, 0x17, 0x16,
            0x0, 0x0, 0x0,
        ];

        let ubuf = data as *mut Termios;
        unsafe {
            *ubuf = Termios {
                c_iflag: 0x500,
                c_oflag: 0x5,
                c_cflag: 0xcbd,
                c_lflag: 0x8a3b,
                c_line: 0,
                c_cc: cc,
            };
        }
        Ok(0)
    }

    axfs_vfs::impl_vfs_non_dir_default! {}
}
