//! Startup process for monolithic kernel.

#![no_std]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use alloc::{vec, vec::Vec};
use alloc::string::String;

use axerrno::{LinuxError, LinuxResult};
#[cfg(target_arch = "riscv64")]
use axhal::mem::phys_to_virt;
use axtype::DtbInfo;
use fork::{user_mode_thread, CloneFlags};

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init();
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);
    fileops::init(cpu_id, dtb_pa);
}

/// start_kernel
pub fn start(_cpu_id: usize, dtb: usize) {
    let dtb_info = setup_arch(dtb);
    rest_init(dtb_info);
}

fn setup_arch(dtb: usize) -> DtbInfo {
    parse_dtb(dtb)
}

fn parse_dtb(_dtb_pa: usize) -> DtbInfo {
    #[cfg(target_arch = "riscv64")]
    {
        let mut dtb_info = DtbInfo::new();
        let mut cb = |name: String,
                      _addr_cells: usize,
                      _size_cells: usize,
                      props: Vec<(String, Vec<u8>)>| {
            if name == "chosen" {
                for prop in props {
                    match prop.0.as_str() {
                        "bootargs" => {
                            if let Ok(cmd) = core::str::from_utf8(&prop.1) {
                                parse_cmdline(cmd, &mut dtb_info);
                            }
                        }
                        _ => (),
                    }
                }
            }
        };

        let dtb_va = phys_to_virt(_dtb_pa.into());
        axdtb::parse(dtb_va.into(), &mut cb);
        dtb_info
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        DtbInfo::new()
    }
}

#[allow(dead_code)]
fn parse_cmdline(cmd: &str, dtb_info: &mut DtbInfo) {
    let cmd = cmd.trim_end_matches(char::from(0));
    if cmd.len() > 0 {
        assert!(cmd.starts_with("init="));
        let cmd = cmd.strip_prefix("init=").unwrap();
        dtb_info.set_init_cmd(cmd);
    }
}

fn rest_init(dtb_info: DtbInfo) {
    info!("rest_init ...");
    let tid = user_mode_thread(
        move || {
            kernel_init(dtb_info);
        },
        CloneFlags::CLONE_FS,
    );
    assert_eq!(tid, 1);

    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();
    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(/* CPUHP_ONLINE */);
}

fn schedule_preempt_disabled() {
    task::yield_now();
}

fn cpu_startup_entry() {
    loop {
        task::yield_now();
    }
}

/// Prepare for entering first user app.
fn kernel_init(dtb_info: DtbInfo) {
    let _ = kernel_init_freeable();

    /*
     * We try each of these until one succeeds.
     *
     * The Bourne shell can be used instead of init if we are
     * trying to recover a really broken machine.
     */
    if let Some(cmd) = dtb_info.get_init_cmd() {
        run_init_process(cmd).unwrap_or_else(|_| panic!("Requested init {} failed.", cmd));
        return;
    }

    // Todo: for x86_64, we don't know how to get cmdline
    // from qemu arg '-append="XX"'.
    // Just use environment.
    let init_cmd = env!("AX_INIT_CMD");
    if init_cmd.len() > 0 {
        info!("init_cmd: {}", init_cmd);
        run_init_process(init_cmd).unwrap_or_else(|_| panic!("Requested init {} failed.", init_cmd));
        return;
    }

    try_to_run_init_process("/sbin/init").expect("No working init found.");
}

fn try_to_run_init_process(init_filename: &str) -> LinuxResult {
    run_init_process(init_filename).inspect_err(|e| {
        if e != &LinuxError::ENOENT {
            error!(
                "Starting init: {} exists but couldn't execute it (error {})",
                init_filename, e
            );
        }
    })
}

fn run_init_process(init_filename: &str) -> LinuxResult {
    info!("run_init_process...");

    let argv_init: Vec<String> = vec![init_filename.into()];
    let envp_init: Vec<String> = vec![
        "HOME=/".into(), "TERM=linux".into(),
    ];

    exec::kernel_execve(init_filename, argv_init, envp_init)?;
    Ok(())
}

fn kernel_init_freeable() -> LinuxResult {
    fileops::console_on_rootfs()?;
    fileops::loop_init()
}
