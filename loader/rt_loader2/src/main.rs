//! Startup process for monolithic kernel.

#![no_std]
#![no_main]

#[macro_use]
extern crate axlog2;
extern crate alloc;

use axerrno::{LinuxError, LinuxResult};
use axhal::mem::{memory_regions, phys_to_virt};
use axtype::DtbInfo;
use core::sync::atomic::{AtomicUsize, Ordering};
use fork::{user_mode_thread, CloneFlags};
use core::panic::PanicInfo;

#[cfg(feature = "smp")]
mod mp;

static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);

fn is_init_ok() -> bool {
    INITED_CPUS.load(Ordering::Acquire) == axconfig::SMP
}



/// The main entry point for monolithic kernel startup.
#[cfg_attr(not(test), no_mangle)]
pub extern "Rust" fn runtime_main(cpu_id: usize, dtb: usize) {
    init(cpu_id, dtb);
    run(cpu_id, dtb);
    panic!("Never reach here!");
}

pub fn init(cpu_id: usize, dtb: usize) {

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    info!("Logging is enabled.");
    info!(
        "MacroKernel is starting: Primary CPU {} started, dtb = {:#x}.",
        cpu_id, dtb
    );

    axhal::arch_init_early(cpu_id);

    axtrap::early_init();

    

    info!("Initialize global memory allocator...");
    axalloc::init();

    info!("Initialize kernel page table...");
    page_table::init();

    info!("Initialize platform devices...");
    axhal::platform_init();

    info!("Initialize schedule system ...");
    task::init();

    //let all_devices = axdriver::init_drivers();
    //let root_dir = axmount::init(all_devices.block);

    //task::current().fs.lock().init(root_dir);


    axtrap::final_init();

    info!("Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Relaxed);

    while !is_init_ok() {
        core::hint::spin_loop();
    }
}



pub fn run(_cpu_id: usize, dtb: usize) {
    start_kernel(dtb).expect("Fatal error!");
}

fn start_kernel(dtb: usize) -> LinuxResult {
    let dtb_info = setup_arch(dtb)?;
    rest_init(dtb_info);
    Ok(())
}

fn setup_arch(dtb: usize) -> LinuxResult<DtbInfo> {
    parse_dtb(dtb)
}

fn parse_dtb(_dtb_pa: usize) -> LinuxResult<DtbInfo> {
    #[cfg(target_arch = "riscv64")]
    {
        let mut dtb_info = DtbInfo::new();
        use alloc::string::String;
        use alloc::vec::Vec;
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
        let dt = axdtb::DeviceTree::init(dtb_va.into()).unwrap();
        dt.parse(dt.off_struct, 0, 0, &mut cb).unwrap();
        Ok(dtb_info)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        Ok(DtbInfo::new())
    }
}

#[allow(dead_code)]
fn parse_cmdline(cmd: &str, dtb_info: &mut DtbInfo) {
    let cmd = cmd.trim_end_matches(char::from(0));
    if cmd.len() > 0 {
        assert!(cmd.starts_with("init="));

        //info!("cmd:{}",&cmd);
        //cmd:init=/sbin/init
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
    let task = task::current();
    let rq = run_queue::task_rq(&task.sched_info);
    rq.lock().resched(false);
    unimplemented!("schedule_preempt_disabled()");
}

fn cpu_startup_entry() {
    unimplemented!("do idle()");
}

/// Prepare for entering first user app.
fn kernel_init(dtb_info: DtbInfo) {
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

    // TODO: Replace this testcase with a more appropriate x86_64 testcase
    //#[cfg(target_arch = "x86_64")]
    //compile_error!("Remove it after replace a more appropriate x86_64 testcase.");
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
    exec::kernel_execve(init_filename)
}

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    arch_boot::panic(info)
}
