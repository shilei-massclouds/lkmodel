#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use axerrno::{LinuxResult, LinuxError, linux_err_from};
use axhal::arch::start_thread;
use axtype::get_user_str_vec;

pub fn kernel_execve(filename: &str, argv: Vec<String>, envp: Vec<String>) -> LinuxResult<usize> {
    info!("kernel_execve... {}", filename);

    task::alloc_mm();

    do_close_on_exec()?;

    let (entry, sp) = bprm_loader::execve(filename, 0, argv, envp)?;

    info!("start thread... usp {:#x}", sp);
    start_thread(task::current().pt_regs_addr(), entry, sp);
    Ok(0)
}

fn do_close_on_exec() -> LinuxResult {
    let current = task::current();
    let mut locked_ft = current.filetable.lock();
    let mut set = locked_ft.close_on_exec();
    let mut fd = 0;
    while set != 0 {
        if (set & 1) == 1 {
            locked_ft.remove(fd);
        }
        set >>= 1;
        fd += 1;
    }
    Ok(())
}

pub fn execve(path: &str, argv: usize, envp: usize) -> usize {
    info!("execve: {}", path);

    let args = get_user_str_vec(argv);
    assert!(args.len() > 0);
    for arg in &args {
        info!("arg: {}", arg);
    }
    let envp = get_user_str_vec(envp);
    for env in &envp {
        info!("env: {}", env);
    }

    kernel_execve(path, args, envp)
        .unwrap_or_else(|e| {
            linux_err_from!(e)
        })
}

pub fn init(cpu_id: usize, dtb_pa: usize) {
    axconfig::init_once!();

    axlog2::init(option_env!("AX_LOG").unwrap_or(""));
    axhal::arch_init_early(cpu_id);
    axalloc::init();
    page_table::init();
    axhal::platform_init();
    task::init(cpu_id, dtb_pa);
    bprm_loader::init(cpu_id, dtb_pa);
}
