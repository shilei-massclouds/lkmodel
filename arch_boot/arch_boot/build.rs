use std::io::Result;
use std::path::Path;

fn main() {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let platform = axconfig::PLATFORM;
    if platform != "dummy" {
        gen_linker_script(&arch, platform).unwrap();
    }

    println!("cargo::rerun-if-changed=linker.lds.S");
    println!("cargo:rustc-cfg=platform=\"{}\"", platform);
    println!("cargo:rustc-cfg=platform_family=\"{}\"", axconfig::FAMILY);
}

fn gen_linker_script(arch: &str, platform: &str) -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = out_dir + "/../../../";
    let fname = Path::new(&out_dir).join(format!("linker_{}.lds", platform));
    println!("Generating linker file: {}", fname.display());

    let output_arch = if arch == "x86_64" {
        "i386:x86-64"
    } else if arch.contains("riscv") {
        "riscv" // OUTPUT_ARCH of both riscv32/riscv64 is "riscv"
    } else {
        arch
    };
    let ld_content = std::fs::read_to_string("linker.lds.S")?;
    let ld_content = ld_content.replace("%ARCH%", output_arch);
    let ld_content = ld_content.replace(
        "%KERNEL_BASE%",
        &format!("{:#x}", axconfig::KERNEL_BASE_VADDR),
    );

    let mut ld_content = ld_content.replace("%SMP%", &format!("{}", axconfig::SMP));

    // Note:
    // For loongarch64, it causes error "too large segment" when we put 'got' into data.
    // We need to figure out the reason.
    if arch == "loongarch64" {
        ld_content = ld_content.replace(r"*(.got .got.*)", "");
    }

    std::fs::write(fname, ld_content)?;
    Ok(())
}
