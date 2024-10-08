OUTPUT_ARCH(%ARCH%)

BASE_ADDRESS = %KERNEL_BASE%;

ENTRY(_start)
SECTIONS
{
    . = BASE_ADDRESS;
    _skernel = .;

    .text : ALIGN(4K) {
        _stext = .;
        *(.text.boot)
        *(.text .text.*)
        *(.fixup)
        . = ALIGN(4K);
        _etext = .;
    }

    .rodata : ALIGN(4K) {
        _srodata = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.sdata2 .sdata2.*)
        . = ALIGN(16);
        __start___ex_table = .;
        KEEP(*(__ex_table))
        __stop___ex_table = .;
        . = ALIGN(4K);
        _erodata = .;
    }

    .data : ALIGN(4K) {
        _sdata = .;
        *(.data.boot_page_table)
        . = ALIGN(4K);
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.got .got.*)
    }

    .tdata : ALIGN(0x10) {
        _stdata = .;
        *(.tdata .tdata.*)
        _etdata = .;
    }

    .tbss : ALIGN(0x10) {
        _stbss = .;
        *(.tbss .tbss.*)
        *(.tcommon)
        _etbss = .;
    }

    . = ALIGN(4K);
    _percpu_start = .;
    .percpu 0x0 : AT(_percpu_start) {
        _percpu_load_start = .;
        *(.percpu .percpu.*)
        _percpu_load_end = .;
        . = ALIGN(64);
        _percpu_size_aligned = .;

        . = _percpu_load_start + _percpu_size_aligned * %SMP%;
    }
    . = _percpu_start + SIZEOF(.percpu);
    _percpu_end = .;

    . = ALIGN(4K);
    _edata = .;

    .bss : ALIGN(4K) {
        boot_stack = .;
        *(.bss.stack)
        . = ALIGN(4K);
        boot_stack_top = .;

        _sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(4K);
        _ebss = .;
    }

    _ekernel = .;

	/DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*)
    }
}
