SECTIONS {
    . = 0;
    .text : {
        *(.text.kpm_entry)
        *(.text*)
    }
    .rodata : { *(.rodata*) }
    .data   : { *(.data*) }
    .bss    : { *(.bss*) *(COMMON) }
}
