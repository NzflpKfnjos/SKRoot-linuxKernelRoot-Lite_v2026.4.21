SECTIONS
{
  . = 0;
  __kpm_loader_start = .;
  .text : ALIGN(16) {
    *(.text*)
  }
  .rodata : ALIGN(16) {
    *(.rodata*)
  }
  .data : ALIGN(16) {
    *(.data*)
  }
  .got : ALIGN(8) {
    *(.got*)
  }
  .bss : ALIGN(16) {
    *(.bss*)
    *(COMMON)
  }
  __kpm_loader_end = .;
}
