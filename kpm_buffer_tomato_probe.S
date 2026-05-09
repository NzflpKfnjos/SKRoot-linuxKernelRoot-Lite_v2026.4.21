.section .text
.global _start
_start:
    adr x20, kpm_blob
    adrp x21, cmd_buf
    add x21, x21, :lo12:cmd_buf

    adr x0, prefix
    mov x1, x21
    bl copy_cstr_no_nul

    mov x0, x20
    mov x1, x21
    bl append_hex16

    mov w0, #','
    strb w0, [x21], #1

    mov x0, #kpm_blob_size
    mov x1, x21
    bl append_hex16

    mov w0, #','
    strb w0, [x21], #1

    adr x0, name
    mov x1, x21
    bl copy_cstr_with_nul

    mov x0, #-100
    adrp x1, cmd_buf
    add x1, x1, :lo12:cmd_buf
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x8, #281
    svc #0

    mov x0, #1
    adr x1, survived_msg
    mov x2, #9
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0

copy_cstr_no_nul:
    ldrb w2, [x0], #1
    cbz w2, 1f
    strb w2, [x1], #1
    b copy_cstr_no_nul
1:
    mov x21, x1
    ret

copy_cstr_with_nul:
    ldrb w2, [x0], #1
    strb w2, [x1], #1
    cbnz w2, copy_cstr_with_nul
    mov x21, x1
    ret

append_hex16:
    mov x3, #60
    adr x4, hexchars
2:
    lsr x5, x0, x3
    and x5, x5, #0xf
    ldrb w6, [x4, x5]
    strb w6, [x1], #1
    subs x3, x3, #4
    b.ge 2b
    mov x21, x1
    ret

.section .rodata
prefix:
    .asciz "@LD:"
name:
    .asciz "tomato"
hexchars:
    .ascii "0123456789abcdef"
survived_msg:
    .ascii "survived\n"

.balign 8
kpm_blob:
    .incbin "tomato.kpm"
kpm_blob_end:
.equ kpm_blob_size, kpm_blob_end - kpm_blob

.section .bss
.balign 16
cmd_buf:
    .skip 128
