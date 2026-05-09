.section .text
.global _start
_start:
    adr x0, kpm_cmd
    mov x1, xzr
    mov x2, xzr
    mov x8, #221
    svc #0
    mov x0, #1
    adr x1, done_msg
    mov x2, #12
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0
.section .rodata
kpm_cmd:
    .asciz "@LS"
done_msg:
    .ascii "execve_done\n"
