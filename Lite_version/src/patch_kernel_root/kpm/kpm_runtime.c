#include "kpm_libc.h"
#include "kpm_runtime.h"

/* == Minimal libc subset (freestanding, no builtins) == */

void* kpm_memcpy(void* dest, const void* src, unsigned long n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    for (unsigned long i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}

void* kpm_memset(void* s, int c, unsigned long n) {
    unsigned char* p = (unsigned char*)s;
    for (unsigned long i = 0; i < n; ++i) p[i] = (unsigned char)c;
    return s;
}

int kpm_memcmp(const void* a, const void* b, unsigned long n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    for (unsigned long i = 0; i < n; ++i) {
        if (pa[i] != pb[i]) return (int)pa[i] - (int)pb[i];
    }
    return 0;
}

unsigned long kpm_strlen(const char* s) {
    unsigned long n = 0;
    while (s && *s) { ++n; ++s; }
    return n;
}

int kpm_strcmp(const char* a, const char* b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && *a == *b) { ++a; ++b; }
    return (int)((unsigned char)*a) - (int)((unsigned char)*b);
}

int kpm_strncmp(const char* a, const char* b, unsigned long n) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    for (unsigned long i = 0; i < n; ++i) {
        if (a[i] != b[i]) return (int)((unsigned char)a[i]) - (int)((unsigned char)b[i]);
        if (!a[i]) return 0;
    }
    return 0;
}

char* kpm_strcpy(char* dest, const char* src) {
    char* d = dest;
    while (*src) *d++ = *src++;
    *d = '\0';
    return dest;
}

char* kpm_strncpy(char* dest, const char* src, unsigned long n) {
    unsigned long i;
    for (i = 0; i < n && src[i]; ++i) dest[i] = src[i];
    for (; i < n; ++i) dest[i] = '\0';
    return dest;
}

/* Simple hex string to u64 (not exported — local use only) */
static u64 hex_to_u64_local(const char* s, int max_digits) {
    u64 v = 0;
    int i;
    for (i = 0; i < max_digits && s[i]; ++i) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (u64)(c - 'A' + 10);
        else break;
    }
    return v;
}

/* == Global runtime state == */
static struct kpm_runtime_state g_rt_state;
static struct hook_entry* g_hook_list = 0;

void kpm_runtime_init(struct kpm_system_table* sys, struct kpm_runtime_api* api) {
    g_rt_state.sys = sys;
    g_rt_state.api = api;
    g_hook_list = 0;
}

struct kpm_runtime_state* kpm_runtime_get_state(void) { return &g_rt_state; }
struct hook_entry* kpm_runtime_get_hooks(void) { return g_hook_list; }

/* == I-cache maintenance helpers == */

/* SYS instruction encoding for DC/IC operations */
static void kpm_dc_cvau(const void* va) {
    /* DC CVAU, Xn — clean data cache to point of unification */
    __asm__ __volatile__(
        "dc cvau, %0\n"
        : : "r" (va) : "memory"
    );
}

static void kpm_ic_ivau(const void* va) {
    /* IC IVAU, Xn — invalidate instruction cache to point of unification */
    __asm__ __volatile__(
        "ic ivau, %0\n"
        : : "r" (va) : "memory"
    );
}

void kpm_cache_flush_range(const void* start, unsigned long size) {
    const unsigned char* p = (const unsigned char*)start;
    const unsigned char* end = p + size;
    /* Align to cache line (typically 64 bytes on ARM64) */
    const unsigned long cline = 64;
    p = (const unsigned char*)((unsigned long)p & ~(cline - 1));

    for (; p < end; p += cline) {
        kpm_dc_cvau(p);
    }
    __asm__ __volatile__("dsb ish" ::: "memory");

    p = (const unsigned char*)((unsigned long)start & ~(cline - 1));
    for (; p < end; p += cline) {
        kpm_ic_ivau(p);
    }
    __asm__ __volatile__(
        "dsb ish\n"
        "isb\n"
        ::: "memory"
    );
}

/* == Runtime API implementations == */

void* rt_kallsyms_lookup_name(const char* name) {
    struct kpm_runtime_state* st = &g_rt_state;
    if (!st->sys || !st->sys->kallsyms_lookup_name) return 0;
    return st->sys->kallsyms_lookup_name(name);
}

/* hook_wrap(target, handler, trampoline_buf)
 * Installs an inline hook at 'target' that jumps to 'handler'.
 * 'trampoline_buf' is a pre-allocated buffer (at least 64 bytes) for
 * saving original instructions + branch back.
 * Returns trampoline address or 0 on failure.
 */
void* rt_hook_wrap(void* target, void* handler, void* trampoline_buf) {
    struct kpm_runtime_state* st = &g_rt_state;
    if (!target || !handler || !trampoline_buf) return 0;

    u8* tgt = (u8*)target;
    u8* tramp = (u8*)trampoline_buf;

    /* Read the first 2 instructions (8 bytes) from target */
    u32 insn0 = *(volatile u32*)(tgt);
    u32 insn1 = *(volatile u32*)(tgt + 4);

    /* Build trampoline: original instructions + branch back */
    *(volatile u32*)(tramp) = insn0;
    *(volatile u32*)(tramp + 4) = insn1;

    /* B <target + 8> from trampoline + 8 */
    s64 delta_tramp = (s64)((u64)(tgt + 8) - (u64)(tramp + 8));
    u32 branch_back = 0x14000000u | (u32)((delta_tramp >> 2) & 0x03FFFFFFu);
    *(volatile u32*)(tramp + 8) = branch_back;

    /* Flush trampoline dcache + icache */
    kpm_cache_flush_range(tramp, 12);

    /* Write B <handler> at target */
    s64 delta_hook = (s64)((u64)handler - (u64)target);
    u32 branch_hook = 0x14000000u | (u32)((delta_hook >> 2) & 0x03FFFFFFu);
    *(volatile u32*)(tgt) = branch_hook;
    kpm_cache_flush_range(tgt, 4);

    /* Track this hook */
    struct hook_entry* entry = (struct hook_entry*)
        st->sys->kmalloc(sizeof(struct hook_entry), 0xCC0);
    if (entry) {
        entry->target = target;
        entry->trampoline = trampoline_buf;
        entry->orig_insns[0] = insn0;
        entry->orig_insns[1] = insn1;
        entry->orig_insn_count = 2;
        entry->is_syscall_wrap = 0;
        entry->syscall_nr = 0;
        entry->syscall_original = 0;
        entry->next = g_hook_list;
        g_hook_list = entry;
    }

    return trampoline_buf;
}

void rt_hook_unwrap_remove(void* target) {
    struct hook_entry** prev = &g_hook_list;
    struct hook_entry* entry = g_hook_list;
    struct kpm_runtime_state* st = &g_rt_state;

    while (entry) {
        if (entry->target == target) {
            /* Restore original instructions */
            u8* tgt = (u8*)target;
            if (entry->is_syscall_wrap) {
                /* Restore syscall table entry */
                u64* sct = (u64*)st->sys->syscall_table;
                sct[entry->syscall_nr] = (u64)entry->syscall_original;
                kpm_cache_flush_range(&sct[entry->syscall_nr], 8);
            } else {
                /* Restore inline hook */
                for (int i = 0; i < entry->orig_insn_count; ++i) {
                    *(volatile u32*)(tgt + i * 4) = entry->orig_insns[i];
                }
                kpm_cache_flush_range(tgt, (unsigned long)entry->orig_insn_count * 4);
            }

            /* Free trampoline */
            if (entry->trampoline) st->sys->kfree(entry->trampoline);

            /* Unlink and free entry */
            *prev = entry->next;
            st->sys->kfree(entry);
            return;
        }
        prev = &entry->next;
        entry = entry->next;
    }
}

/* fp_wrap_syscalln(nr, before, after)
 * Wraps syscall_table[nr] to call before() -> original() -> after()
 */
void* rt_fp_wrap_syscalln(int nr, void* before, void* after) {
    struct kpm_runtime_state* st = &g_rt_state;
    if (!st->sys || !st->sys->syscall_table) return 0;

    u64* sct = (u64*)st->sys->syscall_table;
    void* original = (void*)(u64)sct[nr];
    if (!original) return 0;

    /* Allocate trampoline page */
    u8* tramp = (u8*)st->sys->kmalloc(0x1000, 0xCC0);
    if (!tramp) return 0;

    /* Build wrapper asm:
     *   stp x29, x30, [sp, #-16]!
     *   mov x29, sp
     *   blr <before>        (if not null)
     *   blr <original>
     *   mov <scratch>, x0
     *   blr <after>         (if not null)
     *   mov x0, <scratch>
     *   ldp x29, x30, [sp], #16
     *   ret
     */
    int idx = 0;
    /* stp x29, x30, [sp, #-16]!   = 0xA9BF7BFD */
    *(volatile u32*)(tramp + idx) = 0xA9BF7BFD; idx += 4;
    /* mov x29, sp                   = 0x910003FD */
    *(volatile u32*)(tramp + idx) = 0x910003FD; idx += 4;

    if (before) {
        /* blr x16 */  /* save x0 first */
        s64 d0 = (s64)((u64)before - (u64)(tramp + idx));
        u32 bl0 = 0x94000000u | (u32)((d0 >> 2) & 0x03FFFFFFu);
        *(volatile u32*)(tramp + idx) = bl0; idx += 4;
    }

    {
        /* blr <original> */
        s64 d1 = (s64)((u64)original - (u64)(tramp + idx));
        u32 bl1 = 0x94000000u | (u32)((d1 >> 2) & 0x03FFFFFFu);
        *(volatile u32*)(tramp + idx) = bl1; idx += 4;
    }

    /* mov x19, x0 (save return value) */
    *(volatile u32*)(tramp + idx) = 0xAA0003F3; idx += 4;

    if (after) {
        s64 d2 = (s64)((u64)after - (u64)(tramp + idx));
        u32 bl2 = 0x94000000u | (u32)((d2 >> 2) & 0x03FFFFFFu);
        *(volatile u32*)(tramp + idx) = bl2; idx += 4;
    }

    /* mov x0, x19 (restore return value) */
    *(volatile u32*)(tramp + idx) = 0xAA1303E0; idx += 4;
    /* ldp x29, x30, [sp], #16    = 0xA8C17BFD */
    *(volatile u32*)(tramp + idx) = 0xA8C17BFD; idx += 4;
    /* ret                         = 0xD65F03C0 */
    *(volatile u32*)(tramp + idx) = 0xD65F03C0; idx += 4;

    kpm_cache_flush_range(tramp, (unsigned long)idx);

    /* Replace syscall table entry */
    sct[nr] = (u64)tramp;
    kpm_cache_flush_range(&sct[nr], 8);

    /* Track hook */
    struct hook_entry* entry = (struct hook_entry*)
        st->sys->kmalloc(sizeof(struct hook_entry), 0xCC0);
    if (entry) {
        entry->target = (void*)(u64)(&sct[nr]);
        entry->trampoline = tramp;
        entry->orig_insn_count = 0;
        entry->is_syscall_wrap = 1;
        entry->syscall_nr = nr;
        entry->syscall_original = original;
        entry->next = g_hook_list;
        g_hook_list = entry;
    }

    return tramp;
}

void rt_fp_unwrap_syscalln(int nr) {
    struct kpm_runtime_state* st = &g_rt_state;
    if (!st->sys || !st->sys->syscall_table) return;

    /* Find hook entry by syscall nr */
    struct hook_entry** prev = &g_hook_list;
    struct hook_entry* entry = g_hook_list;
    while (entry) {
        if (entry->is_syscall_wrap && entry->syscall_nr == nr) {
            u64* sct = (u64*)st->sys->syscall_table;
            sct[nr] = (u64)entry->syscall_original;
            kpm_cache_flush_range(&sct[nr], 8);
            if (entry->trampoline) st->sys->kfree(entry->trampoline);
            *prev = entry->next;
            st->sys->kfree(entry);
            return;
        }
        prev = &entry->next;
        entry = entry->next;
    }
}

void* rt_kf_memset(void* s, int c, unsigned long n) {
    struct kpm_runtime_state* st = &g_rt_state;
    if (st->sys && st->sys->memset_impl)
        return st->sys->memset_impl(s, c, n);
    return kpm_memset(s, c, n);
}

int rt_is_su_allow_uid(int uid) {
    /* Allow root (0) and system UIDs (1000-2000) */
    if (uid == 0) return 1;
    if (uid >= 1000 && uid <= 2000) return 1;
    return 0;
}

/* pgtable_entry: walk kernel page tables (TTBR1_EL1) to find PTE for VA */
u64 rt_pgtable_entry(u64 va) {
    u64 ttbr1, par;
    /* Read TTBR1_EL1 (kernel space page table base) */
    __asm__ __volatile__("mrs %0, TTBR1_EL1" : "=r"(ttbr1));
    ttbr1 &= ~0xFFFULL;  /* clear ASID/bits, get physical base */

    /* We need to convert physical to virtual.
     * In the linear map, physical addresses are at a fixed offset.
     * For KPTI kernels, we use the phys_to_virt trick.
     * Since we can't easily do phys_to_virt here, we'll use
     * AT S1E1R to walk the page tables via hardware.
     */
    __asm__ __volatile__(
        "at s1e1r, %1\n"
        "mrs %0, PAR_EL1\n"
        : "=r"(par) : "r"(va) : "memory"
    );

    /* PAR_EL1[0] = 0 means successful translation,
     * PAR_EL1[47:12] = physical address bits [47:12] */
    if (par & 1) return 0;  /* fault */
    return (par & 0x0000FFFFFFFFF000ULL) >> 12;
}
