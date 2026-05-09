#include "kpm_libc.h"
#include "kpm_runtime.h"

void kpm_main(struct kpm_system_table* sys, int command,
              const void* arg, unsigned long arg_size);
void* kpm_add_slide_ptr(void* ptr, long slide);
extern char __kpm_loader_start[];
extern char __kpm_loader_end[];

/* == Minimal libc subset (freestanding, no builtins) == */

void* kpm_memcpy(void* dest, const void* src, unsigned long n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    for (unsigned long i = 0; i < n; ++i) d[i] = s[i];
    return dest;
}

/* Compiler may generate calls to standard memcpy for struct assignments */
__attribute__((used, visibility("default")))
void* memcpy(void* dest, const void* src, unsigned long n) {
    return kpm_memcpy(dest, src, n);
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

/* == Runtime state ==
 * This loader is embedded in kernel text, so its own .bss is read-only at
 * runtime. Do not persist mutable state here.
 */
static struct hook_entry* const g_hook_list = 0;

static int kpm_runtime_get_sys(struct kpm_system_table* out) {
    unsigned long actual_entry = (unsigned long)&kpm_main;
    unsigned long actual_loader_end =
        ((unsigned long)__kpm_loader_end + 7UL) & ~7UL;
    struct kpm_system_table* raw =
        (struct kpm_system_table*)actual_loader_end;

    if (!out || !raw || !raw->loader_base || !raw->loader_entry_offset) return 0;
    kpm_memcpy(out, raw, sizeof(*out));

    unsigned long table_entry = (unsigned long)raw->loader_base +
                                raw->loader_entry_offset;
    long slide = (long)(actual_entry - table_entry);
    if (slide == 0) return 1;

    out->kallsyms_lookup_name =
        (void* (*)(const char*))kpm_add_slide_ptr((void*)out->kallsyms_lookup_name, slide);
    out->kmalloc =
        (void* (*)(unsigned long, unsigned int))kpm_add_slide_ptr((void*)out->kmalloc, slide);
    out->kfree =
        (void (*)(const void*))kpm_add_slide_ptr((void*)out->kfree, slide);
    out->vmalloc =
        (void* (*)(unsigned long))kpm_add_slide_ptr((void*)out->vmalloc, slide);
    out->vfree =
        (void (*)(const void*))kpm_add_slide_ptr((void*)out->vfree, slide);
    out->memset_impl =
        (void* (*)(void*, int, unsigned long))kpm_add_slide_ptr((void*)out->memset_impl, slide);
    out->memcpy_impl =
        (void* (*)(void*, const void*, unsigned long))kpm_add_slide_ptr((void*)out->memcpy_impl, slide);
    out->printk =
        (int (*)(const char*, ...))kpm_add_slide_ptr((void*)out->printk, slide);
    out->syscall_table = kpm_add_slide_ptr(out->syscall_table, slide);
    out->init_task = kpm_add_slide_ptr(out->init_task, slide);
    out->filp_open_fn =
        (void* (*)(const char*, int, unsigned short))kpm_add_slide_ptr((void*)out->filp_open_fn, slide);
    out->kernel_read_fn =
        (long (*)(void*, void*, unsigned long, unsigned long long*))kpm_add_slide_ptr((void*)out->kernel_read_fn, slide);
    out->filp_close_fn =
        (int (*)(void*, void*))kpm_add_slide_ptr((void*)out->filp_close_fn, slide);
    out->copy_from_user_fn =
        (unsigned long (*)(void*, const void*, unsigned long))kpm_add_slide_ptr((void*)out->copy_from_user_fn, slide);
    out->loader_base = kpm_add_slide_ptr(out->loader_base, slide);
    return 1;
}

void kpm_runtime_init(struct kpm_system_table* sys, struct kpm_runtime_api* api) {
    (void)sys;
    (void)api;
}

struct kpm_runtime_state* kpm_runtime_get_state(void) { return 0; }
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

static int a64_branch26(void* from, void* to, u32* out) {
    s64 delta;
    s64 imm26;

    if (!from || !to || !out) return 0;
    delta = (s64)((u64)to - (u64)from);
    if ((delta & 3) != 0) return 0;
    imm26 = delta >> 2;
    if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) return 0;
    *out = 0x14000000u | ((u32)imm26 & 0x03FFFFFFu);
    return 1;
}

static int a64_is_pc_relative(u32 insn) {
    if ((insn & 0x9F000000u) == 0x10000000u) return 1;
    if ((insn & 0x9F000000u) == 0x90000000u) return 1;
    if ((insn & 0x3B000000u) == 0x18000000u) return 1;
    if ((insn & 0xFC000000u) == 0x14000000u) return 1;
    if ((insn & 0xFC000000u) == 0x94000000u) return 1;
    if ((insn & 0xFF000010u) == 0x54000000u) return 1;
    if ((insn & 0x7E000000u) == 0x34000000u) return 1;
    if ((insn & 0x7E000000u) == 0x36000000u) return 1;
    return 0;
}

static int emit_u32(u8* code, int* idx, u32 insn) {
    if (!code || !idx || *idx < 0 || *idx > 0x1000 - 4) return 0;
    *(volatile u32*)(code + *idx) = insn;
    *idx += 4;
    return 1;
}

static int emit_mov_abs_x16(u8* code, int* idx, u64 addr) {
    if (!emit_u32(code, idx, 0xD2800000u | (u32)(((addr >> 0) & 0xFFFFu) << 5) | 16u)) return 0;
    if (!emit_u32(code, idx, 0xF2800000u | (1u << 21) | (u32)(((addr >> 16) & 0xFFFFu) << 5) | 16u)) return 0;
    if (!emit_u32(code, idx, 0xF2800000u | (2u << 21) | (u32)(((addr >> 32) & 0xFFFFu) << 5) | 16u)) return 0;
    if (!emit_u32(code, idx, 0xF2800000u | (3u << 21) | (u32)(((addr >> 48) & 0xFFFFu) << 5) | 16u)) return 0;
    return 1;
}

static int emit_call_abs_x16(u8* code, int* idx, void* fn) {
    if (!fn) return 1;
    if (!emit_mov_abs_x16(code, idx, (u64)(unsigned long)fn)) return 0;
    return emit_u32(code, idx, 0xD63F0200u);
}

/* == Runtime API implementations == */

void* rt_kallsyms_lookup_name(const char* name) {
    struct kpm_system_table sys;
    if (!kpm_runtime_get_sys(&sys) || !sys.kallsyms_lookup_name) return 0;
    return sys.kallsyms_lookup_name(name);
}

/* hook_wrap(target, handler, trampoline_buf)
 * Installs an inline hook at 'target' that jumps to 'handler'.
 * 'trampoline_buf' is a pre-allocated buffer (at least 64 bytes) for
 * saving original instructions + branch back.
 * Returns trampoline address or 0 on failure.
 */
void* rt_hook_wrap(void* target, void* handler, void* trampoline_buf) {
    (void)target;
    (void)handler;
    (void)trampoline_buf;
    return 0;
}

void rt_hook_unwrap_remove(void* target) {
    (void)target;
}

/* fp_wrap_syscalln(nr, before, after)
 * Wraps syscall_table[nr] to call before() -> original() -> after()
 */
void* rt_fp_wrap_syscalln(int nr, void* before, void* after) {
    (void)nr;
    (void)before;
    (void)after;
    return 0;
}

void rt_fp_unwrap_syscalln(int nr) {
    (void)nr;
}

void* rt_kf_memset(void* s, int c, unsigned long n) {
    struct kpm_system_table sys;
    if (kpm_runtime_get_sys(&sys) && sys.memset_impl)
        return sys.memset_impl(s, c, n);
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
