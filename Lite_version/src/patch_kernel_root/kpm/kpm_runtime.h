#ifndef KPM_RUNTIME_H
#define KPM_RUNTIME_H

#include "kpm_shellcode.h"
#include "kpm_elf.h"

/* == KPM Runtime API ==
 * These are the 18 symbols exported to loaded KPM modules.
 * Each function symbol has a C implementation compiled into the loader binary.
 * Data symbols are resolved to slots in a data-export region.
 */

/* Globally visible runtime API table (accessed by KPM modules via relocation) */
struct kpm_runtime_api {
    /* Function pointers — one per KernelPatch runtime function symbol */
    void* kallsyms_lookup_name;
    void* hook_wrap;
    void* hook_unwrap_remove;
    void* fp_wrap_syscalln;
    void* fp_unwrap_syscalln;
    void* kf_memset;
    void* is_su_allow_uid;
    void* pgtable_entry;

    /* Data export slots — each is a u64 value pointed to by the symbol */
    u64 data_kver;
    u64 data_task_struct_offset;
    u64 data_cred_offset;
    u64 data_mm_struct_offset;
    u64 data_thread_info_in_task;
    u64 data_sp_el0_is_current;
    u64 data_sp_el0_is_thread_info;
    u64 data_thread_size;
    u64 data_task_in_thread_info_offset;
    u64 data_has_syscall_wrapper;
};

/* ---- Internal runtime state ---- */
struct kpm_runtime_state {
    struct kpm_system_table* sys;
    struct kpm_runtime_api* api;     /* pointer to API table for resolving */
};

/* ---- Hook tracking ---- */
struct hook_entry {
    void* target;                    /* original function address */
    void* trampoline;                /* allocated trampoline page */
    u32  orig_insns[4];              /* saved original instructions */
    int  orig_insn_count;            /* how many instructions saved */
    int  is_syscall_wrap;            /* 1 if this is a syscall table hook */
    int  syscall_nr;                 /* syscall number (if is_syscall_wrap) */
    void* syscall_original;          /* original syscall handler */
    struct hook_entry* next;
};

/* runtime API function implementations */
void* rt_kallsyms_lookup_name(const char* name);
void* rt_hook_wrap(void* target, void* handler, void* trampoline_buf);
void  rt_hook_unwrap_remove(void* target);
void* rt_fp_wrap_syscalln(int nr, void* before, void* after);
void  rt_fp_unwrap_syscalln(int nr);
void* rt_kf_memset(void* s, int c, unsigned long n);
int   rt_is_su_allow_uid(int uid);
u64   rt_pgtable_entry(u64 va);

/* called by main loader to initialize the runtime */
void kpm_runtime_init(struct kpm_system_table* sys, struct kpm_runtime_api* api);
struct kpm_runtime_state* kpm_runtime_get_state(void);
struct hook_entry* kpm_runtime_get_hooks(void);

#endif /* KPM_RUNTIME_H */
