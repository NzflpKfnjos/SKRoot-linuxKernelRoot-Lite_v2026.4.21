#ifndef KPM_SHELLCODE_H
#define KPM_SHELLCODE_H

/* ABI contract between C kernel runtime and C++ desktop patcher.
 * Both sides include this header.
 * The KpmSystemTable is populated by the patcher at build time and placed
 * in kernel memory immediately after the KPM loader binary.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct kpm_system_table {
    /* Kernel function pointers (pre-computed addresses from kallsyms) */
    void* (*kallsyms_lookup_name)(const char* name);
    void* (*kmalloc)(unsigned long size, unsigned int flags);
    void  (*kfree)(const void* ptr);
    void* (*vmalloc)(unsigned long size);
    void  (*vfree)(const void* ptr);
    void* (*memset_impl)(void* s, int c, unsigned long n);
    void* (*memcpy_impl)(void* dest, const void* src, unsigned long n);
    int   (*printk)(const char* fmt, ...);

    /* Kernel data structure addresses */
    void* syscall_table;
    void* init_task;

    /* Pre-computed kernel offsets */
    unsigned long cred_offset;
    unsigned long mm_struct_offset;
    unsigned long task_in_thread_info_offset;
    unsigned long seccomp_offset;

    /* Pre-computed kernel constants */
    unsigned long thread_size;
    unsigned int  tif_seccomp_bit;

    /* Pre-computed booleans (kernel config) */
    int sp_el0_is_current;
    int sp_el0_is_thread_info;
    int thread_info_in_task;
    int has_syscall_wrapper;

    /* Kernel version string pointer (points into kernel .rodata) */
    const char* kver;

    /* KPM module list head (managed by loader) */
    void* kpm_module_list_head;

    /* VFS file operations (for loading KPM from file path on disk) */
    void* (*filp_open_fn)(const char* path, int flags, unsigned short mode);
    long  (*kernel_read_fn)(void* file, void* buf, unsigned long count, unsigned long long* pos);
    int   (*filp_close_fn)(void* file, void* owner);
    unsigned long (*copy_from_user_fn)(void* to, const void* from, unsigned long n);

    /* KPM loader binary base (for self-referencing) */
    void* loader_base;
    unsigned long loader_size;
    unsigned long loader_entry_offset;
};

/* KPM loader entry point, called by asmjit wrapper shellcode.
 * x0 = pointer to struct kpm_system_table
 * x1 = command (0=LOAD, 1=UNLOAD, 2=LIST)
 * x2 = argument pointer (command-specific)
 * x3 = argument size or secondary argument
 */
void kpm_main(struct kpm_system_table* sys, int command,
              const void* arg, unsigned long arg_size);

#ifdef __cplusplus
}
#endif

#endif /* KPM_SHELLCODE_H */
