#ifndef KPM_LOADER_H
#define KPM_LOADER_H

#include "kpm_shellcode.h"
#include "kpm_elf.h"
#include "kpm_runtime.h"

#define KPM_MODULE_NAME_MAX 64
#define KPM_MAX_GOT_ENTRIES 256
#define GFP_KERNEL           0xCC0

/* == KPM Module descriptor == */
struct kpm_module {
    struct kpm_module* next;
    char name[KPM_MODULE_NAME_MAX];
    char version[32];
    u8*  base;               /* allocated workspace base */
    unsigned long size;      /* total workspace size */
    u64 load_addr;           /* absolute VA of base */

    void (*init_func)(void);
    void (*ctl0_func)(void*, unsigned long);
    void (*exit_func)(void);

    struct kpm_section_map {
        const char* name;
        u8* addr;
        unsigned long size;
        u64 va;
    } sections[32];
    int section_count;

    u64* got_table;
    unsigned int got_entry_count;

    /* Data export slots for non-function undefined symbols */
    u64 data_export[16];
    unsigned int data_export_count;

    /* Track hooks installed by this module */
    struct hook_entry* module_hooks;
};

/* == Exported entry point (called by asmjit wrapper) == */
void kpm_main(struct kpm_system_table* sys, int command,
              const void* arg, unsigned long arg_size);

/* == Module management == */
struct kpm_module* kpm_find_module(const char* name);
int kpm_load_elf(struct kpm_system_table* sys,
                 const u8* elf_data, unsigned long elf_size,
                 const char* module_name);
int kpm_unload_module(struct kpm_system_table* sys, const char* name);
void kpm_list_modules(struct kpm_system_table* sys);

#endif /* KPM_LOADER_H */
