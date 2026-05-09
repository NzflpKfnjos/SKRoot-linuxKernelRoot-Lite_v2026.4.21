#pragma once
#include <vector>
#include <cstdint>
#include "patch_kernel_root.h"
#include "analyze/symbol_analyze.h"
#include "kpm/kpm_shellcode.h"

/* KPM loader embedding configuration */
struct KpmEmbedConfig {
    const std::vector<char>* kernel_file_buf;
    size_t cred_offset;
    size_t cred_uid_offset;
    size_t seccomp_offset;
    int thread_info_in_task;
    int sp_el0_is_current;
    int sp_el0_is_thread_info;
    int has_syscall_wrapper;
    int execve_filename_reg;
    int execve_filename_is_direct;
    const char* kernel_version_str;
    uint64_t kallsyms_lookup_name_addr;
    uint64_t kernel_va_base;
    uint64_t kmalloc_addr;
    uint64_t kfree_addr;
    uint64_t vmalloc_addr;
    uint64_t vfree_addr;
    uint64_t memset_addr;
    uint64_t memcpy_addr;
    uint64_t printk_addr;
    uint64_t syscall_table_addr;
    uint64_t init_task_addr;
    uint64_t filp_open_addr;
    uint64_t kernel_read_addr;
    uint64_t filp_close_addr;
    uint64_t copy_from_user_addr;
    uint64_t kti_addr;
};

/* Result of embedding the KPM loader */
struct KpmEmbedResult {
    bool success = false;
    size_t loader_start_addr = 0;    /* kernel VA where loader binary starts */
    size_t loader_end_addr = 0;      /* end of loader + system table */
    size_t system_table_addr = 0;    /* kernel VA of KpmSystemTable */
    size_t command_handler_addr = 0; /* entry point for '@' command dispatch */
    std::vector<patch_bytes_data> patches;
};

/* Embed the KPM loader binary and system table into the kernel image.
 * Returns the embedding result with generated patches.
 */
KpmEmbedResult kpm_embed_loader(const KpmEmbedConfig& config,
                                const SymbolRegion& available_region);

size_t kpm_required_space();
