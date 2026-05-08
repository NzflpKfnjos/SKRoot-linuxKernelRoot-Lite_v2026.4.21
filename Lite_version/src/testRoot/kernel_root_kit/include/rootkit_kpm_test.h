#pragma once
#include <string>
#include <vector>

#include "rootkit_err_def.h"

namespace kernel_root {

struct KpmElfInfo {
    bool is_elf64 = false;
    bool is_little_endian = false;
    bool is_aarch64 = false;
    bool is_relocatable = false;
    bool has_kpm_info = false;
    bool has_kpm_init = false;
    bool has_kpm_ctl0 = false;
    bool has_kpm_exit = false;
    bool has_rela_sections = false;
    bool has_symtab = false;
    bool has_strtab = false;
    std::string name;
    std::string version;
    std::string license;
    std::string author;
    std::string description;
    std::vector<std::string> undefined_symbols;
    std::vector<std::string> sections;
};

struct KpmRuntimeProbe {
    bool has_root = false;
    bool has_loader = false;
    std::string loader_path;
    std::string load_cmd;
    std::string status_cmd;
    std::string unload_cmd;
    std::string probe_log;
};

struct KpmTestReport {
    KpmElfInfo elf_info;
    KpmRuntimeProbe runtime;
    KRootErr err = KRootErr::OK;
    std::string output;
};

KRootErr parse_kpm_elf_info(const char* kpm_path, KpmElfInfo& out);
KRootErr kpm_compat_precheck(const char* root_key, const char* kpm_path, KpmTestReport& out);
KRootErr kpm_load_temp(const char* root_key, const char* kpm_path, KpmTestReport& out);
KRootErr kpm_unload_by_name(const char* root_key, const char* module_name, KpmTestReport& out);
std::string format_kpm_elf_info(const KpmElfInfo& info);
const char* get_kpm_compat_report(const char* root_key, const char* kpm_path);

}
