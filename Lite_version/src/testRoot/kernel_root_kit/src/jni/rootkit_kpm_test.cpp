#include "rootkit_kpm_test.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string_view>

#include "rootkit_command.h"
#include "____DO_NOT_EDIT____/private_api_runtime_helper.h"

namespace kernel_root {
namespace {

constexpr uint8_t EI_CLASS = 4;
constexpr uint8_t EI_DATA = 5;
constexpr uint8_t ELFCLASS64 = 2;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint16_t ET_REL = 1;
constexpr uint16_t EM_AARCH64 = 183;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint16_t SHN_UNDEF = 0;

struct Elf64_Ehdr_Min {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr_Min {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym_Min {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct LoaderCommands {
    std::string loader_path;
    std::string load_cmd;
    std::string status_cmd;
    std::string unload_cmd;
};

template <typename T>
bool read_struct(const std::vector<char>& data, size_t offset, T& out) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) return false;
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

bool read_file(const char* path, std::vector<char>& out) {
    out.clear();
    if (!path || !std::strlen(path)) return false;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    out.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return true;
}

std::string read_cstr(const std::vector<char>& data, size_t offset) {
    if (offset >= data.size()) return {};
    size_t end = offset;
    while (end < data.size() && data[end] != '\0') ++end;
    return std::string(data.data() + offset, end - offset);
}

std::string section_data_to_string(const std::vector<char>& data, const Elf64_Shdr_Min& sh) {
    if (sh.sh_offset > data.size() || sh.sh_size > data.size() - sh.sh_offset) return {};
    return std::string(data.data() + sh.sh_offset, data.data() + sh.sh_offset + sh.sh_size);
}

std::vector<std::string> split_info_entries(const std::string& text) {
    std::vector<std::string> entries;
    std::string cur;
    for (char c : text) {
        if (c == '\0' || c == '\n' || c == '\r') {
            if (!cur.empty()) entries.push_back(cur);
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) entries.push_back(cur);
    return entries;
}

void parse_kpm_info_text(const std::string& text, KpmElfInfo& out) {
    for (const auto& entry : split_info_entries(text)) {
        auto pos = entry.find('=');
        if (pos == std::string::npos) continue;
        std::string key = entry.substr(0, pos);
        std::string value = entry.substr(pos + 1);
        if (key == "name") out.name = value;
        else if (key == "version") out.version = value;
        else if (key == "license") out.license = value;
        else if (key == "author") out.author = value;
        else if (key == "description") out.description = value;
    }
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

bool has_unsafe_shell_char(const std::string& s) {
    for (unsigned char c : s) {
        if (c == 0 || c == '\n' || c == '\r' || c == '`' || c == ';' || c == '|' ||
            c == '$' || c == '<' || c == '>' || c == '&' || c == '\\') {
            return true;
        }
    }
    return false;
}

bool is_safe_kpm_path(const std::string& path) {
    if (path.empty() || path[0] != '/') return false;
    if (!ends_with(path, ".kpm")) return false;
    if (!starts_with(path, "/data/local/tmp/") && !starts_with(path, "/data/adb/")) return false;
    if (path.find("..") != std::string::npos) return false;
    return !has_unsafe_shell_char(path);
}

bool is_safe_module_name(const std::string& name) {
    if (name.empty()) return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '-' || c == '.';
    });
}

std::string shell_quote_single_arg(const std::string& arg) {
    std::string out = "'";
    for (char c : arg) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

std::string first_non_empty_line(const std::string& text) {
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || std::isspace(static_cast<unsigned char>(line.back())))) line.pop_back();
        size_t start = 0;
        while (start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) ++start;
        if (start < line.size()) return line.substr(start);
    }
    return {};
}

std::string basename_of(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

LoaderCommands make_loader_commands(const std::string& loader_path, const std::string& kpm_path, const std::string& module_name) {
    LoaderCommands cmds;
    cmds.loader_path = loader_path;
    const std::string loader = shell_quote_single_arg(loader_path);
    const std::string quoted_path = shell_quote_single_arg(kpm_path);
    const std::string quoted_name = shell_quote_single_arg(module_name);
    const std::string base = basename_of(loader_path);
    if (base == "apd" || base == "apatch") {
        cmds.load_cmd = loader + " kpm load " + quoted_path;
        cmds.status_cmd = loader + " kpm list";
        cmds.unload_cmd = loader + " kpm unload " + quoted_name;
    } else {
        cmds.load_cmd = loader + " load " + quoted_path;
        cmds.status_cmd = loader + " list";
        cmds.unload_cmd = loader + " unload " + quoted_name;
    }
    return cmds;
}

std::string loader_probe_cmd() {
    return "for p in "
           "/data/adb/ap/bin/kpm "
           "/data/adb/ap/bin/kpmd "
           "/data/adb/ap/bin/apd "
           "/data/adb/ap/bin/apatch "
           "/data/adb/ksu/bin/kpm "
           "/data/local/tmp/kpm "
           "/data/local/tmp/kpmd "
           "/data/local/tmp/apd; do "
           "if [ -x \"$p\" ]; then echo \"$p\"; break; fi; "
           "done";
}

KRootErr probe_runtime(const char* root_key, KpmRuntimeProbe& runtime, const std::string& kpm_path, const std::string& module_name) {
    runtime = {};
    std::string out;
    KRootErr err = run_root_cmd(root_key, "id && uname -a && getprop ro.product.cpu.abi", out);
    runtime.probe_log += "# root/runtime\n" + out + "\n";
    if (is_failed(err)) return err;
    runtime.has_root = true;

    out.clear();
    err = run_root_cmd(root_key, loader_probe_cmd().c_str(), out);
    runtime.probe_log += "# loader probe\n" + out + "\n";
    if (is_failed(err)) return err;

    std::string loader = first_non_empty_line(out);
    if (loader.empty()) return KRootErr::ERR_KPM_NO_LOADER;
    runtime.has_loader = true;
    LoaderCommands cmds = make_loader_commands(loader, kpm_path, module_name.empty() ? "Module" : module_name);
    runtime.loader_path = cmds.loader_path;
    runtime.load_cmd = cmds.load_cmd;
    runtime.status_cmd = cmds.status_cmd;
    runtime.unload_cmd = cmds.unload_cmd;
    return KRootErr::OK;
}

void append_section_bool(std::stringstream& ss, const char* name, bool value) {
    ss << "  " << name << ": " << (value ? "yes" : "no") << "\n";
}

bool text_has_module_name(const std::string& text, const std::string& module_name) {
    if (module_name.empty()) return false;
    return text.find(module_name) != std::string::npos;
}

} // namespace

KRootErr parse_kpm_elf_info(const char* kpm_path, KpmElfInfo& out) {
    out = {};
    std::vector<char> data;
    if (!read_file(kpm_path, data)) return KRootErr::ERR_OPEN_FILE;
    if (data.size() < sizeof(Elf64_Ehdr_Min)) return KRootErr::ERR_KPM_NOT_ELF64;

    Elf64_Ehdr_Min eh{};
    if (!read_struct(data, 0, eh)) return KRootErr::ERR_KPM_NOT_ELF64;
    if (!(eh.e_ident[0] == 0x7f && eh.e_ident[1] == 'E' && eh.e_ident[2] == 'L' && eh.e_ident[3] == 'F')) {
        return KRootErr::ERR_KPM_NOT_ELF64;
    }
    out.is_elf64 = eh.e_ident[EI_CLASS] == ELFCLASS64;
    out.is_little_endian = eh.e_ident[EI_DATA] == ELFDATA2LSB;
    out.is_aarch64 = eh.e_machine == EM_AARCH64;
    out.is_relocatable = eh.e_type == ET_REL;
    if (!out.is_elf64 || !out.is_little_endian) return KRootErr::ERR_KPM_NOT_ELF64;
    if (!out.is_aarch64) return KRootErr::ERR_KPM_NOT_AARCH64;
    if (!out.is_relocatable) return KRootErr::ERR_KPM_NOT_REL;
    if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shentsize < sizeof(Elf64_Shdr_Min)) return KRootErr::ERR_KPM_MISSING_INFO;

    std::vector<Elf64_Shdr_Min> sections;
    sections.reserve(eh.e_shnum);
    for (uint16_t i = 0; i < eh.e_shnum; ++i) {
        Elf64_Shdr_Min sh{};
        if (!read_struct(data, static_cast<size_t>(eh.e_shoff) + static_cast<size_t>(i) * eh.e_shentsize, sh)) return KRootErr::ERR_KPM_MISSING_INFO;
        sections.push_back(sh);
    }
    if (eh.e_shstrndx >= sections.size()) return KRootErr::ERR_KPM_MISSING_INFO;

    const auto& shstr = sections[eh.e_shstrndx];
    if (shstr.sh_offset > data.size() || shstr.sh_size > data.size() - shstr.sh_offset) return KRootErr::ERR_KPM_MISSING_INFO;
    std::vector<char> shstr_data(data.begin() + shstr.sh_offset, data.begin() + shstr.sh_offset + shstr.sh_size);

    std::set<std::string> undefined_seen;
    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& sh = sections[i];
        std::string section_name = read_cstr(shstr_data, sh.sh_name);
        out.sections.push_back(section_name);
        if (section_name == ".kpm.info") {
            out.has_kpm_info = true;
            parse_kpm_info_text(section_data_to_string(data, sh), out);
        } else if (section_name == ".kpm.init") {
            out.has_kpm_init = true;
        } else if (section_name == ".kpm.ctl0") {
            out.has_kpm_ctl0 = true;
        } else if (section_name == ".kpm.exit") {
            out.has_kpm_exit = true;
        } else if (starts_with(section_name, ".rela.")) {
            out.has_rela_sections = true;
        } else if (section_name == ".strtab") {
            out.has_strtab = true;
        }

        if (sh.sh_type != SHT_SYMTAB) continue;
        out.has_symtab = true;
        if (sh.sh_entsize < sizeof(Elf64_Sym_Min) || sh.sh_link >= sections.size()) continue;
        const auto& strtab = sections[sh.sh_link];
        if (strtab.sh_offset > data.size() || strtab.sh_size > data.size() - strtab.sh_offset) continue;
        std::vector<char> strtab_data(data.begin() + strtab.sh_offset, data.begin() + strtab.sh_offset + strtab.sh_size);
        const size_t sym_count = static_cast<size_t>(sh.sh_size / sh.sh_entsize);
        for (size_t n = 0; n < sym_count; ++n) {
            Elf64_Sym_Min sym{};
            if (!read_struct(data, static_cast<size_t>(sh.sh_offset) + n * static_cast<size_t>(sh.sh_entsize), sym)) break;
            if (sym.st_shndx != SHN_UNDEF || sym.st_name == 0) continue;
            std::string sym_name = read_cstr(strtab_data, sym.st_name);
            if (!sym_name.empty() && undefined_seen.insert(sym_name).second) out.undefined_symbols.push_back(sym_name);
        }
    }

    if (!out.has_kpm_info) return KRootErr::ERR_KPM_MISSING_INFO;
    if (!out.has_kpm_init) return KRootErr::ERR_KPM_MISSING_INIT;
    return KRootErr::OK;
}

std::string format_kpm_elf_info(const KpmElfInfo& info) {
    std::stringstream ss;
    ss << "ELF:\n";
    append_section_bool(ss, "ELF64", info.is_elf64);
    append_section_bool(ss, "little_endian", info.is_little_endian);
    append_section_bool(ss, "AArch64", info.is_aarch64);
    append_section_bool(ss, "relocatable", info.is_relocatable);
    ss << "KPM info:\n";
    ss << "  name: " << info.name << "\n";
    ss << "  version: " << info.version << "\n";
    ss << "  license: " << info.license << "\n";
    ss << "  author: " << info.author << "\n";
    ss << "  description: " << info.description << "\n";
    ss << "sections:\n";
    append_section_bool(ss, " .kpm.info", info.has_kpm_info);
    append_section_bool(ss, " .kpm.init", info.has_kpm_init);
    append_section_bool(ss, " .kpm.ctl0", info.has_kpm_ctl0);
    append_section_bool(ss, " .kpm.exit", info.has_kpm_exit);
    append_section_bool(ss, " .rela.*", info.has_rela_sections);
    append_section_bool(ss, " .symtab", info.has_symtab);
    append_section_bool(ss, " .strtab", info.has_strtab);
    ss << "undefined symbols:\n";
    for (const auto& sym : info.undefined_symbols) ss << "  " << sym << "\n";
    return ss.str();
}

KRootErr kpm_compat_precheck(const char* root_key, const char* kpm_path, KpmTestReport& out) {
    out = {};
    KRootErr err = parse_kpm_elf_info(kpm_path, out.elf_info);
    out.err = err;
    out.output = format_kpm_elf_info(out.elf_info);
    if (is_failed(err)) return err;

    std::string path = kpm_path ? kpm_path : "";
    if (!is_safe_kpm_path(path)) {
        out.err = KRootErr::ERR_KPM_BAD_PATH;
        out.output += "runtime precheck: ERR_KPM_BAD_PATH\n";
        return out.err;
    }

    err = probe_runtime(root_key, out.runtime, path, out.elf_info.name);
    out.err = err;
    out.output += "runtime probe:\n";
    out.output += out.runtime.probe_log;
    out.output += "loader: " + (out.runtime.loader_path.empty() ? std::string("not found") : out.runtime.loader_path) + "\n";
    out.output += "runtime result: " + to_string(err) + "\n";
    return err;
}

KRootErr kpm_load_temp(const char* root_key, const char* kpm_path, KpmTestReport& out) {
    KRootErr err = kpm_compat_precheck(root_key, kpm_path, out);
    std::stringstream ss;
    ss << out.output;
    ss << "[1/6] parse kpm: " << (is_ok(parse_kpm_elf_info(kpm_path, out.elf_info)) ? "OK" : "FAILED") << "\n";
    ss << "[2/6] root: " << (out.runtime.has_root ? "OK" : "FAILED") << "\n";
    ss << "[3/6] runtime probe: " << to_string(err) << "\n";
    if (is_failed(err)) {
        out.output = ss.str();
        return err;
    }

    if (!is_safe_module_name(out.elf_info.name)) {
        out.err = KRootErr::ERR_KPM_UNSAFE_ARG;
        ss << "[4/6] load: ERR_KPM_UNSAFE_ARG\n";
        out.output = ss.str();
        return out.err;
    }

    std::string cmd_out;
    err = run_root_cmd(root_key, out.runtime.load_cmd.c_str(), cmd_out);
    ss << "[4/6] load command: " << out.runtime.load_cmd << "\n";
    ss << cmd_out << "\n";
    if (is_failed(err)) {
        out.err = err;
        ss << "[4/6] load: " << to_string(err) << "\n";
        out.output = ss.str();
        return err;
    }

    std::string status_out;
    KRootErr status_err = run_root_cmd(root_key, out.runtime.status_cmd.c_str(), status_out);
    ss << "[5/6] status command: " << out.runtime.status_cmd << "\n";
    ss << status_out << "\n";

    std::string unload_out;
    KRootErr unload_err = run_root_cmd(root_key, out.runtime.unload_cmd.c_str(), unload_out);
    ss << "[6/6] unload command: " << out.runtime.unload_cmd << "\n";
    ss << unload_out << "\n";
    if (is_failed(unload_err)) {
        out.err = KRootErr::ERR_KPM_UNLOAD_FAILED;
        ss << "[6/6] unload: " << to_string(unload_err) << "\n";
        out.output = ss.str();
        return out.err;
    }

    if (is_failed(status_err) || !text_has_module_name(status_out + cmd_out, out.elf_info.name)) {
        out.err = KRootErr::ERR_KPM_LOAD_FAILED;
        ss << "load result: " << to_string(out.err) << "\n";
        out.output = ss.str();
        return out.err;
    }

    out.err = KRootErr::OK;
    ss << "load result: OK\n";
    out.output = ss.str();
    return out.err;
}

KRootErr kpm_unload_by_name(const char* root_key, const char* module_name, KpmTestReport& out) {
    out = {};
    std::string name = module_name ? module_name : "";
    if (!is_safe_module_name(name)) {
        out.err = KRootErr::ERR_KPM_UNSAFE_ARG;
        out.output = "kpmUnload: ERR_KPM_UNSAFE_ARG\n";
        return out.err;
    }

    KRootErr err = probe_runtime(root_key, out.runtime, "/data/local/tmp/placeholder.kpm", name);
    std::stringstream ss;
    ss << "runtime probe:\n" << out.runtime.probe_log;
    ss << "loader: " << (out.runtime.loader_path.empty() ? "not found" : out.runtime.loader_path) << "\n";
    if (is_failed(err)) {
        out.err = err;
        ss << "kpmUnload: " << to_string(err) << "\n";
        out.output = ss.str();
        return err;
    }

    std::string unload_out;
    err = run_root_cmd(root_key, out.runtime.unload_cmd.c_str(), unload_out);
    ss << "unload command: " << out.runtime.unload_cmd << "\n" << unload_out << "\n";
    if (is_failed(err)) {
        out.err = KRootErr::ERR_KPM_UNLOAD_FAILED;
        ss << "kpmUnload: " << to_string(err) << "\n";
        out.output = ss.str();
        return out.err;
    }

    std::string status_out;
    KRootErr status_err = run_root_cmd(root_key, out.runtime.status_cmd.c_str(), status_out);
    ss << "status command: " << out.runtime.status_cmd << "\n" << status_out << "\n";
    out.err = is_failed(status_err) ? status_err : KRootErr::OK;
    ss << "kpmUnload: " << to_string(out.err) << "\n";
    out.output = ss.str();
    return out.err;
}

const char* get_kpm_compat_report(const char* root_key, const char* kpm_path) {
    thread_local std::string report;
    KpmTestReport out;
    kpm_compat_precheck(root_key, kpm_path, out);
    report = out.output;
    return report.c_str();
}

}
