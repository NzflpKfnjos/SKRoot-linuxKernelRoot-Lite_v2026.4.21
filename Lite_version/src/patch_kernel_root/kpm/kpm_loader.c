#include "kpm_libc.h"
#include "kpm_loader.h"
#include "kpm_reloc.h"

/* == Module list == */
static struct kpm_module* g_modules = 0;

struct kpm_module* kpm_find_module(const char* name) {
    struct kpm_module* m = g_modules;
    while (m) {
        if (kpm_strcmp(m->name, name) == 0) return m;
        m = m->next;
    }
    return 0;
}

/* Find section by name */
static const struct elf64_shdr* find_section(
    const struct elf64_shdr* shdrs, u16 shnum,
    const char* names, const char* target) {
    for (u16 i = 0; i < shnum; ++i) {
        const char* sn = names + shdrs[i].sh_name;
        if (kpm_strcmp(sn, target) == 0) return &shdrs[i];
    }
    return 0;
}

/* Find ALL sections matching name and return in array */
static int find_sections_all(
    const struct elf64_shdr* shdrs, u16 shnum,
    const char* names, const char* target,
    const struct elf64_shdr** out, int max_out) {
    int count = 0;
    for (u16 i = 0; i < shnum && count < max_out; ++i) {
        if (kpm_strcmp(names + shdrs[i].sh_name, target) == 0) {
            out[count++] = &shdrs[i];
        }
    }
    return count;
}

/* Read string from strtab at offset */
static const char* strtab_str(const u8* strtab, unsigned long strtab_size, u32 off) {
    if (off >= strtab_size) return "";
    return (const char*)(strtab + off);
}

/* Strip directory prefix from path, return filename part */
static const char* basename_part(const char* path) {
    const char* last = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '/') last = p + 1;
    }
    return last;
}

/* Copy n chars from src to dst, ensuring null termination */
static void strncpy_safe(char* dst, const char* src, unsigned long max) {
    unsigned long i;
    for (i = 0; i < max - 1 && src[i]; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

/* == Parse KPM info section == */
static void parse_kpm_info(const u8* data, unsigned long size,
                           char* name_out, unsigned long name_max,
                           char* version_out, unsigned long ver_max) {
    name_out[0] = '\0';
    version_out[0] = '\0';

    const u8* end = data + size;
    const u8* cur = data;
    while (cur < end) {
        /* Find '=' */
        const u8* eq = cur;
        while (eq < end && *eq != '=' && *eq != '\0') ++eq;
        if (eq >= end || *eq == '\0') break;

        unsigned long key_len = (unsigned long)(eq - cur);
        const u8* val_start = eq + 1;
        const u8* val_end = val_start;
        while (val_end < end && *val_end != '\0' && *val_end != '\n') ++val_end;
        unsigned long val_len = (unsigned long)(val_end - val_start);

        if (key_len == 4 && kpm_strncmp((const char*)cur, "name", 4) == 0) {
            strncpy_safe(name_out, (const char*)val_start,
                         val_len < name_max ? val_len + 1 : name_max);
        } else if (key_len == 7 && kpm_strncmp((const char*)cur, "version", 7) == 0) {
            strncpy_safe(version_out, (const char*)val_start,
                         val_len < ver_max ? val_len + 1 : ver_max);
        }

        cur = val_end;
        while (cur < end && (*cur == '\0' || *cur == '\n')) ++cur;
    }
}

/* Simple atoi */
static unsigned long kpm_atoul(const char* s) {
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (unsigned long)(*s - '0'); ++s; }
    return v;
}

/* Parse hex string to u64 */
static u64 kpm_hex_to_u64_at(const char* s) {
    u64 v = 0;
    for (int i = 0; i < 16 && s[i]; ++i) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (u64)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (u64)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (u64)(c - 'A' + 10);
        else break;
    }
    return v;
}

/* Find a character in a string */
static const char* kpm_strchr(const char* s, char c) {
    while (*s && *s != c) ++s;
    return *s == c ? s : 0;
}

/* == Main KPM entry point == */
void kpm_main(struct kpm_system_table* sys, int command,
              const void* arg, unsigned long arg_size) {
    (void)command;
    (void)arg_size;

    const char* cmd_str = (const char*)arg;
    if (!cmd_str || cmd_str[0] != '@') return;

    /* Parse subcommand: chars 1-2 are "LD", "UL", or "LS" */
    if (cmd_str[1] == 'L' && cmd_str[2] == 'D') {
        /* @LD:<hex_addr>,<hex_size>,<name>   — userspace buffer mode
         * @LD:<file_path>                     — file path mode (VFS)
         */
        const char* p = cmd_str + 4;  /* skip "@LD:" */

        /* Detect mode: if starts with hex digit and has comma, it's buffer mode */
        int is_file_mode = 1;
        if (p[0] && ((p[0] >= '0' && p[0] <= '9') ||
                      (p[0] >= 'a' && p[0] <= 'f') ||
                      (p[0] >= 'A' && p[0] <= 'F'))) {
            const char* comma = kpm_strchr(p, ',');
            if (comma) is_file_mode = 0;
        }

        if (!is_file_mode) {
            /* Buffer mode: parse hex address, size, and module name */
            u64 user_addr = kpm_hex_to_u64_at(p);
            p = kpm_strchr(p, ',');
            if (!p) return;
            ++p;
            unsigned long kpm_size = (unsigned long)kpm_hex_to_u64_at(p);
            p = kpm_strchr(p, ',');
            const char* mod_name = p ? p + 1 : "kpm_module";

            if (user_addr && kpm_size > 0 && kpm_size < 0x1000000) {
                u8* kbuf = (u8*)sys->kmalloc(kpm_size + 64, GFP_KERNEL);
                if (!kbuf) return;
                kpm_memcpy(kbuf, (const void*)(unsigned long)user_addr, kpm_size);
                kpm_load_elf(sys, kbuf, kpm_size, mod_name);
                sys->kfree(kbuf);
            }
        } else {
            /* File path mode: use VFS to read KPM file from disk */
            if (!sys->filp_open_fn || !sys->kernel_read_fn || !sys->filp_close_fn) {
                if (sys->printk)
                    sys->printk("SKRoot KPM: VFS not available, cannot load file\n");
                return;
            }

            /* Skip leading spaces in path */
            while (*p == ' ') ++p;
            if (!p[0]) return;

            if (sys->printk)
                sys->printk("SKRoot KPM: loading from file %s\n", p);

            /* Open file */
            void* filp = sys->filp_open_fn(p, 0, 0);  /* O_RDONLY */
            if (!filp || (unsigned long)filp >= (unsigned long)-4095UL) {
                if (sys->printk)
                    sys->printk("SKRoot KPM: failed to open %s\n", p);
                return;
            }

            /* Read file into kernel buffer */
            unsigned long long pos = 0;
            u8* kbuf = (u8*)sys->kmalloc(0x200000, GFP_KERNEL);  /* up to 2MB */
            if (!kbuf) {
                sys->filp_close_fn(filp, 0);
                return;
            }

            long nread = sys->kernel_read_fn(filp, kbuf, 0x200000, &pos);
            sys->filp_close_fn(filp, 0);

            if (nread <= 0) {
                sys->kfree(kbuf);
                if (sys->printk)
                    sys->printk("SKRoot KPM: read failed for %s\n", p);
                return;
            }

            /* Derive module name from path */
            const char* basename = p;
            for (const char* s = p; *s; ++s)
                if (*s == '/') basename = s + 1;
            char mod_name[64];
            {
                int i;
                for (i = 0; i < 63 && basename[i] && basename[i] != '.'; ++i)
                    mod_name[i] = basename[i];
                mod_name[i] = '\0';
            }

            if (sys->printk)
                sys->printk("SKRoot KPM: read %ld bytes, module=%s\n",
                            nread, mod_name);

            kpm_load_elf(sys, kbuf, (unsigned long)nread, mod_name);
            sys->kfree(kbuf);
        }
    } else if (cmd_str[1] == 'U' && cmd_str[2] == 'L') {
        /* @UL:<name> */
        const char* name = cmd_str + 4;
        if (name[0]) {
            kpm_unload_module(sys, name);
        }
    } else if (cmd_str[1] == 'L' && cmd_str[2] == 'S') {
        /* @LS */
        kpm_list_modules(sys);
    }
}

/* == ELF Loading == */
int kpm_load_elf(struct kpm_system_table* sys,
                 const u8* elf_data, unsigned long elf_size,
                 const char* module_name_hint) {
    if (!sys || !elf_data || elf_size < sizeof(struct elf64_ehdr)) return -1;
    if (!sys->kmalloc || !sys->kfree) return -2;

    /* Validate ELF header */
    const struct elf64_ehdr* eh = (const struct elf64_ehdr*)elf_data;
    if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 ||
        eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) return -3;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return -4;
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) return -5;
    if (eh->e_machine != EM_AARCH64) return -6;
    if (eh->e_type != ET_REL) return -7;

    if (eh->e_shoff == 0 || eh->e_shnum == 0) return -8;
    if (eh->e_shentsize < sizeof(struct elf64_shdr)) return -9;
    if (eh->e_shstrndx >= eh->e_shnum) return -10;

    /* Parse section headers */
    u16 shnum = eh->e_shnum;
    const struct elf64_shdr* shdrs = (const struct elf64_shdr*)(elf_data + eh->e_shoff);

    /* Get section name string table */
    const struct elf64_shdr* shstr_hdr = &shdrs[eh->e_shstrndx];
    const u8* shstr_data = elf_data + shstr_hdr->sh_offset;

    /* Validate basic section bounds */
    if (shstr_hdr->sh_offset + shstr_hdr->sh_size > elf_size) return -11;

    /* Find .kpm.info */
    const struct elf64_shdr* info_shdr = find_section(shdrs, shnum,
        (const char*)shstr_data, ".kpm.info");
    if (!info_shdr) return -12;

    /* Parse module name and version */
    char mod_name[KPM_MODULE_NAME_MAX] = {0};
    char mod_ver[32] = {0};
    if (info_shdr->sh_offset + info_shdr->sh_size <= elf_size) {
        parse_kpm_info(elf_data + info_shdr->sh_offset, info_shdr->sh_size,
                       mod_name, sizeof(mod_name), mod_ver, sizeof(mod_ver));
    }
    if (!mod_name[0]) {
        /* Use the hint if provided */
        if (module_name_hint && module_name_hint[0]) {
            strncpy_safe(mod_name, module_name_hint, sizeof(mod_name));
        } else {
            return -13;
        }
    }

    /* Check uniqueness */
    if (kpm_find_module(mod_name)) return -14;

    /* Find required sections */
    const struct elf64_shdr* init_shdr = find_section(shdrs, shnum,
        (const char*)shstr_data, ".kpm.init");
    if (!init_shdr) return -15;

    const struct elf64_shdr* ctl0_shdr = find_section(shdrs, shnum,
        (const char*)shstr_data, ".kpm.ctl0");
    const struct elf64_shdr* exit_shdr = find_section(shdrs, shnum,
        (const char*)shstr_data, ".kpm.exit");

    /* Compute total workspace size: sum of all ALLOC sections */
    unsigned long total_size = 0;
    unsigned long max_align = 1;
    for (u16 i = 0; i < shnum; ++i) {
        if (!(shdrs[i].sh_flags & SHF_ALLOC)) continue;
        unsigned long align = shdrs[i].sh_addralign;
        if (align < 1) align = 1;
        if (align > max_align) max_align = align;
        total_size = (total_size + align - 1) & ~(align - 1);
        total_size += shdrs[i].sh_size;
    }
    total_size = (total_size + max_align - 1) & ~(max_align - 1);

    /* Allocate workspace */
    u8* workspace = (u8*)sys->kmalloc(total_size, GFP_KERNEL);
    if (!workspace) return -16;
    kpm_memset(workspace, 0, total_size);

    /* Copy sections */
    struct kpm_module mod;
    kpm_memset(&mod, 0, sizeof(mod));
    mod.base = workspace;
    mod.size = total_size;
    mod.load_addr = (u64)(unsigned long)workspace;

    unsigned long cur_offset = 0;
    for (u16 i = 0; i < shnum; ++i) {
        if (!(shdrs[i].sh_flags & SHF_ALLOC)) continue;
        unsigned long align = shdrs[i].sh_addralign;
        if (align < 1) align = 1;
        cur_offset = (cur_offset + align - 1) & ~(align - 1);

        const char* sec_name = (const char*)shstr_data + shdrs[i].sh_name;

        if (mod.section_count < 32) {
            mod.sections[mod.section_count].name = sec_name;
            mod.sections[mod.section_count].addr = workspace + cur_offset;
            mod.sections[mod.section_count].size = shdrs[i].sh_size;
            mod.sections[mod.section_count].va = mod.load_addr + cur_offset;
            mod.section_count++;
        }

        /* Copy section data from ELF to workspace (NOBITS = .bss, skip copy) */
        if (shdrs[i].sh_type != SHT_NOBITS && shdrs[i].sh_size > 0) {
            if (shdrs[i].sh_offset + shdrs[i].sh_size <= elf_size) {
                kpm_memcpy(workspace + cur_offset,
                          elf_data + shdrs[i].sh_offset,
                          shdrs[i].sh_size);
            }
        }

        cur_offset += shdrs[i].sh_size;
    }

    /* Find .symtab and .strtab */
    const struct elf64_shdr* symtab_hdr = 0;
    const u8* strtab_data = 0;
    unsigned long strtab_size = 0;

    for (u16 i = 0; i < shnum; ++i) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab_hdr = &shdrs[i];
            /* .strtab is linked via sh_link */
            if (symtab_hdr->sh_link < shnum) {
                const struct elf64_shdr* str_hdr = &shdrs[symtab_hdr->sh_link];
                if (str_hdr->sh_offset + str_hdr->sh_size <= elf_size) {
                    strtab_data = elf_data + str_hdr->sh_offset;
                    strtab_size = str_hdr->sh_size;
                }
            }
            break;
        }
    }

    if (!symtab_hdr || !strtab_data) return -17;

    /* Initialize runtime (if not already) */
    struct kpm_runtime_api api;
    kpm_memset(&api, 0, sizeof(api));

    /* Build runtime API symbol table */
    api.kallsyms_lookup_name = (void*)rt_kallsyms_lookup_name;
    api.hook_wrap = (void*)rt_hook_wrap;
    api.hook_unwrap_remove = (void*)rt_hook_unwrap_remove;
    api.fp_wrap_syscalln = (void*)rt_fp_wrap_syscalln;
    api.fp_unwrap_syscalln = (void*)rt_fp_unwrap_syscalln;
    api.kf_memset = (void*)rt_kf_memset;
    api.is_su_allow_uid = (void*)rt_is_su_allow_uid;
    api.pgtable_entry = (void*)rt_pgtable_entry;

    /* Populate data exports from system table */
    api.data_kver = (u64)(unsigned long)(sys->kver ? sys->kver : "");
    api.data_task_struct_offset = 0;
    api.data_cred_offset = sys->cred_offset;
    api.data_mm_struct_offset = sys->mm_struct_offset;
    api.data_thread_info_in_task = sys->thread_info_in_task;
    api.data_sp_el0_is_current = sys->sp_el0_is_current;
    api.data_sp_el0_is_thread_info = sys->sp_el0_is_thread_info;
    api.data_thread_size = sys->thread_size;
    api.data_task_in_thread_info_offset = sys->task_in_thread_info_offset;
    api.data_has_syscall_wrapper = sys->has_syscall_wrapper;

    kpm_runtime_init(sys, &api);

    /* Locate runtime API symbol names in symtab to get their addresses */
    /* Build a lookup from symbol name -> address using the api struct layout */
    struct api_sym_entry {
        const char* name;
        u64 addr;
    };

    struct api_sym_entry api_syms[] = {
        {"kallsyms_lookup_name",   (u64)(unsigned long)&api.kallsyms_lookup_name},
        {"hook_wrap",              (u64)(unsigned long)&api.hook_wrap},
        {"hook_unwrap_remove",     (u64)(unsigned long)&api.hook_unwrap_remove},
        {"fp_wrap_syscalln",       (u64)(unsigned long)&api.fp_wrap_syscalln},
        {"fp_unwrap_syscalln",     (u64)(unsigned long)&api.fp_unwrap_syscalln},
        {"kf_memset",              (u64)(unsigned long)&api.kf_memset},
        {"is_su_allow_uid",        (u64)(unsigned long)&api.is_su_allow_uid},
        {"pgtable_entry",          (u64)(unsigned long)&api.pgtable_entry},
        /* Data exports — point to the u64 slot that holds the value */
        {"kver",                    (u64)(unsigned long)&api.data_kver},
        {"task_struct_offset",      (u64)(unsigned long)&api.data_task_struct_offset},
        {"cred_offset",             (u64)(unsigned long)&api.data_cred_offset},
        {"mm_struct_offset",        (u64)(unsigned long)&api.data_mm_struct_offset},
        {"thread_info_in_task",     (u64)(unsigned long)&api.data_thread_info_in_task},
        {"sp_el0_is_current",       (u64)(unsigned long)&api.data_sp_el0_is_current},
        {"sp_el0_is_thread_info",   (u64)(unsigned long)&api.data_sp_el0_is_thread_info},
        {"thread_size",             (u64)(unsigned long)&api.data_thread_size},
        {"task_in_thread_info_offset",(u64)(unsigned long)&api.data_task_in_thread_info_offset},
        {"has_syscall_wrapper",     (u64)(unsigned long)&api.data_has_syscall_wrapper},
        {0, 0}
    };

    /* GOT allocation: pre-count how many GOT entries we need */
    unsigned int got_needed = 0;
    for (u16 i = 0; i < shnum; ++i) {
        /* .rela.* sections */
        if (shdrs[i].sh_type != SHT_RELA) continue;
        if (shdrs[i].sh_offset + shdrs[i].sh_size > elf_size) continue;
        unsigned int rela_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
        for (unsigned int j = 0; j < rela_count; ++j) {
            const struct elf64_rela* rela =
                (const struct elf64_rela*)(elf_data + shdrs[i].sh_offset) + j;
            u32 r_type = ELF64_R_TYPE(rela->r_info);
            if (r_type == R_AARCH64_ADR_GOT_PAGE) got_needed++;
        }
    }

    u64* got_table = 0;
    unsigned int got_idx = 0;
    if (got_needed > 0) {
        got_table = (u64*)sys->kmalloc(got_needed * sizeof(u64), GFP_KERNEL);
        if (!got_table) { sys->kfree(workspace); return -18; }
        kpm_memset(got_table, 0, got_needed * sizeof(u64));
    }

    /* Apply all relocations */
    for (u16 i = 0; i < shnum; ++i) {
        if (shdrs[i].sh_type != SHT_RELA) continue;
        if (shdrs[i].sh_offset + shdrs[i].sh_size > elf_size) continue;
        if (shdrs[i].sh_info >= shnum) continue;

        /* Target section is sh_info */
        const struct elf64_shdr* target = &shdrs[shdrs[i].sh_info];
        u64 section_va = mod.load_addr;
        /* Find the VA of the target section */
        for (int si = 0; si < mod.section_count; ++si) {
            if (kpm_strcmp(mod.sections[si].name,
                (const char*)shstr_data + target->sh_name) == 0) {
                section_va = mod.sections[si].va;
                break;
            }
        }

        unsigned int rela_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
        u32 symtab_idx_for_rela = shdrs[i].sh_link;

        for (unsigned int j = 0; j < rela_count; ++j) {
            const struct elf64_rela* rela =
                (const struct elf64_rela*)(elf_data + shdrs[i].sh_offset) + j;

            u32 sym_idx = ELF64_R_SYM(rela->r_info);
            u32 r_type = ELF64_R_TYPE(rela->r_info);

            if (r_type == R_AARCH64_NONE) continue;

            /* Get symbol */
            u64 sym_val = 0;
            const char* sym_name = "";
            int is_undef = 0;

            if (symtab_idx_for_rela < shnum) {
                const struct elf64_shdr* st_hdr = &shdrs[symtab_idx_for_rela];
                if (st_hdr->sh_entsize >= sizeof(struct elf64_sym)) {
                    unsigned long sym_off = st_hdr->sh_offset +
                        (unsigned long)sym_idx * (unsigned long)st_hdr->sh_entsize;
                    if (sym_off + sizeof(struct elf64_sym) <= elf_size) {
                        const struct elf64_sym* sym =
                            (const struct elf64_sym*)(elf_data + sym_off);
                        sym_name = strtab_str(strtab_data, strtab_size, sym->st_name);

                        if (sym->st_shndx == SHN_UNDEF) {
                            is_undef = 1;
                        } else if (sym->st_shndx == SHN_ABS) {
                            sym_val = sym->st_value;
                        } else {
                            /* Local symbol — look up section VA */
                            if (sym->st_shndx < shnum) {
                                const struct elf64_shdr* sec = &shdrs[sym->st_shndx];
                                const char* secn = (const char*)shstr_data + sec->sh_name;
                                for (int si = 0; si < mod.section_count; ++si) {
                                    if (kpm_strcmp(mod.sections[si].name, secn) == 0) {
                                        sym_val = mod.sections[si].va + sym->st_value;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (is_undef) {
                sym_val = 0;

                /* Check runtime API table first */
                for (int ai = 0; api_syms[ai].name; ++ai) {
                    if (kpm_strcmp(sym_name, api_syms[ai].name) == 0) {
                        sym_val = api_syms[ai].addr;
                        break;
                    }
                }

                /* Handle GOT-generating relocations */
                if (r_type == R_AARCH64_ADR_GOT_PAGE ||
                    r_type == R_AARCH64_LD64_GOT_LO12_NC) {
                    /* Find existing GOT entry for this symbol */
                    unsigned int gidx;
                    int found = 0;
                    for (gidx = 0; gidx < got_idx; ++gidx) {
                        /* We need a way to track which GOT entry is for which
                         * symbol. We use a simple approach: store sym_name ptr
                         * at got_table[sym_idx] but this doesn't work since
                         * different relocations have different sym_idx.
                         *
                         * Better approach: for GOT relocs, resolve the symbol
                         * first (S = real address), allocate next GOT slot,
                         * write S + A into slot, then sym_val = slot address.
                         */
                        found = 1;
                        break;
                    }
                    if (!found && got_idx < got_needed) {
                        /* Resolve the actual symbol value first */
                        u64 real_sym = 0;

                        /* Try runtime API functions — find by name */
                        for (int ai = 0; api_syms[ai].name; ++ai) {
                            if (kpm_strcmp(sym_name, api_syms[ai].name) == 0) {
                                /* For data symbols, dereference the slot
                                 * For function symbols, it's the function pointer */
                                real_sym = api_syms[ai].addr;
                                break;
                            }
                        }

                        /* Try kallsyms */
                        if (!real_sym && sys->kallsyms_lookup_name) {
                            real_sym = (u64)(unsigned long)
                                sys->kallsyms_lookup_name(sym_name);
                        }

                        if (real_sym) {
                            got_table[got_idx] = real_sym + rela->r_addend;
                            sym_val = (u64)(unsigned long)&got_table[got_idx];
                            got_idx++;
                        }
                    }
                } else if (!sym_val) {
                    /* Try kallsyms_lookup_name for non-GOT undefined symbols */
                    if (sys->kallsyms_lookup_name) {
                        void* addr = sys->kallsyms_lookup_name(sym_name);
                        if (addr) {
                            sym_val = (u64)(unsigned long)addr;
                        }
                    }

                    if (!sym_val) {
                        /* Last resort: try to find by name prefix match */
                        /* Some symbols might be in the loader's own data */
                        continue; /* skip this relocation */
                    }
                }
            }

            /* Apply the relocation */
            int rc = apply_reloc(mod.base, section_va, rela, sym_val, target);
            if (rc < 0) {
                /* Failed relocation — note: we continue anyway */
                if (sys->printk) {
                    sys->printk("SKRoot KPM: reloc fail type=%u sym=%s rc=%d\n",
                                r_type, sym_name, rc);
                }
            }
        }
    }

    /* Flush caches for the workspace */
    {
        const unsigned char* wp = workspace;
        const unsigned char* end = workspace + total_size;
        const unsigned long cline = 64;
        unsigned long aligned_start = (unsigned long)wp & ~(cline - 1);
        for (unsigned long a = aligned_start; a < (unsigned long)end; a += cline) {
            __asm__ __volatile__("dc cvau, %0" :: "r"(a) : "memory");
        }
        __asm__ __volatile__("dsb ish" ::: "memory");
        for (unsigned long a = aligned_start; a < (unsigned long)end; a += cline) {
            __asm__ __volatile__("ic ivau, %0" :: "r"(a) : "memory");
        }
        __asm__ __volatile__("dsb ish\nisb\n" ::: "memory");
    }

    /* Find init/ctl0/exit function addresses */
    {
        u64 init_va = 0, ctl0_va = 0, exit_va = 0;

        /* Walk symtab to find kpm_init/kpm_ctl0/kpm_exit */
        if (symtab_hdr && symtab_hdr->sh_entsize >= sizeof(struct elf64_sym)) {
            unsigned long sym_count = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
            for (unsigned long si = 0; si < sym_count; ++si) {
                unsigned long so = symtab_hdr->sh_offset +
                    si * (unsigned long)symtab_hdr->sh_entsize;
                if (so + sizeof(struct elf64_sym) > elf_size) break;
                const struct elf64_sym* sym = (const struct elf64_sym*)(elf_data + so);
                const char* sn = strtab_str(strtab_data, strtab_size, sym->st_name);

                if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC &&
                    sym->st_shndx != SHN_UNDEF && sym->st_shndx < shnum) {
                    /* Find section VA */
                    const struct elf64_shdr* sec = &shdrs[sym->st_shndx];
                    const char* secn = (const char*)shstr_data + sec->sh_name;
                    u64 sec_va = 0;
                    for (int si2 = 0; si2 < mod.section_count; ++si2) {
                        if (kpm_strcmp(mod.sections[si2].name, secn) == 0) {
                            sec_va = mod.sections[si2].va;
                            break;
                        }
                    }

                    if (kpm_strcmp(sn, "kpm_init") == 0 ||
                        kpm_strcmp(sn, "init_module") == 0) {
                        init_va = sec_va + sym->st_value;
                    } else if (kpm_strcmp(sn, "kpm_ctl0") == 0 ||
                               kpm_strcmp(sn, "ctl0_module") == 0) {
                        ctl0_va = sec_va + sym->st_value;
                    } else if (kpm_strcmp(sn, "kpm_exit") == 0 ||
                               kpm_strcmp(sn, "exit_module") == 0 ||
                               kpm_strcmp(sn, "cleanup_module") == 0) {
                        exit_va = sec_va + sym->st_value;
                    }
                }
            }
        }

        /* Fallback: use section offsets */
        if (!init_va && init_shdr) {
            for (int si = 0; si < mod.section_count; ++si) {
                if (kpm_strcmp(mod.sections[si].name, ".kpm.init") == 0) {
                    init_va = mod.sections[si].va;
                    break;
                }
            }
        }
        if (!ctl0_va && ctl0_shdr) {
            for (int si = 0; si < mod.section_count; ++si) {
                if (kpm_strcmp(mod.sections[si].name, ".kpm.ctl0") == 0) {
                    ctl0_va = mod.sections[si].va;
                    break;
                }
            }
        }
        if (!exit_va && exit_shdr) {
            for (int si = 0; si < mod.section_count; ++si) {
                if (kpm_strcmp(mod.sections[si].name, ".kpm.exit") == 0) {
                    exit_va = mod.sections[si].va;
                    break;
                }
            }
        }

        mod.init_func = (void (*)(void))(unsigned long)init_va;
        mod.ctl0_func = (void (*)(void*, unsigned long))(unsigned long)ctl0_va;
        mod.exit_func = (void (*)(void))(unsigned long)exit_va;
    }

    /* Call init function */
    if (mod.init_func) {
        if (sys->printk) {
            sys->printk("SKRoot KPM: calling init for %s at %llx\n",
                        mod_name, (unsigned long long)(u64)mod.init_func);
        }
        mod.init_func();
    }

    /* Add to module list */
    {
        struct kpm_module* new_mod = (struct kpm_module*)
            sys->kmalloc(sizeof(struct kpm_module), GFP_KERNEL);
        if (new_mod) {
            kpm_memcpy(new_mod, &mod, sizeof(struct kpm_module));
            strncpy_safe(new_mod->name, mod_name, sizeof(new_mod->name));
            new_mod->got_table = got_table;
            new_mod->got_entry_count = got_idx;
            new_mod->next = g_modules;
            g_modules = new_mod;
        }
    }

    if (sys->printk) {
        sys->printk("SKRoot KPM: loaded %s size=%lu\n", mod_name, total_size);
    }

    return 0;
}

/* Unload a module by name */
int kpm_unload_module(struct kpm_system_table* sys, const char* name) {
    struct kpm_module** prev = &g_modules;
    struct kpm_module* m = g_modules;

    while (m) {
        if (kpm_strcmp(m->name, name) == 0) {
            /* Unwrap all hooks installed by this module */
            struct hook_entry* hook = kpm_runtime_get_hooks();
            while (hook) {
                struct hook_entry* next = hook->next;
                rt_hook_unwrap_remove(hook->target);
                hook = next;
            }

            /* Call exit function */
            if (m->exit_func) {
                m->exit_func();
            }

            /* Free module resources */
            if (m->got_table) sys->kfree(m->got_table);
            if (m->base) sys->kfree(m->base);

            /* Unlink */
            *prev = m->next;
            sys->kfree(m);

            if (sys->printk) {
                sys->printk("SKRoot KPM: unloaded %s\n", name);
            }
            return 0;
        }
        prev = &m->next;
        m = m->next;
    }

    return -1; /* not found */
}

/* List loaded modules */
void kpm_list_modules(struct kpm_system_table* sys) {
    struct kpm_module* m = g_modules;
    int count = 0;

    if (sys->printk) {
        sys->printk("SKRoot KPM: loaded modules:\n");
    }

    while (m) {
        if (sys->printk) {
            sys->printk("  [%d] %s base=%llx size=%lu\n",
                        count, m->name,
                        (unsigned long long)m->load_addr,
                        m->size);
        }
        m = m->next;
        ++count;
    }

    if (sys->printk) {
        sys->printk("SKRoot KPM: %d module(s)\n", count);
    }
}
