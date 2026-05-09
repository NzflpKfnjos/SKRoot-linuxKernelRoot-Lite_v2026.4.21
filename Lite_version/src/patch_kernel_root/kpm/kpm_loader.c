#include "kpm_libc.h"
#include "kpm_loader.h"
#include "kpm_reloc.h"

/* == Module list ==
 * The loader lives in a patched kernel text cave, which is mapped read-only
 * on modern Android kernels (CONFIG_STRICT_KERNEL_RWX).  Static variables
 * cannot be written at runtime, so the list head is always NULL.
 *
 * Loaded module descriptors are heap-allocated (kmalloc) but we intentionally
 * do not chain them here — writing to this static slot would fault on RO
 * kernel memory.  The list command reports 0 modules by design.
 *
 * TODO: Store the list head in a heap block referenced via the GOT, or
 *       use the kpm_module_list_head field in the system-table copy.
 */
static struct kpm_module* const g_modules = 0;

struct api_sym_entry {
    const char* name;
    u64 addr;      /* callable function address, or address of data slot */
    int is_func;
};

struct import_entry {
    u32 sym_idx;
    u64 real;
    u64 slot;
    u64 veneer;
    int is_func;
};

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

static int range_in_bounds(unsigned long off, unsigned long size, unsigned long total) {
    if (off > total) return 0;
    return size <= total - off;
}

static int entry_in_module(const struct kpm_module* mod, u64 addr) {
    if (!addr) return 1;
    if (!mod || mod->size == 0) return 0;
    if (addr < mod->load_addr) return 0;
    return addr - mod->load_addr < mod->size;
}

static int is_power_of_two_ulong(unsigned long v) {
    return v && ((v & (v - 1)) == 0);
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

static unsigned long parse_kernel_version_code(const char* s) {
    unsigned long parts[3] = {0, 0, 0};
    int idx = 0;
    if (!s) return 0;

    while (*s && idx < 3) {
        if (*s >= '0' && *s <= '9') {
            parts[idx] = kpm_atoul(s);
            while (*s >= '0' && *s <= '9') ++s;
            ++idx;
            if (*s == '.') ++s;
            continue;
        }
        ++s;
    }

    if (idx == 0) return 0;
    return (parts[0] << 16) | (parts[1] << 8) | parts[2];
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

void* kpm_add_slide_ptr(void* ptr, long slide) {
    if (!ptr || slide == 0) return ptr;
    return (void*)((unsigned long)ptr + (unsigned long)slide);
}

static u64 read_u64_le_local(const u8* p) {
    u64 v = 0;
    for (int i = 0; i < 8; ++i) v |= (u64)p[i] << (i * 8);
    return v;
}

static unsigned long align_up_ulong(unsigned long v, unsigned long align) {
    if (align <= 1) return v;
    return (v + align - 1) & ~(align - 1);
}

static struct import_entry* find_import_entry(struct import_entry* imports,
                                              unsigned int import_count,
                                              u32 sym_idx) {
    for (unsigned int i = 0; i < import_count; ++i) {
        if (imports[i].sym_idx == sym_idx) return &imports[i];
    }
    return 0;
}

static struct import_entry* get_or_create_import_entry(
    struct import_entry* imports, unsigned int* import_count, unsigned int import_cap,
    u32 sym_idx, u64 real, int is_func) {
    struct import_entry* ent = find_import_entry(imports, *import_count, sym_idx);
    if (ent) return ent;
    if (*import_count >= import_cap) return 0;
    ent = &imports[*import_count];
    ent->sym_idx = sym_idx;
    ent->real = real;
    ent->slot = 0;
    ent->veneer = 0;
    ent->is_func = is_func;
    (*import_count)++;
    return ent;
}

static u64 materialize_import_slot(struct import_entry* ent,
                                   u8* import_base,
                                   unsigned long* import_used,
                                   unsigned long import_area_size) {
    if (!ent) return 0;
    if (ent->slot) return ent->slot;
    unsigned long off = align_up_ulong(*import_used, 8);
    if (off > import_area_size || 8 > import_area_size - off) return 0;
    ent->slot = (u64)(unsigned long)(import_base + off);
    wr64_le(import_base + off, ent->real);
    *import_used = off + 8;
    return ent->slot;
}

static u64 materialize_import_veneer(struct import_entry* ent,
                                     u8* import_base,
                                     unsigned long* import_used,
                                     unsigned long import_area_size) {
    if (!ent) return 0;
    if (ent->veneer) return ent->veneer;
    unsigned long off = align_up_ulong(*import_used, 8);
    if (off > import_area_size || 16 > import_area_size - off) return 0;
    ent->veneer = (u64)(unsigned long)(import_base + off);
    /* ldr x16, #8 ; br x16 ; .quad target */
    wr32_le(import_base + off + 0, 0x58000050u);
    wr32_le(import_base + off + 4, 0xD61F0200u);
    wr64_le(import_base + off + 8, ent->real);
    *import_used = off + 16;
    return ent->veneer;
}

static u64 resolve_kpm_entry_section(const struct kpm_module* mod,
                                     const struct elf64_shdr* shdr,
                                     const char* section_name) {
    if (!mod || !shdr || !section_name) return 0;

    for (int i = 0; i < mod->section_count; ++i) {
        if (kpm_strcmp(mod->sections[i].name, section_name) != 0) continue;
        if (shdr->sh_flags & SHF_EXECINSTR) return mod->sections[i].va;
        if (mod->sections[i].size >= sizeof(u64)) return read_u64_le_local(mod->sections[i].addr);
        return 0;
    }

    return 0;
}

static struct kpm_system_table kpm_adjust_system_table(struct kpm_system_table* sys) {
    struct kpm_system_table out;
    kpm_memcpy(&out, sys, sizeof(out));

    /* Compute the KASLR slide: the difference between our actual runtime
     * address and the address the offline patcher expected.
     *
     * The patcher may store either raw file offsets (when kernel_va_base is
     * unavailable) or link-time VAs.  In both cases the slide is the delta
     * between &kpm_main at runtime and the stored loader entry, and
     * applying it to every pointer field gives the correct runtime address.
     */
    unsigned long actual_entry = (unsigned long)&kpm_main;
    unsigned long table_entry =
        (unsigned long)out.loader_base + out.loader_entry_offset;
    long slide = (long)(actual_entry - table_entry);

    if (slide != 0) {
        /* Helper: add slide to a pointer field, keeping NULL as NULL */
#define SLIDE_PTR(p) do { \
    if ((p)) p = (__typeof__(p))((unsigned long)(p) + (unsigned long)slide); \
} while (0)

        SLIDE_PTR(out.kallsyms_lookup_name);
        SLIDE_PTR(out.kmalloc);
        SLIDE_PTR(out.kfree);
        SLIDE_PTR(out.vmalloc);
        SLIDE_PTR(out.vfree);
        SLIDE_PTR(out.memset_impl);
        SLIDE_PTR(out.memcpy_impl);
        SLIDE_PTR(out.printk);
        SLIDE_PTR(out.filp_open_fn);
        SLIDE_PTR(out.kernel_read_fn);
        SLIDE_PTR(out.filp_close_fn);
        SLIDE_PTR(out.copy_from_user_fn);
        SLIDE_PTR(out.syscall_table);
        SLIDE_PTR(out.init_task);
        SLIDE_PTR(out.loader_base);
        SLIDE_PTR(out.kpm_module_list_head);
        /* kver is a string pointer that may be null — slide it too */
        if (out.kver)
            out.kver = (const char*)((unsigned long)out.kver + (unsigned long)slide);

#undef SLIDE_PTR
    }

    return out;
}

/* == Main KPM entry point == */
void kpm_main(struct kpm_system_table* sys, int command,
              const void* arg, unsigned long arg_size) {
    (void)command;
    (void)arg_size;

    if (!sys) return;

    /* Make a stack copy and adjust all function/data pointers for KASLR
     * BEFORE any function call.  The patcher may have stored raw file
     * offsets instead of kernel VAs for some kernel versions; the slide
     * computation corrects both cases.  sizeof(kpm_system_table) is ~200
     * bytes — well within the 16 KB kernel stack. */
    struct kpm_system_table adjusted = kpm_adjust_system_table(sys);
    sys = &adjusted;

    if (!sys->kmalloc || !sys->kfree) return;

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
                if (!sys->copy_from_user_fn) {
                    if (sys->printk)
                        sys->printk("SKRoot KPM: copy_from_user unavailable\n");
                    sys->kfree(kbuf);
                    return;
                }
                if (sys->copy_from_user_fn(kbuf, (const void*)(unsigned long)user_addr, kpm_size) != 0) {
                    if (sys->printk)
                        sys->printk("SKRoot KPM: copy_from_user failed\n");
                    sys->kfree(kbuf);
                    return;
                }
                if (sys->printk)
                    sys->printk("SKRoot KPM: loading from buffer size=%lu module=%s\n",
                                kpm_size, mod_name);
                int rc = kpm_load_elf(sys, kbuf, kpm_size, mod_name);
                if (sys->printk)
                    sys->printk("SKRoot KPM: buffer load rc=%d module=%s\n",
                                rc, mod_name);
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

            int rc = kpm_load_elf(sys, kbuf, (unsigned long)nread, mod_name);
            if (sys->printk)
                sys->printk("SKRoot KPM: file load rc=%d module=%s\n",
                            rc, mod_name);
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
    if (eh->e_shoff > elf_size) return -11;
    if ((unsigned long)eh->e_shnum > (elf_size - eh->e_shoff) / eh->e_shentsize) return -11;

    /* Parse section headers */
    u16 shnum = eh->e_shnum;
    const struct elf64_shdr* shdrs = (const struct elf64_shdr*)(elf_data + eh->e_shoff);

    /* Get section name string table */
    const struct elf64_shdr* shstr_hdr = &shdrs[eh->e_shstrndx];
    const u8* shstr_data = elf_data + shstr_hdr->sh_offset;

    /* Validate basic section bounds */
    if (!range_in_bounds(shstr_hdr->sh_offset, shstr_hdr->sh_size, elf_size)) return -11;
    if (shstr_hdr->sh_size == 0) return -11;
    if (elf_data[shstr_hdr->sh_offset + shstr_hdr->sh_size - 1] != 0) return -11;
    for (u16 i = 0; i < shnum; ++i) {
        if (shdrs[i].sh_name >= shstr_hdr->sh_size) return -11;
    }

    /* Find .kpm.info */
    const struct elf64_shdr* info_shdr = find_section(shdrs, shnum,
        (const char*)shstr_data, ".kpm.info");
    if (!info_shdr) return -12;

    /* Parse module name and version */
    char mod_name[KPM_MODULE_NAME_MAX] = {0};
    char mod_ver[32] = {0};
    if (range_in_bounds(info_shdr->sh_offset, info_shdr->sh_size, elf_size)) {
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

    /* Compute total workspace size: sum of all ALLOC sections.
     *
     * Reserve a small import area at the end of the same kmalloc object.  Some
     * KPMs are compiled with direct ADRP/LDR or CALL relocations against
     * undefined runtime API symbols.  The real runtime functions live in the
     * loader text cave, which can be more than ADRP/CALL reach away from the
     * kmalloc module image.  Per-symbol import slots and branch veneers placed
     * inside the module workspace keep those relocations in range.
     */
    const unsigned long import_area_size = 4096;
    unsigned long total_size = 0;
    unsigned long max_align = 1;
    for (u16 i = 0; i < shnum; ++i) {
        if (!(shdrs[i].sh_flags & SHF_ALLOC)) continue;
        unsigned long align = shdrs[i].sh_addralign;
        if (align < 1) align = 1;
        if (!is_power_of_two_ulong(align)) return -16;
        if (align > max_align) max_align = align;
        if (total_size > (unsigned long)-1 - (align - 1)) return -16;
        total_size = (total_size + align - 1) & ~(align - 1);
        if (shdrs[i].sh_size > (unsigned long)-1 - total_size) return -16;
        total_size += shdrs[i].sh_size;
    }
    if (total_size > (unsigned long)-1 - (max_align - 1)) return -16;
    total_size = (total_size + max_align - 1) & ~(max_align - 1);
    if (!total_size) return -16;
    unsigned long module_image_size = total_size;
    if (total_size > (unsigned long)-1 - import_area_size) return -16;
    total_size += import_area_size;

    /* Allocate workspace.
     * Prefer module_alloc() so loaded module text lives in executable memory.
     * Some Android 6.6 kernels mark kmalloc slabs NX, which would panic when
     * we branch into kpm_init()/kpm_ctl0()/kpm_exit().
     */
    typedef void* (*module_alloc_fn_t)(unsigned long);
    module_alloc_fn_t module_alloc_fn = 0;
    int workspace_use_vfree = 0;
    if (sys->kallsyms_lookup_name) {
        module_alloc_fn =
            (module_alloc_fn_t)sys->kallsyms_lookup_name("module_alloc");
    }

    u8* workspace = 0;
    if (module_alloc_fn) {
        unsigned long exec_size = align_up_ulong(total_size, 4096);
        workspace = (u8*)module_alloc_fn(exec_size);
        if (workspace) {
            total_size = exec_size;
            workspace_use_vfree = 1;
        }
    }
    if (!workspace) {
        workspace = (u8*)sys->kmalloc(total_size, GFP_KERNEL);
        workspace_use_vfree = 0;
    }
    if (!workspace) return -16;
    kpm_memset(workspace, 0, total_size);

#define FREE_WORKSPACE() do { \
    if (workspace) { \
        if (workspace_use_vfree && sys->vfree) sys->vfree(workspace); \
        else sys->kfree(workspace); \
    } \
} while (0)

    /* Copy sections - allocate mod on heap to avoid stack overflow */
    struct kpm_module* mod = (struct kpm_module*)sys->kmalloc(sizeof(struct kpm_module), GFP_KERNEL);
    if (!mod) {
        FREE_WORKSPACE();
        return -16;
    }
    kpm_memset(mod, 0, sizeof(*mod));
    mod->base = workspace;
    mod->size = total_size;
    mod->load_addr = (u64)(unsigned long)workspace;

    unsigned long cur_offset = 0;
    for (u16 i = 0; i < shnum; ++i) {
        if (!(shdrs[i].sh_flags & SHF_ALLOC)) continue;
        unsigned long align = shdrs[i].sh_addralign;
        if (align < 1) align = 1;
        if (!is_power_of_two_ulong(align)) {
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -21;
        }
        if (cur_offset > (unsigned long)-1 - (align - 1)) {
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -21;
        }
        cur_offset = (cur_offset + align - 1) & ~(align - 1);
        if (cur_offset > total_size || shdrs[i].sh_size > total_size - cur_offset) {
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -21;
        }

        const char* sec_name = (const char*)shstr_data + shdrs[i].sh_name;

        if (mod->section_count < 32) {
            mod->sections[mod->section_count].name = sec_name;
            mod->sections[mod->section_count].addr = workspace + cur_offset;
            mod->sections[mod->section_count].size = shdrs[i].sh_size;
            mod->sections[mod->section_count].va = mod->load_addr + cur_offset;
            mod->section_count++;
        }

        /* Copy section data from ELF to workspace (NOBITS = .bss, skip copy) */
        if (shdrs[i].sh_type != SHT_NOBITS && shdrs[i].sh_size > 0) {
            if (!range_in_bounds(shdrs[i].sh_offset, shdrs[i].sh_size, elf_size)) {
                sys->kfree(mod);
                FREE_WORKSPACE();
                return -21;
            }
            kpm_memcpy(workspace + cur_offset,
                      elf_data + shdrs[i].sh_offset,
                      shdrs[i].sh_size);
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
                if (range_in_bounds(str_hdr->sh_offset, str_hdr->sh_size, elf_size) &&
                    str_hdr->sh_size > 0 && elf_data[str_hdr->sh_offset + str_hdr->sh_size - 1] == 0) {
                    strtab_data = elf_data + str_hdr->sh_offset;
                    strtab_size = str_hdr->sh_size;
                }
            }
            break;
        }
    }

    if (!symtab_hdr || !strtab_data) {
        sys->kfree(mod);
        FREE_WORKSPACE();
        return -17;
    }

    /* Initialize runtime (if not already) - allocate on heap to avoid stack overflow */
    struct kpm_runtime_api* api = (struct kpm_runtime_api*)sys->kmalloc(sizeof(struct kpm_runtime_api), GFP_KERNEL);
    if (!api) {
        sys->kfree(mod);
        FREE_WORKSPACE();
        return -19;
    }
    kpm_memset(api, 0, sizeof(*api));

    /* Build runtime API symbol table */
    api->kallsyms_lookup_name = (void*)rt_kallsyms_lookup_name;
    api->hook_wrap = (void*)rt_hook_wrap;
    api->hook_unwrap_remove = (void*)rt_hook_unwrap_remove;
    api->fp_wrap_syscalln = (void*)rt_fp_wrap_syscalln;
    api->fp_unwrap_syscalln = (void*)rt_fp_unwrap_syscalln;
    api->kf_memset = (void*)rt_kf_memset;
    api->is_su_allow_uid = (void*)rt_is_su_allow_uid;
    api->pgtable_entry = (void*)rt_pgtable_entry;

    /* Populate data exports from system table */
    api->data_kver = (u64)parse_kernel_version_code(sys->kver);
    api->data_task_struct_offset = 0;
    api->data_cred_offset = sys->cred_offset;
    api->data_mm_struct_offset = sys->mm_struct_offset;
    api->data_thread_info_in_task = sys->thread_info_in_task;
    api->data_sp_el0_is_current = sys->sp_el0_is_current;
    api->data_sp_el0_is_thread_info = sys->sp_el0_is_thread_info;
    api->data_thread_size = sys->thread_size;
    api->data_task_in_thread_info_offset = sys->task_in_thread_info_offset;
    api->data_has_syscall_wrapper = sys->has_syscall_wrapper;

    kpm_runtime_init(sys, api);

    /* Resolve function symbols to code addresses and data symbols to stable slots. */
    /* Allocate api_syms on heap to avoid stack overflow (19 entries × 16 bytes = 304 bytes) */
    struct api_sym_entry* api_syms = (struct api_sym_entry*)sys->kmalloc(20 * sizeof(struct api_sym_entry), GFP_KERNEL);
    if (!api_syms) {
        sys->kfree(api);
        sys->kfree(mod);
        FREE_WORKSPACE();
        return -20;
    }

    api_syms[0].name = "kallsyms_lookup_name";   api_syms[0].addr = (u64)(unsigned long)rt_kallsyms_lookup_name; api_syms[0].is_func = 1;
    api_syms[1].name = "hook_wrap";              api_syms[1].addr = (u64)(unsigned long)rt_hook_wrap; api_syms[1].is_func = 1;
    api_syms[2].name = "hook_unwrap_remove";     api_syms[2].addr = (u64)(unsigned long)rt_hook_unwrap_remove; api_syms[2].is_func = 1;
    api_syms[3].name = "fp_wrap_syscalln";       api_syms[3].addr = (u64)(unsigned long)rt_fp_wrap_syscalln; api_syms[3].is_func = 1;
    api_syms[4].name = "fp_unwrap_syscalln";     api_syms[4].addr = (u64)(unsigned long)rt_fp_unwrap_syscalln; api_syms[4].is_func = 1;
    api_syms[5].name = "kf_memset";              api_syms[5].addr = (u64)(unsigned long)rt_kf_memset; api_syms[5].is_func = 1;
    api_syms[6].name = "is_su_allow_uid";        api_syms[6].addr = (u64)(unsigned long)rt_is_su_allow_uid; api_syms[6].is_func = 1;
    api_syms[7].name = "pgtable_entry";          api_syms[7].addr = (u64)(unsigned long)rt_pgtable_entry; api_syms[7].is_func = 1;
    /* Data exports — point to the u64 slot that holds the value */
    api_syms[8].name = "kver";                    api_syms[8].addr = (u64)(unsigned long)&api->data_kver; api_syms[8].is_func = 0;
    api_syms[9].name = "task_struct_offset";      api_syms[9].addr = (u64)(unsigned long)&api->data_task_struct_offset; api_syms[9].is_func = 0;
    api_syms[10].name = "cred_offset";            api_syms[10].addr = (u64)(unsigned long)&api->data_cred_offset; api_syms[10].is_func = 0;
    api_syms[11].name = "mm_struct_offset";       api_syms[11].addr = (u64)(unsigned long)&api->data_mm_struct_offset; api_syms[11].is_func = 0;
    api_syms[12].name = "thread_info_in_task";    api_syms[12].addr = (u64)(unsigned long)&api->data_thread_info_in_task; api_syms[12].is_func = 0;
    api_syms[13].name = "sp_el0_is_current";      api_syms[13].addr = (u64)(unsigned long)&api->data_sp_el0_is_current; api_syms[13].is_func = 0;
    api_syms[14].name = "sp_el0_is_thread_info";  api_syms[14].addr = (u64)(unsigned long)&api->data_sp_el0_is_thread_info; api_syms[14].is_func = 0;
    api_syms[15].name = "thread_size";            api_syms[15].addr = (u64)(unsigned long)&api->data_thread_size; api_syms[15].is_func = 0;
    api_syms[16].name = "task_in_thread_info_offset"; api_syms[16].addr = (u64)(unsigned long)&api->data_task_in_thread_info_offset; api_syms[16].is_func = 0;
    api_syms[17].name = "has_syscall_wrapper";    api_syms[17].addr = (u64)(unsigned long)&api->data_has_syscall_wrapper; api_syms[17].is_func = 0;
    api_syms[18].name = 0;                        api_syms[18].addr = 0; api_syms[18].is_func = 0;

    struct import_entry* imports =
        (struct import_entry*)sys->kmalloc(64 * sizeof(struct import_entry), GFP_KERNEL);
    if (!imports) {
        sys->kfree(api_syms);
        sys->kfree(api);
        sys->kfree(mod);
        FREE_WORKSPACE();
        return -20;
    }
    kpm_memset(imports, 0, 64 * sizeof(struct import_entry));
    unsigned int import_count = 0;
    unsigned long import_used = 0;
    u8* import_base = workspace + module_image_size;

    unsigned int got_needed = 0;
    for (u16 i = 0; i < shnum; ++i) {
        if (shdrs[i].sh_type != SHT_RELA) continue;
        if (shdrs[i].sh_entsize < sizeof(struct elf64_rela) ||
            !range_in_bounds(shdrs[i].sh_offset, shdrs[i].sh_size, elf_size) ||
            shdrs[i].sh_info >= shnum || shdrs[i].sh_link >= shnum) {
            sys->kfree(imports);
            sys->kfree(api_syms);
            sys->kfree(api);
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -22;
        }
        unsigned int rela_count = shdrs[i].sh_size / shdrs[i].sh_entsize;
        for (unsigned int j = 0; j < rela_count; ++j) {
            const struct elf64_rela* rela =
                (const struct elf64_rela*)(elf_data + shdrs[i].sh_offset) + j;
            u32 r_type = ELF64_R_TYPE(rela->r_info);
            if (r_type == R_AARCH64_ADR_GOT_PAGE ||
                r_type == R_AARCH64_LD64_GOT_LO12_NC) got_needed++;
        }
    }

    u64* got_table = 0;
    u32* got_sym_indices = 0;
    unsigned int got_idx = 0;
    if (got_needed > 0) {
        unsigned long got_off = align_up_ulong(import_used, 8);
        unsigned long got_bytes = got_needed * sizeof(u64);
        if (got_off > import_area_size || got_bytes > import_area_size - got_off) {
            sys->kfree(imports);
            sys->kfree(api_syms);
            sys->kfree(api);
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -18;
        }
        got_table = (u64*)(import_base + got_off);
        import_used = got_off + got_bytes;
        got_sym_indices = (u32*)sys->kmalloc(got_needed * sizeof(u32), GFP_KERNEL);
        if (!got_sym_indices) {
            if (got_sym_indices) sys->kfree(got_sym_indices);
            sys->kfree(imports);
            sys->kfree(api_syms);
            sys->kfree(api);
            sys->kfree(mod);
            FREE_WORKSPACE();
            return -18;
        }
        kpm_memset(got_table, 0, got_needed * sizeof(u64));
        kpm_memset(got_sym_indices, 0xFF, got_needed * sizeof(u32));
    }

    int reloc_failed = 0;
    int reloc_rc = 0;

    /* Apply all relocations */
    for (u16 i = 0; i < shnum; ++i) {
        if (shdrs[i].sh_type != SHT_RELA) continue;
        if (shdrs[i].sh_entsize < sizeof(struct elf64_rela) ||
            !range_in_bounds(shdrs[i].sh_offset, shdrs[i].sh_size, elf_size) ||
            shdrs[i].sh_info >= shnum || shdrs[i].sh_link >= shnum) {
            reloc_failed = 1;
            reloc_rc = -23;
            break;
        }

        /* Target section is sh_info */
        const struct elf64_shdr* target = &shdrs[shdrs[i].sh_info];
        u64 section_va = 0;
        u8* section_addr = 0;
        /* Find the VA and copied memory of the target section */
        for (int si = 0; si < mod->section_count; ++si) {
            if (kpm_strcmp(mod->sections[si].name,
                (const char*)shstr_data + target->sh_name) == 0) {
                section_va = mod->sections[si].va;
                section_addr = mod->sections[si].addr;
                break;
            }
        }
        if (!section_va || !section_addr) {
            reloc_failed = 1;
            reloc_rc = -24;
            break;
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
            int sym_found = 0;

            if (symtab_idx_for_rela < shnum) {
                const struct elf64_shdr* st_hdr = &shdrs[symtab_idx_for_rela];
                if (st_hdr->sh_entsize >= sizeof(struct elf64_sym) &&
                    range_in_bounds(st_hdr->sh_offset, st_hdr->sh_size, elf_size)) {
                    unsigned long sym_count = st_hdr->sh_size / st_hdr->sh_entsize;
                    if (sym_idx < sym_count) {
                        unsigned long sym_off = st_hdr->sh_offset +
                            (unsigned long)sym_idx * (unsigned long)st_hdr->sh_entsize;
                        const struct elf64_sym* sym =
                            (const struct elf64_sym*)(elf_data + sym_off);
                        sym_found = 1;
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
                                for (int si = 0; si < mod->section_count; ++si) {
                                    if (kpm_strcmp(mod->sections[si].name, secn) == 0) {
                                        sym_val = mod->sections[si].va + sym->st_value;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!sym_found || (!is_undef && !sym_val)) {
                reloc_failed = 1;
                reloc_rc = -29;
                break;
            }

            if (is_undef) {
                sym_val = 0;

                if (r_type == R_AARCH64_ADR_GOT_PAGE ||
                    r_type == R_AARCH64_LD64_GOT_LO12_NC) {
                    unsigned int gidx;
                    int found = 0;
                    for (gidx = 0; gidx < got_idx; ++gidx) {
                        if (got_sym_indices && got_sym_indices[gidx] == sym_idx) {
                            sym_val = (u64)(unsigned long)&got_table[gidx];
                            found = 1;
                            break;
                        }
                    }

                    if (!found) {
                        u64 real_sym = 0;
                        for (int ai = 0; api_syms[ai].name; ++ai) {
                            if (kpm_strcmp(sym_name, api_syms[ai].name) == 0) {
                                real_sym = api_syms[ai].addr;
                                break;
                            }
                        }
                        if (!real_sym && sys->kallsyms_lookup_name) {
                            real_sym = (u64)(unsigned long)
                                sys->kallsyms_lookup_name(sym_name);
                        }
                        if (!real_sym || !got_table || !got_sym_indices || got_idx >= got_needed) {
                            if (sys->printk) {
                                sys->printk("SKRoot KPM: unresolved GOT symbol %s type=%u\n",
                                            sym_name, r_type);
                            }
                            reloc_failed = 1;
                            reloc_rc = -25;
                            break;
                        }
                        got_table[got_idx] = real_sym + rela->r_addend;
                        got_sym_indices[got_idx] = sym_idx;
                        sym_val = (u64)(unsigned long)&got_table[got_idx];
                        got_idx++;
                    }
                } else {
                    u64 real_sym = 0;
                    int is_func_sym = 0;
                    struct import_entry* import_ent = 0;

                    for (int ai = 0; api_syms[ai].name; ++ai) {
                        if (kpm_strcmp(sym_name, api_syms[ai].name) == 0) {
                            real_sym = api_syms[ai].addr;
                            is_func_sym = api_syms[ai].is_func;
                            break;
                        }
                    }
                    if (!real_sym && sys->kallsyms_lookup_name) {
                        void* addr = sys->kallsyms_lookup_name(sym_name);
                        if (addr) real_sym = (u64)(unsigned long)addr;
                    }
                    if (!real_sym) {
                        if (sys->printk) {
                            sys->printk("SKRoot KPM: unresolved symbol %s type=%u\n",
                                        sym_name, r_type);
                        }
                        reloc_failed = 1;
                        reloc_rc = -26;
                        break;
                    }

                    if (r_type == R_AARCH64_CALL26 || r_type == R_AARCH64_JUMP26) {
                        import_ent = get_or_create_import_entry(
                            imports, &import_count, 64, sym_idx, real_sym, 1);
                        if (!import_ent) {
                            reloc_failed = 1;
                            reloc_rc = -31;
                            break;
                        }
                        sym_val = materialize_import_veneer(
                            import_ent, import_base, &import_used, import_area_size);
                    } else if (r_type == R_AARCH64_ADR_PREL_PG_HI21 ||
                               r_type == R_AARCH64_ADD_ABS_LO12_NC ||
                               r_type == R_AARCH64_LDST8_ABS_LO12_NC ||
                               r_type == R_AARCH64_LDST16_ABS_LO12_NC ||
                               r_type == R_AARCH64_LDST32_ABS_LO12_NC ||
                               r_type == R_AARCH64_LDST64_ABS_LO12_NC ||
                               r_type == R_AARCH64_LDST128_ABS_LO12_NC) {
                        import_ent = get_or_create_import_entry(
                            imports, &import_count, 64, sym_idx, real_sym, is_func_sym);
                        if (!import_ent) {
                            reloc_failed = 1;
                            reloc_rc = -31;
                            break;
                        }
                        sym_val = materialize_import_slot(
                            import_ent, import_base, &import_used, import_area_size);
                    } else {
                        sym_val = real_sym;
                    }

                    if (!sym_val) {
                        if (sys->printk) {
                            sys->printk("SKRoot KPM: import area exhausted for %s type=%u\n",
                                        sym_name, r_type);
                        }
                        reloc_failed = 1;
                        reloc_rc = -31;
                        break;
                    }
                }
            }

            int rc = apply_reloc(section_addr, section_va, rela, sym_val, target);
            if (rc < 0) {
                if (sys->printk) {
                    sys->printk("SKRoot KPM: reloc fail type=%u sym=%s rc=%d\n",
                                r_type, sym_name, rc);
                }
                reloc_failed = 1;
                reloc_rc = -27;
                break;
            }
        }
        if (reloc_failed) break;
    }

    if (reloc_failed) {
        if (sys->printk) {
            sys->printk("SKRoot KPM: relocation incomplete, abort init rc=%d\n", reloc_rc);
        }
        if (got_sym_indices) sys->kfree(got_sym_indices);
        sys->kfree(imports);
        sys->kfree(api_syms);
        sys->kfree(api);
        sys->kfree(mod);
        FREE_WORKSPACE();
        return reloc_rc ? reloc_rc : -28;
    }

    if (workspace_use_vfree && sys->kallsyms_lookup_name) {
        typedef int (*set_memory_x_fn_t)(unsigned long, int);
        set_memory_x_fn_t set_memory_x_fn =
            (set_memory_x_fn_t)sys->kallsyms_lookup_name("set_memory_x");
        if (set_memory_x_fn) {
            unsigned long page_count = (total_size + 4095) >> 12;
            set_memory_x_fn((unsigned long)workspace, (int)page_count);
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
                    for (int si2 = 0; si2 < mod->section_count; ++si2) {
                        if (kpm_strcmp(mod->sections[si2].name, secn) == 0) {
                            sec_va = mod->sections[si2].va;
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

        /* Fallback: support both executable entry sections and entry pointer slots. */
        if (!init_va && init_shdr)
            init_va = resolve_kpm_entry_section(mod, init_shdr, ".kpm.init");
        if (!ctl0_va && ctl0_shdr)
            ctl0_va = resolve_kpm_entry_section(mod, ctl0_shdr, ".kpm.ctl0");
        if (!exit_va && exit_shdr)
            exit_va = resolve_kpm_entry_section(mod, exit_shdr, ".kpm.exit");

        mod->init_func = (void (*)(void))(unsigned long)init_va;
        mod->ctl0_func = (void (*)(void*, unsigned long))(unsigned long)ctl0_va;
        mod->exit_func = (void (*)(void))(unsigned long)exit_va;
    }

    if (!entry_in_module(mod, (u64)(unsigned long)mod->init_func) ||
        !entry_in_module(mod, (u64)(unsigned long)mod->ctl0_func) ||
        !entry_in_module(mod, (u64)(unsigned long)mod->exit_func)) {
        if (sys->printk) sys->printk("SKRoot KPM: entry outside module, abort init\n");
        if (got_sym_indices) sys->kfree(got_sym_indices);
        sys->kfree(imports);
        sys->kfree(api_syms);
        sys->kfree(api);
        sys->kfree(mod);
        FREE_WORKSPACE();
        return -30;
    }

    /* Call init function */
    if (mod->init_func) {
        if (sys->printk) {
            sys->printk("SKRoot KPM: calling init for %s at %llx\n",
                        mod_name, (unsigned long long)(u64)mod->init_func);
        }
        mod->init_func();
    }

    if (sys->printk) {
        sys->printk("SKRoot KPM: loaded %s size=%lu\n", mod_name, total_size);
    }

    /* Keep api and got_table alive because loaded code may reference their slots. */
    if (got_sym_indices) sys->kfree(got_sym_indices);
    sys->kfree(imports);
    sys->kfree(api_syms);
    sys->kfree(mod);

    return 0;
}

/* Unload a module by name */
int kpm_unload_module(struct kpm_system_table* sys, const char* name) {
    if (sys->printk) {
        sys->printk("SKRoot KPM: unload unsupported in read-only runtime: %s\n",
                    name ? name : "");
    }
    return -1;
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
