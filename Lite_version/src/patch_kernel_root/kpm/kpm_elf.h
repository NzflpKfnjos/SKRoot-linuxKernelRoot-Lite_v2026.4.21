#ifndef KPM_ELF_H
#define KPM_ELF_H

/* Freestanding ELF64 definitions for kernel-side KPM loader.
 * No libc headers available — all types self-defined.
 */

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned short     u16;
typedef unsigned char      u8;
typedef signed long long   s64;
typedef signed int         s32;

/* ELF identification indices */
#define EI_MAG0       0
#define EI_MAG1       1
#define EI_MAG2       2
#define EI_MAG3       3
#define EI_CLASS      4
#define EI_DATA       5
#define EI_VERSION    6
#define EI_OSABI      7

#define ELFMAG0       0x7f
#define ELFMAG1       'E'
#define ELFMAG2       'L'
#define ELFMAG3       'F'

#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define EV_CURRENT    1

/* ELF types */
#define ET_NONE       0
#define ET_REL        1
#define ET_EXEC       2
#define ET_DYN        3

/* Machine */
#define EM_AARCH64    183

/* Section types */
#define SHT_NULL      0
#define SHT_PROGBITS  1
#define SHT_SYMTAB    2
#define SHT_STRTAB    3
#define SHT_RELA      4
#define SHT_NOBITS    8

/* Section flags */
#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

/* Symbol binding */
#define STB_LOCAL     0
#define STB_GLOBAL    1
#define STB_WEAK      2

/* Symbol type */
#define STT_NOTYPE    0
#define STT_OBJECT    1
#define STT_FUNC      2
#define STT_SECTION   3

/* Special section indices */
#define SHN_UNDEF     0
#define SHN_ABS       0xFFF1

#define ELF64_ST_BIND(i)    ((i) >> 4)
#define ELF64_ST_TYPE(i)    ((i) & 0xf)
#define ELF64_ST_INFO(b,t)  (((b) << 4) + ((t) & 0xf))

#define ELF64_R_SYM(i)      ((u32)((i) >> 32))
#define ELF64_R_TYPE(i)     ((u32)((i) & 0xffffffff))
#define ELF64_R_INFO(s,t)   (((u64)(s) << 32) + ((u64)(t) & 0xffffffff))

/* ELF64 header */
struct elf64_ehdr {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
};

/* ELF64 section header */
struct elf64_shdr {
    u32 sh_name;
    u32 sh_type;
    u64 sh_flags;
    u64 sh_addr;
    u64 sh_offset;
    u64 sh_size;
    u32 sh_link;
    u32 sh_info;
    u64 sh_addralign;
    u64 sh_entsize;
};

/* ELF64 symbol */
struct elf64_sym {
    u32 st_name;
    u8  st_info;
    u8  st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
};

/* ELF64 relocation with addend */
struct elf64_rela {
    u64 r_offset;
    u64 r_info;
    s64 r_addend;
};

#endif /* KPM_ELF_H */
