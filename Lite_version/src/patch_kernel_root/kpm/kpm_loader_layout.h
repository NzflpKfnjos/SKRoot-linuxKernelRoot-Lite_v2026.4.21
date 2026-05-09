#ifndef KPM_LOADER_LAYOUT_H
#define KPM_LOADER_LAYOUT_H

/* Auto-generated layout for kpm_loader.elf */
/* Total binary size: 14992 bytes */

struct kpm_loader_layout_entry {
    const char* name;
    unsigned long offset;
    unsigned long size;
    int is_exec;
    int is_write;
};

static const struct kpm_loader_layout_entry kpm_loader_layout[] = {
    {".text", 0, 13512, 1, 0},
    {".rodata", 13520, 1462, 0, 0},
    {".got", 14984, 8, 0, 1},
    {0, 0, 0, 0, 0}
};

#define KPM_LOADER_BIN_SIZE 14992
#define KPM_LOADER_TEXT_ADDR_OFFSET 0
#define KPM_LOADER_ENTRY_OFFSET 2192

#endif
