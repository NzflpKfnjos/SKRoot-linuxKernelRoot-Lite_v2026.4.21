#ifndef KPM_LOADER_LAYOUT_H
#define KPM_LOADER_LAYOUT_H

/* Auto-generated layout for kpm_loader.o */
/* Total binary size: 12992 bytes */

struct kpm_loader_layout_entry {
    const char* name;
    unsigned long offset;
    unsigned long size;
    int is_exec;
    int is_write;
};

static const struct kpm_loader_layout_entry kpm_loader_layout[] = {
    {".text", 0, 11696, 1, 0},
    {".rodata.cst16", 11696, 384, 0, 0},
    {".rodata.cst8", 12080, 16, 0, 0},
    {".bss", 12096, 32, 0, 1},
    {".rodata.str1.1", 12128, 854, 0, 0},
    {0, 0, 0, 0, 0}
};

#define KPM_LOADER_BIN_SIZE 12992
#define KPM_LOADER_TEXT_ADDR_OFFSET 0

#endif
