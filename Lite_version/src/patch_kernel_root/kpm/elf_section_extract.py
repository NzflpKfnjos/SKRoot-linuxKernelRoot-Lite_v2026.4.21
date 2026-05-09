#!/usr/bin/env python3
"""Extract all ALLOC sections from ELF64 ET_REL into a contiguous flat binary,
mimicking what a linker would produce when laying out sections.

Outputs the flat binary to <output>.bin and section layout info to <output>.h
"""

import struct
import sys

SECTION_FLAGS = {0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 8: 'NOBITS'}
SHF_WRITE = 0x1
SHF_ALLOC = 0x2

def parse_sections(data):
    if len(data) < 64:
        raise ValueError("File too small")

    e_shoff  = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum  = struct.unpack_from('<H', data, 60)[0]
    e_shstrndx = struct.unpack_from('<H', data, 62)[0]

    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("No section headers")

    sections = []
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh = {
            'idx': i,
            'name_off': struct.unpack_from('<I', data, sh_off)[0],
            'type':     struct.unpack_from('<I', data, sh_off + 4)[0],
            'flags':    struct.unpack_from('<Q', data, sh_off + 8)[0],
            'addr':     struct.unpack_from('<Q', data, sh_off + 16)[0],
            'offset':   struct.unpack_from('<Q', data, sh_off + 24)[0],
            'size':     struct.unpack_from('<Q', data, sh_off + 32)[0],
            'link':     struct.unpack_from('<I', data, sh_off + 40)[0],
            'info':     struct.unpack_from('<I', data, sh_off + 44)[0],
            'addralign':struct.unpack_from('<Q', data, sh_off + 48)[0],
            'entsize':  struct.unpack_from('<Q', data, sh_off + 56)[0],
        }
        sections.append(sh)

    # Resolve names
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    shstr_data_off = sections[e_shstrndx]['offset']
    shstr_data_sz  = sections[e_shstrndx]['size']

    def get_name(off):
        if off >= shstr_data_sz:
            return '?'
        end = data.index(0, shstr_data_off + off)
        return data[shstr_data_off + off : end].decode('ascii', errors='replace')

    for sh in sections:
        sh['name'] = get_name(sh['name_off'])

    return sections

def parse_symbols(data, sections):
    symbols = {}
    symtabs = [s for s in sections if s['type'] == 2 and s['entsize']]
    for symtab in symtabs:
        if symtab['link'] >= len(sections):
            continue
        strtab = sections[symtab['link']]
        str_base = strtab['offset']
        str_size = strtab['size']
        count = symtab['size'] // symtab['entsize']
        for i in range(count):
            off = symtab['offset'] + i * symtab['entsize']
            st_name = struct.unpack_from('<I', data, off)[0]
            st_value = struct.unpack_from('<Q', data, off + 8)[0]
            if st_name >= str_size:
                continue
            end = data.find(b'\0', str_base + st_name, str_base + str_size)
            if end < 0:
                continue
            name = data[str_base + st_name:end].decode('ascii', errors='replace')
            if name:
                symbols[name] = st_value
    return symbols

def layout_sections(sections, data):
    """Layout ALLOC sections in order, return (combined_binary, layout_info)."""
    alloc_sections = [s for s in sections if s['flags'] & SHF_ALLOC and s['size'] > 0]

    if not alloc_sections:
        raise ValueError("No ALLOC sections found")

    # Sort by section index (preserves original order from compilation)
    alloc_sections.sort(key=lambda s: s['idx'])

    # Layout: accumulate offset, align each section
    cur_offset = 0
    layout = []

    for sh in alloc_sections:
        align = sh['addralign']
        if align < 1:
            align = 1
        # Align
        cur_offset = (cur_offset + align - 1) & ~(align - 1)

        sec_data = b''
        if sh['type'] != 8:  # not NOBITS (.bss)
            if sh['offset'] + sh['size'] <= len(data):
                sec_data = data[sh['offset']:sh['offset'] + sh['size']]
        else:
            sec_data = b'\x00' * sh['size']

        layout.append({
            'name': sh['name'],
            'flags': sh['flags'],
            'offset': cur_offset,
            'size': sh['size'],
            'data': sec_data,
        })
        cur_offset += sh['size']

    # Final alignment to max alignment
    max_align = max((s['addralign'] for s in alloc_sections), default=1)
    total_size = (cur_offset + max_align - 1) & ~(max_align - 1)

    # Build combined binary
    combined = bytearray(total_size)
    for entry in layout:
        combined[entry['offset']:entry['offset'] + entry['size']] = entry['data']

    return bytes(combined), layout

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <elf.o> <output_prefix>")
        print(f"  Produces: <output_prefix>.bin  (flat binary)")
        print(f"            <output_prefix>.h    (layout info)")
        sys.exit(1)

    elf_path = sys.argv[1]
    prefix = sys.argv[2]

    with open(elf_path, 'rb') as f:
        data = f.read()

    sections = parse_sections(data)
    symbols = parse_symbols(data, sections)
    combined, layout = layout_sections(sections, data)
    entry_offset = symbols.get('kpm_main', 0)

    # Write binary
    bin_path = prefix + '.bin'
    with open(bin_path, 'wb') as f:
        f.write(combined)

    # Write layout header
    h_path = prefix + '_layout.h'
    with open(h_path, 'w') as f:
        f.write('#ifndef KPM_LOADER_LAYOUT_H\n')
        f.write('#define KPM_LOADER_LAYOUT_H\n\n')
        f.write(f'/* Auto-generated layout for {elf_path} */\n')
        f.write(f'/* Total binary size: {len(combined)} bytes */\n\n')
        f.write('struct kpm_loader_layout_entry {\n')
        f.write('    const char* name;\n')
        f.write('    unsigned long offset;\n')
        f.write('    unsigned long size;\n')
        f.write('    int is_exec;\n')
        f.write('    int is_write;\n')
        f.write('};\n\n')
        f.write('static const struct kpm_loader_layout_entry kpm_loader_layout[] = {\n')
        for entry in layout:
            is_exec = 1 if (entry['flags'] & 0x4) else 0  # SHF_EXECINSTR = 0x4
            is_write = 1 if (entry['flags'] & 0x1) else 0  # SHF_WRITE
            f.write(f'    {{"{entry["name"]}", {entry["offset"]}, {entry["size"]}, {is_exec}, {is_write}}},\n')
        f.write('    {0, 0, 0, 0, 0}\n')
        f.write('};\n\n')
        f.write(f'#define KPM_LOADER_BIN_SIZE {len(combined)}\n')
        f.write(f'#define KPM_LOADER_TEXT_ADDR_OFFSET 0\n')
        f.write(f'#define KPM_LOADER_ENTRY_OFFSET {entry_offset}\n')
        f.write('\n#endif\n')

    print(f"Extracted: {len(combined)} bytes → {bin_path}")
    print(f"Layout:    {h_path}")
    print(f"Entry:     kpm_main @ {entry_offset:#x}")
    for entry in layout:
        print(f"  [{entry['name']:20s} off={entry['offset']:#06x} size={entry['size']:6d}]")

if __name__ == '__main__':
    main()
