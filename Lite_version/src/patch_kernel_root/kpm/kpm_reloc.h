#ifndef KPM_RELOC_H
#define KPM_RELOC_H

#include "kpm_elf.h"

/* AArch64 ELF relocation types */
#define R_AARCH64_NONE              0
#define R_AARCH64_ABS64           257
#define R_AARCH64_ABS32           258
#define R_AARCH64_CALL26          283
#define R_AARCH64_JUMP26          282
#define R_AARCH64_ADR_GOT_PAGE    311
#define R_AARCH64_LD64_GOT_LO12_NC 312
#define R_AARCH64_ADR_PREL_PG_HI21 275
#define R_AARCH64_ADD_ABS_LO12_NC 277
#define R_AARCH64_LDST128_ABS_LO12_NC 279
#define R_AARCH64_CONDBR19        280
#define R_AARCH64_LDST64_ABS_LO12_NC 286

/* == Bit manipulation helpers == */
static u32 rd32_le(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static void wr32_le(u8* p, u32 v) {
    p[0] = (u8)(v);
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

static void wr64_le(u8* p, u64 v) {
    wr32_le(p, (u32)(v));
    wr32_le(p + 4, (u32)(v >> 32));
}

/* Sign-extend a value within a given bit width */
static s64 sext(s64 val, int bits) {
    u64 shift = 64 - bits;
    return (s64)(((u64)val << shift) >> shift);
}

static int apply_reloc(u8* base, u64 base_addr,
                       const struct elf64_rela* rela,
                       u64 sym_val,
                       const struct elf64_shdr* target_shdr __attribute__((unused))) {
    u32 r_type = ELF64_R_TYPE(rela->r_info);
    u64 P = base_addr + rela->r_offset;  /* relocation place address */
    u64 A = (u64)rela->r_addend;          /* addend */
    u64 S = sym_val;                      /* symbol value */
    u8* loc = base + rela->r_offset;

    switch (r_type) {
    case R_AARCH64_NONE:
        break;

    case R_AARCH64_ABS64:
        wr64_le(loc, S + A);
        break;

    case R_AARCH64_JUMP26:
    case R_AARCH64_CALL26: {
        s64 delta = (s64)(S + A - P);
        if ((delta & 3) != 0) return -1;
        s64 imm = delta >> 2;
        if (imm < -(1LL << 25) || imm >= (1LL << 25)) return -2;
        u32 insn = rd32_le(loc);
        insn &= ~0x03FFFFFFu;
        insn |= (u32)(imm & 0x03FFFFFFu);
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_ADR_PREL_PG_HI21: {
        /* ADRP: compute page delta */
        s64 page_delta = (s64)((S + A) & ~0xFFFULL) - (s64)(P & ~0xFFFULL);
        s64 imm21 = page_delta >> 12;
        if (imm21 < -(1LL << 20) || imm21 >= (1LL << 20)) return -2;
        u32 insn = rd32_le(loc);
        u32 immlo = (u32)(imm21 & 0x3);
        u32 immhi = (u32)((imm21 >> 2) & 0x7FFFF);
        insn &= ~(0x3u << 29 | 0x7FFFFu << 5);
        insn |= immlo << 29 | immhi << 5;
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_ADD_ABS_LO12_NC: {
        u32 imm12 = (u32)((S + A) & 0xFFF);
        /* ADD: imm12 is in bits [21:10] */
        u32 insn = rd32_le(loc);
        insn &= ~(0xFFFu << 10);
        insn |= imm12 << 10;
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_LDST64_ABS_LO12_NC: {
        u32 imm12 = (u32)((S + A) & 0xFFF);
        u32 insn = rd32_le(loc);
        /* LDR/STR unsigned offset: imm12 scaled by 8 for 64-bit,
         * but in UXTW form the immediate is in bits [21:10] unscaled.
         * The encoding uses bits [21:10] as a 12-bit immediate. */
        insn &= ~(0xFFFu << 10);
        insn |= imm12 << 10;
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_CONDBR19: {
        s64 delta = (s64)(S + A - P);
        if ((delta & 3) != 0) return -1;
        s64 imm = delta >> 2;
        if (imm < -(1LL << 18) || imm >= (1LL << 18)) return -2;
        u32 insn = rd32_le(loc);
        insn &= ~(0x7FFFFu << 5);
        insn |= (u32)(imm & 0x7FFFFu) << 5;
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_ADR_GOT_PAGE: {
        /* ADRP instruction referencing a GOT entry.
         * At this point, sym_val should be the ABSOLUTE address of the
         * GOT entry for this symbol.
         * The instruction is an ADRP (bit 31=1, bits[30:29]=immlo,
         * bits[28:24]=10000, bits[23:5]=immhi, bits[4:0]=Rd).
         * We compute the page delta from the ADRP's page to the GOT entry's page.
         */
        u64 got_addr = S;  /* S is already the GOT entry address */
        s64 page_delta = (s64)(got_addr & ~0xFFFULL) - (s64)(P & ~0xFFFULL);
        s64 imm21 = page_delta >> 12;
        if (imm21 < -(1LL << 20) || imm21 >= (1LL << 20)) return -2;
        u32 insn = rd32_le(loc);
        u32 immlo2 = (u32)(imm21 & 0x3);
        u32 immhi2 = (u32)((imm21 >> 2) & 0x7FFFF);
        insn &= ~(0x3u << 29 | 0x7FFFFu << 5);
        insn |= immlo2 << 29 | immhi2 << 5;
        wr32_le(loc, insn);
        break;
    }

    case R_AARCH64_LD64_GOT_LO12_NC: {
        /* LDR Xt, [Xbase, #:lo12:got_entry]
         * The instruction is an LDR (unsigned offset) with the GOT entry's
         * low 12 bits as the offset.
         * sym_val (S) should be the GOT entry address.
         */
        u32 imm12 = (u32)((u64)S & 0xFFF);
        /* LDR 64-bit: imm12 scaled by 8, so we divide by 8 */
        u32 scaled_imm = imm12 >> 3;
        u32 insn = rd32_le(loc);
        insn &= ~(0xFFFu << 10);
        insn |= scaled_imm << 10;
        wr32_le(loc, insn);
        break;
    }

    default:
        /* Unknown relocation type — return error */
        return -(int)r_type;
    }

    return 0;
}

/* == GOT management == */
struct kpm_got_entry {
    const char* sym_name;
    u64 got_addr;       /* absolute VA of this GOT entry */
    u64 sym_value;      /* resolved symbol value (S) */
    int resolved;
};

/* Simple linear GOT — we allocate a contiguous array of u64 slots,
 * one per undefined symbol that generates GOT references.
 */

/* Allocate and build a GOT table for a module.
 * got_base_out: receives start of GOT region in module workspace
 * got_count: number of entries to allocate
 * Returns 0 on success, -1 on error.
 */
static int kpm_got_alloc(void* (*kmalloc_fn)(unsigned long, unsigned int),
                         unsigned int count, u64** got_base_out) {
    if (count == 0) {
        *got_base_out = 0;
        return 0;
    }
    /* GFP_KERNEL = 0xCC0 typically, but we use the raw alloc */
    u64* got = (u64*)kmalloc_fn((unsigned long)count * sizeof(u64), 0xCC0);
    if (!got) return -1;
    for (unsigned int i = 0; i < count; ++i) got[i] = 0;
    *got_base_out = got;
    return 0;
}

#endif /* KPM_RELOC_H */
