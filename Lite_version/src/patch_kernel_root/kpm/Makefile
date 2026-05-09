CC     := clang
TARGET := aarch64-linux-gnu

CFLAGS := --target=$(TARGET) \
          -ffreestanding -nostdinc -fno-builtin \
          -fPIC -fno-stack-protector -fno-asynchronous-unwind-tables \
          -fvisibility=hidden -Os -g0 \
          -march=armv8-a -Wall -Wextra -Wno-unused-function \
          -I. -D__KERNEL__ \
          -fno-builtin-memcpy -fno-builtin-memset

TARGET_O := kpm_loader.o
TARGET_ELF := kpm_loader.elf
PREFIX   := kpm_loader

.PHONY: all clean

all: $(PREFIX).bin $(PREFIX)_data.h

$(TARGET_O): kpm_all.c kpm_libc.h kpm_elf.h kpm_reloc.h kpm_runtime.h kpm_loader.h kpm_shellcode.h kpm_runtime.c kpm_loader.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_ELF): $(TARGET_O) kpm_loader.ld
	ld.lld -nostdlib -static -T kpm_loader.ld -o $@ $<

$(PREFIX).bin: $(TARGET_ELF) elf_section_extract.py
	python3 elf_section_extract.py $< $(PREFIX)

$(PREFIX)_data.h: $(PREFIX).bin
	xxd -i $< > $@

clean:
	rm -f $(TARGET_O) $(TARGET_ELF) $(PREFIX).bin $(PREFIX)_data.h $(PREFIX)_layout.h
