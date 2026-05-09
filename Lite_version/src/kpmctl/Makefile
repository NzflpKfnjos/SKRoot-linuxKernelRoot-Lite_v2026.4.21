# Build kpmctl for Android ARM64
#
# Requirements (one of):
#   1. Android NDK:  export NDK=/path/to/ndk
#   2. aarch64-linux-gnu-gcc (Linux cross-compiler)
#   3. Termux on device: just run: clang -static -o kpmctl kpmctl.c
#
# Usage:
#   make NDK=/path/to/android-ndk
#   make CROSS=aarch64-linux-gnu-
#   make                          (auto-detect)

.PHONY: all clean

all: kpmctl

# --- NDK path ---
ifdef NDK
  # Android NDK toolchain
  NDK_TC := $(NDK)/toolchains/llvm/prebuilt/darwin-x86_64
  ifeq ($(wildcard $(NDK_TC)),)
    NDK_TC := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
  endif
  ifeq ($(wildcard $(NDK_TC)),)
    NDK_TC := $(NDK)/toolchains/llvm/prebuilt/windows-x86_64
  endif
  CC := $(NDK_TC)/bin/aarch64-linux-android21-clang
else ifdef CROSS
  CC := $(CROSS)gcc
else
  # Auto-detect: try NDK, then aarch64-linux-gnu-gcc, then native
  CC := $(shell command -v aarch64-linux-gnu-gcc 2>/dev/null)
  ifeq ($(CC),)
    CC := $(shell command -v aarch64-linux-android21-clang 2>/dev/null)
  endif
  ifeq ($(CC),)
    CC := clang --target=aarch64-linux-gnu
  endif
endif

CFLAGS := -static -Os -Wall -Wextra

kpmctl: kpmctl.c
	$(CC) $(CFLAGS) -o $@ $<
	file $@ 2>/dev/null || true

clean:
	rm -f kpmctl
