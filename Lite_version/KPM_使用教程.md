# SKRoot KPM 使用文档

本文档对应当前仓库版本，已经包含本次修复后的 KPM 运行时与 `kpmctl.sh`。

---

## 1. 这次修复了什么

本次主要修复了两个导致 `.kpm` 无法正常加载的问题：

1. **运行时符号重定位超范围**
   - 典型报错：
     - `reloc fail type=275 sym=kallsyms_lookup_name rc=-2`
     - `reloc fail type=311 sym=cred_offset rc=-2`
   - 现已改为在模块附近生成导入槽 / veneer，避免 AArch64 ADRP/CALL 超范围。

2. **模块代码被分配到不可执行内存**
   - 现已优先使用 `module_alloc()` 分配模块工作区，并在需要时调用 `set_memory_x()`。
   - 否则模块会在 `calling init for ...` 后直接触发内核崩溃或重启。

当前已在你的设备内核上验证通过：

- `noop.kpm`
- `markroot.kpm`
- `tomato.kpm`

---

## 2. 适用场景

KPM（Kernel Patch Module）用于在 **已经打入 SKRoot KPM Loader 的 boot/kernel** 上，动态加载 `.kpm` 模块。

也就是说，想加载 `.kpm`，必须先满足：

- 设备已经刷入带 KPM Loader 的 `boot.img`
- 设备当前能够拿到 root shell

---

## 3. 你当前设备的已知可用方式

你的设备当前可用 `su`：

```sh
/data/MoFS20amQM1zKk0p/su
```

后文示例都可以直接套用这个路径。

---

## 4. kpmctl 脚本位置

仓库中的脚本：

```text
Lite_version/src/kpmctl/kpmctl.sh
```

本次已修复：

- 去掉 `busybox env` 依赖，直接使用系统 `env`
- 处理了 Windows CRLF 导致的脚本报错
- 改成更适合 Android toybox 的写法

---

## 5. 推送到设备

```sh
adb push Lite_version/src/kpmctl/kpmctl.sh /data/local/tmp/kpmctl
adb shell chmod 755 /data/local/tmp/kpmctl

adb push tomato.kpm /data/local/tmp/tomato.kpm
adb push markroot.kpm /data/local/tmp/markroot.kpm
```

---

## 6. 基本用法

### 6.1 检查 KPM 运行时

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl status'"
```

如果正常，通常会看到：

```text
KPM runtime: AVAILABLE
```

如果当前内核构建不输出 `@LS` 探测日志，也可能看到：

```text
KPM runtime: UNKNOWN
Reason: this build does not print @LS probe logs.
Tip: use 'load <module.kpm>' to verify actual availability.
```

这不代表 KPM 一定不可用；你这台设备上就是这种情况，实际 `load tomato.kpm` 仍可成功。

---

### 6.2 加载模块

加载 `tomato.kpm`：

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm'"
```

加载 `markroot.kpm`：

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl load /data/local/tmp/markroot.kpm'"
```

成功时内核日志类似：

```text
SKRoot KPM: loading from file /data/local/tmp/tomato.kpm
SKRoot KPM: read 16824 bytes, module=tomato
SKRoot KPM: calling init for Module at ...
SKRoot KPM: loaded Module size=12288
SKRoot KPM: file load rc=0 module=tomato
```

---

### 6.3 列出模块

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl list'"
```

---

### 6.4 卸载模块

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl unload tomato'"
```

---

## 7. 已知限制

### 7.1 `list` 可能仍然没有输出

当前加载器的模块链表设计仍受只读运行时限制影响，某些版本上：

- 模块实际已经加载成功
- 但 `list` 仍可能显示 `0 module(s)`

因此当前建议以 `load` 时的 `dmesg` 日志为准。

### 7.2 `unload` 仍不是完整卸载

当前 `unload` 不是完整内存回收版卸载。
如果你需要完全干净的状态，最稳妥的方法仍然是：

```text
重启设备
```

---

## 8. 常见错误排查

### 8.1 `syntax error: unexpected 'in\r'`

原因：

- 脚本是 Windows CRLF 行尾

处理：

- 使用仓库里这次修复后的 `kpmctl.sh`
- 重新 `adb push`

---

### 8.2 `busybox: not found`

原因：

- 老脚本依赖 `busybox env`
- 你的设备没有 busybox

处理：

- 使用本次修复后的脚本

---

### 8.3 `KPM runtime: UNKNOWN` 或 `list` 没输出

优先检查：

1. 当前 boot 是否真的是带 KPM Loader 的版本
2. 是否通过 root shell 执行
3. 是否已经刷入本次修复后的 boot

建议直接手工触发一次：

```sh
adb shell "/data/MoFS20amQM1zKk0p/su -c 'dmesg -C; env -i @LS 2>/dev/null; sleep 1; dmesg -c | tail -n 50'"
```

---

如果你的构建本身不打印 `@LS`，最可靠的检查方法仍然是直接加载一个已知可用模块。

### 8.4 出现 `reloc fail type=275/311`

这属于本次已经修掉的旧问题。

如果你又看到了，通常表示：

- 设备还在跑旧 boot
- 没有真正刷入最新修复镜像

---

### 8.5 模块一加载就重启

这通常表示模块代码落在 NX 内存、或正在运行旧版加载器。

本次修复后，`noop.kpm / markroot.kpm / tomato.kpm` 已可正常加载。

---

## 9. 重新制作带 KPM 修复的 boot.img

如果你要重新从原始 `boot.img` 打补丁，流程如下。

### 9.1 解包

```sh
magiskboot unpack -h boot.img
```

会得到：

- `kernel`
- `header`

### 9.2 重新编译 patcher

在 WSL / Linux 下：

```sh
cd Lite_version/src/patch_kernel_root/kpm
make clean && make

cd ..
make
```

### 9.3 给 kernel 打补丁

```sh
./patch_kernel_root /path/to/kernel
```

按提示输入 root key。

### 9.4 重新打包

```sh
magiskboot repack boot.img new-boot.img
```

### 9.5 刷入

如果 fastboot 不能直接写分区，可在 root shell 下用 `dd`：

```sh
adb push new-boot.img /data/local/tmp/new-boot.img
adb shell "/data/MoFS20amQM1zKk0p/su -c 'dd if=/data/local/tmp/new-boot.img of=/dev/block/by-name/boot_a bs=4M; sync'"
adb reboot
```

---

## 10. 本仓库当前建议使用的文件

### 运行脚本

```text
Lite_version/src/kpmctl/kpmctl.sh
```

### 已修复的 boot 镜像产物

本次调试过程中最终稳定验证通过的是：

```text
boot_build_import_fix_v4/boot_a_kpm_import_fix_v4.img
```

### 设备当前 boot_a 备份

```text
boot_a_live_backup.img
```

---

## 11. 推荐最小操作流程

如果你只是想在当前设备上继续用 KPM，最推荐直接这样做：

```sh
adb push Lite_version/src/kpmctl/kpmctl.sh /data/local/tmp/kpmctl
adb shell chmod 755 /data/local/tmp/kpmctl

adb push tomato.kpm /data/local/tmp/tomato.kpm

adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl status'"
adb shell "/data/MoFS20amQM1zKk0p/su -c 'sh /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm'"
```

---

## 12. 附：本次实机验证结果

已成功看到以下结果：

### `markroot.kpm`

```text
SKRoot KPM: loading from file /data/local/tmp/markroot.kpm
SKRoot KPM: read 1536 bytes, module=markroot
SKRoot KPM: calling init for markroot at ...
SKRoot KPM: loaded markroot size=8192
SKRoot KPM: file load rc=0 module=markroot
```

### `tomato.kpm`

```text
SKRoot KPM: loading from file /data/local/tmp/tomato.kpm
SKRoot KPM: read 16824 bytes, module=tomato
SKRoot KPM: calling init for Module at ...
SKRoot KPM: loaded Module size=12288
SKRoot KPM: file load rc=0 module=tomato
```

---

如果你愿意，我下一步还可以继续帮你：

1. 再补一个 **一键 adb 调试脚本（Windows）**
2. 或者把 `kpmctl` 再做一个 **自动套 su 的设备专用版**
