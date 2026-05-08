# SKRoot Self-Hosted KPM Runtime — 完整使用教程

## 概述

SKRoot 现在内置了 KPM（Kernel Patch Module）运行时，可以动态加载 `.kpm` 模块，**不需要 APatch / KernelPatch / KSU 等任何第三方框架**。

### 工作原理

```
┌──────────────────────┐     execve("@LD:...")     ┌──────────────────────┐
│  Userspace           │ ─────────────────────────→ │  Kernel (boot-patch) │
│                      │                            │                      │
│  kpmctl load x.kpm   │      do_execve hook        │  KPM ELF Loader      │
│  kpmctl unload name  │      检测 '@' 前缀          │ ├ 解析 ELF64        │
│  kpmctl list         │      分发到 KPM handler     │ ├ 重定位 AArch64    │
│                      │                            │ ├ 解析 18 个 API    │
│  或 SKRoot APP 调用   │                            │ ├ 调用 init_module  │
│  skroot_kpm_load()   │                            │ └ 管理模块链表      │
└──────────────────────┘                            └──────────────────────┘
```

---

## 第一步：构建内核补丁

### 1.1 准备内核文件

从设备的 `boot.img` 中提取内核二进制文件：

```bash
# 使用 Android Image Kitchen (AIK)
# 将 boot.img 放入 AIK 目录，运行 unpackimg.sh
./unpackimg.sh boot.img

# 内核文件位于 split_img/boot.img-kernel
```

或者如果已有独立的 kernel 文件（如 vmlinux、Image、kernel_dump），直接使用。

### 1.2 运行补丁工具

```bash
cd src/patch_kernel_root

# 编译（首次需要，生成 patch_kernel_root 可执行文件）
make

# 运行补丁
./patch_kernel_root /path/to/kernel_image
```

工具会依次执行：

1. **分析内核符号** — 解析 kallsyms 表，定位所有需要的函数
2. **计算偏移量** — cred、seccomp 等在 task_struct 中的位置
3. **CFI / 华为绕过** — 如果检测到
4. **KPM Runtime 集成** — 查找 kmalloc/kfree/printk/filp_open/kernel_read/filp_close 等 API

   成功后会显示：
   ```
   === KPM Loader Integration ===
   kmalloc: 0xffffffc001234560
   kfree:   0xffffffc001234780
   printk:  0xffffffc001234900
   KPM loader embedding:
     handler:     0xffffffc009876000
     loader:      0xffffffc009876200  (13248 bytes)
     system tbl:  0xffffffc009879800  (144 bytes)
   KPM handler: 0xffffffc009876000
   ```

   如果显示 `[WARN] KPM loader skipped: missing kernel API symbols`，说明内核中没找到所需 API（极少数精简内核可能出现）。

   如果显示 `[WARN] Not enough kernel space for KPM loader`，说明没有足够大的未使用区域（需要 ≥16KB）。

5. **输入 ROOT 密匙** — 48 个字符的密钥，用于 root 权限验证

6. **写入修改** — 将补丁写入内核文件

### 1.3 刷入设备

```bash
# 重新打包 boot.img
./repackimg.sh

# 刷入设备
adb reboot bootloader
fastboot flash boot image-new.img
fastboot reboot
```

---

## 第二步：安装 KPM 管理工具

### 2.1 编译 kpmctl

`kpmctl` 是一个极简的 ARM64 命令行工具，通过 `execve` 系统调用与内核 KPM 运行时通信。

**方法 A：使用 Android NDK 编译**
```bash
cd src/kpmctl
make NDK=/path/to/android-ndk
```

**方法 B：在设备上直接编译（需要 Termux）**
```bash
# 在设备的 Termux 中
pkg install clang
cd /sdcard/kpmctl
clang -static -o kpmctl kpmctl.c
```

**方法 C：使用预编译二进制**

如果无法编译，可以直接在设备上用 shell 触发 KPM 命令（见"无工具使用"章节）。

### 2.2 推送到设备

```bash
adb push kpmctl /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kpmctl
```

---

## 第三步：使用 KPM

### 3.1 加载模块

```bash
# 推送 .kpm 文件到设备
adb push tomato.kpm /data/local/tmp/

# 加载
adb shell /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm

# 查看结果
adb shell dmesg | grep 'SKRoot KPM'
```

输出示例：
```
SKRoot KPM: loading from file /data/local/tmp/tomato.kpm
SKRoot KPM: read 16824 bytes, module=Module
SKRoot KPM: calling init for Module at ffffffc009877000
SKRoot KPM: loaded Module size=32896
```

### 3.2 查看已加载模块

```bash
adb shell /data/local/tmp/kpmctl list
adb shell dmesg -c | grep 'SKRoot KPM'
```

输出示例：
```
SKRoot KPM: loaded modules:
  [0] Module base=ffffffc009877000 size=32896
SKRoot KPM: 1 module(s)
```

### 3.3 卸载模块

```bash
adb shell /data/local/tmp/kpmctl unload Module
adb shell dmesg -c | grep 'SKRoot KPM'
```

输出示例：
```
SKRoot KPM: unloaded Module
```

### 3.4 检测 KPM 运行时

```bash
adb shell /data/local/tmp/kpmctl status
```

---

## 第四步：通过 SKRoot APP 调用

如果需要在 APP 中使用 KPM 功能，使用 JNI 接口：

### 4.1 API 函数

```cpp
#include "rootkit_kpm_test.h"

namespace kernel_root {

// 探测 KPM 运行时是否可用
KRootErr skroot_kpm_probe(const char* root_key, bool& out_available);

// 加载 .kpm 文件
KRootErr skroot_kpm_load(const char* root_key,
                         const char* kpm_path,
                         std::string& out_module_name);

// 卸载模块
KRootErr skroot_kpm_unload(const char* root_key,
                           const char* module_name);

// 列出已加载模块
KRootErr skroot_kpm_list(const char* root_key,
                         std::vector<SkrootKpmInfo>& out_modules);

}
```

### 4.2 使用示例

```cpp
// 1. 获取 root
KRootErr err = get_root(root_key);
if (is_failed(err)) { /* 处理错误 */ }

// 2. 探测 KPM 运行时
bool kpm_available = false;
skroot_kpm_probe(root_key, kpm_available);
if (!kpm_available) {
    // KPM runtime 未嵌入内核
    // 可能是内核空间不足或缺少 API 符号
    return;
}

// 3. 加载模块
std::string mod_name;
err = skroot_kpm_load(root_key,
    "/data/local/tmp/tomato.kpm", mod_name);
if (is_ok(err)) {
    LOGI("KPM loaded: %s", mod_name.c_str());
}

// 4. 查看模块列表
std::vector<SkrootKpmInfo> modules;
skroot_kpm_list(root_key, modules);
for (auto& m : modules) {
    LOGI("  %s (v%s)", m.name.c_str(), m.version.c_str());
}

// 5. 卸载
skroot_kpm_unload(root_key, "Module");
```

---

## 第五步：无工具使用（直接 Shell）

如果不想编译 `kpmctl`，可以直接用 shell 命令通过 busybox 的 `env` 触发：

### 5.1 加载模块

```bash
# 方法1：文件路径模式（需要内核嵌入了 VFS API）
# busybox env -i 会执行 execve，触发内核 hook
busybox env -i @LD:/data/local/tmp/tomato.kpm

# 方法2：手动 mmap 模式（通过 SKRoot APP 或自编程序）
# 需要 root 权限读取文件，然后 mmap 到内存，再传地址
```

### 5.2 卸载模块

```bash
busybox env -i @UL:Module
```

### 5.3 查看模块

```bash
busybox env -i @LS
dmesg | grep 'SKRoot KPM'
```

---

## 命令协议参考

底层通信协议（供开发者参考）：

| 命令 | 格式 | 说明 |
|------|------|------|
| 加载（内存） | `@LD:<hex_addr>,<hex_size>,<name>` | 从用户态内存地址加载 |
| 加载（文件） | `@LD:<absolute_path>` | 通过 VFS 从磁盘读取 |
| 卸载 | `@UL:<module_name>` | 按名称卸载 |
| 列表 | `@LS` | 输出已加载模块到内核日志 |

触发方式：
```c
syscall(__NR_execve, "@XX:...", NULL, NULL);
```

**注意**：`execve` 调用会返回错误（因为 "@XX:..." 不是有效可执行文件），但内核钩子的副作用（加载/卸载）已经生效。这就是为什么 `kpmctl` 不需要特殊权限。

---

## 常见问题

### Q: 补丁工具显示 "KPM loader skipped"

**原因**：内核中没找到 kmalloc / kfree / printk 符号，或者没有足够的未使用内核空间（需要 ≥16KB）。

**解决**：
- 确认内核版本 ≥ 4.19（较新的 ARM64 Android 内核）
- 检查内核是否导出了这些符号（即使未导出，kallsyms 中通常存在）
- 查看详细输出中的具体缺失符号

### Q: kpmctl 加载模块没反应

**解决**：
```bash
# 检查内核日志
adb shell dmesg -c | grep -i 'kpm\|skroot'

# 确认内核补丁正确刷入
adb shell cat /proc/version  # 应该看到熟悉的版本

# 验证 SKRoot root 功能正常
# (通过 APP 或 su 获取 root，确认补丁已生效)
```

### Q: 加载模块后系统崩溃

**原因**：KPM 模块可能存在兼容性问题。

**解决**：
- 确认 KPM 模块是为 ARM64 编译的
- 内核版本匹配（模块依赖的内核 API 可能在不同版本行为不同）
- 通过 `kpmctl unload` 卸载后观察是否恢复

### Q: 提示 "KPM runtime not available" / "@ 命令无效"

**原因**：内核补丁中没有嵌入 KPM 运行时。

**解决**：
- 重新运行 `patch_kernel_root` 并确认看到 "KPM handler: 0x..." 输出
- 如果仍然失败，提供完整终端输出以便诊断

### Q: VFS 模式加载失败（"VFS not available"）

**原因**：内核中没有 `filp_open` / `kernel_read` / `filp_close` 符号（极旧的定制内核可能出现）。

**解决**：
- 使用内存模式：通过 SKRoot APP 调用 `skroot_kpm_load()`（内部自动 mmap + 地址传递）
- 或使用更简单的方式：先 get_root，然后 mmap 文件，用 busybox env 传地址

---

## 完整工作流程示例

```bash
# ========== PC 端 ==========
cd src/patch_kernel_root

# 1. 构建补丁工具
make

# 2. 对内核镜像打补丁
./patch_kernel_root ~/boot.img-kernel
#   → 分析符号...
#   → KPM Loader Integration 显示成功
#   → 选择自动生成 ROOT 密匙
#   → 写入修改 Done.

# 3. 打包 boot.img
cd ~/Android.Image.Kitchen
./repackimg.sh

# 4. 刷入设备
adb reboot bootloader
fastboot flash boot image-new.img
fastboot reboot

# ========== 设备端 ==========
# 5. 推送 kpmctl 和模块
adb push kpmctl /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kpmctl
adb push tomato.kpm /data/local/tmp/

# 6. 加载模块
adb shell /data/local/tmp/kpmctl load /data/local/tmp/tomato.kpm

# 7. 验证
adb shell dmesg -c | grep 'SKRoot KPM'
#   SKRoot KPM: loaded Module size=32896

# 8. 查看列表
adb shell /data/local/tmp/kpmctl list

# 9. 卸载
adb shell /data/local/tmp/kpmctl unload Module

# 10. 确认已卸载
adb shell dmesg -c | grep 'SKRoot KPM'
#   SKRoot KPM: unloaded Module
```
