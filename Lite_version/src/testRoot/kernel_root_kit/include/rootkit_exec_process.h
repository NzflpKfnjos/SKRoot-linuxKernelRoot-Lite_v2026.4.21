#pragma once
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "rootkit_err_def.h"

namespace kernel_root {
/***************************************************************************
 * 以 ROOT 身份执行指定程序（execve）
 * 参数:
 *   str_root_key		ROOT 权限密钥文本
 *   cmdline				要执行的命令行文本，格式为“可执行文件路径 + 参数”
 *								例如：
 *									"/system/bin/ls /data/local/tmp"
 *									"/system/bin/sh /data/local/tmp/test.sh"
 *								当前实现仅支持按空格分割参数
 * 返回: OK 表示执行成功，其他值表示失败
 ***************************************************************************/
KRootErr root_exec_process(const char* str_root_key, const char *cmdline);
}
