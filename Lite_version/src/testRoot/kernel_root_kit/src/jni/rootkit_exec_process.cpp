#include "rootkit_exec_process.h"
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include "rootkit_umbrella.h"
#include "rootkit_fork_helper.h"
#include "common/exec_cmdline_utils.h"

namespace kernel_root {
	static KRootErr unsafe_root_exec_process(const char* str_root_key, const char *cmdline) {
		if (cmdline == NULL || strlen(cmdline) == 0) return KRootErr::ERR_PARAM;

		RETURN_ON_ERROR(get_root(str_root_key));

		execve_cmdline(cmdline);
		return KRootErr::ERR_EXECVE;
	}

	static KRootErr safe_root_exec_process(
		const char* str_root_key,
		const char *cmdline) {
		if (cmdline == NULL || strlen(cmdline) == 0) return KRootErr::ERR_PARAM;
		
		fork_pipe_info finfo;
		if (fork_pipe_child_process(finfo)) {
			KRootErr err = unsafe_root_exec_process(str_root_key, cmdline);
			write_errcode_from_child(finfo, err);
			finfo.close_all();
			_exit(0);
			return KRootErr::OK;
		}
		KRootErr err = KRootErr::OK;
		if (!read_errcode_from_child(finfo, err)) {
			if(err == KRootErr::ERR_READ_EOF) err = KRootErr::OK;
		}
		int status = 0; waitpid(finfo.child_pid, &status, 0);
		return err;
	}

	KRootErr root_exec_process(
		const char* str_root_key,
		const char *cmdline) {
		return safe_root_exec_process(str_root_key, cmdline);
	}

}
