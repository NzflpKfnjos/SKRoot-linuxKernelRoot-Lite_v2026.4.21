#include "rootkit_kpm_test.h"
#include "rootkit_command.h"
#include "____DO_NOT_EDIT____/private_api_runtime_helper.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace kernel_root {

/* Read a file into a buffer. Returns empty vector on failure. */
static std::vector<char> read_file_data(const char* path) {
    std::vector<char> out;
    if (!path) return out;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return out;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return out; }
    if (st.st_size <= 0 || st.st_size > 0x1000000) { close(fd); return out; }
    out.resize(st.st_size);
    ssize_t n = read(fd, out.data(), st.st_size);
    close(fd);
    if (n != st.st_size) out.clear();
    return out;
}

/* Trigger execve with the KPM command string and check dmesg for result.
 * We use a fork/pipe pattern: child calls execve with the command,
 * kernel processes it, child exits. Parent checks dmesg for output.
 */
static KRootErr exec_kpm_cmd(const char* root_key, const char* cmd_string) {
    if (!cmd_string || !cmd_string[0]) return KRootErr::ERR_PARAM;

    /* Fork child that gets root and triggers the KPM command */
    pid_t pid = fork();
    if (pid < 0) return KRootErr::ERR_NO_ROOT;

    if (pid == 0) {
        /* Child: get root, then trigger KPM command via execve */
        KRootErr err = get_root(root_key);
        if (is_failed(err)) _exit(1);

        /* The execve command: syscall(__NR_execve, "@XX:...", NULL, NULL) */
        syscall(__NR_execve, cmd_string, NULL, NULL);

        /* execve should NOT return for KPM commands (they return from the hook).
         * But if it does, it means the hook didn't intercept. */
        _exit(0);
    }

    /* Parent: wait for child */
    int status = 0;
    waitpid(pid, &status, 0);

    /* Read dmesg for KPM output */
    /* If child had an error, return NO_ROOT */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
        return KRootErr::ERR_NO_ROOT;
    }

    return KRootErr::OK;
}

/* Probe whether SKRoot KPM runtime is available */
KRootErr skroot_kpm_probe(const char* root_key, bool& out_available) {
    out_available = false;

    /* Try @LS command — if it works, the runtime is available */
    KRootErr err = exec_kpm_cmd(root_key, "@LS");
    if (is_failed(err)) return err;

    /* Check dmesg for SKRoot KPM output */
    std::string dmesg_out;
    KRootErr dmesg_err = run_root_cmd(root_key, "dmesg -c 2>/dev/null | grep -c 'SKRoot KPM' || true", dmesg_out);
    if (is_ok(dmesg_err)) {
        int count = 0;
        std::stringstream ss(dmesg_out);
        ss >> count;
        out_available = (count > 0);
    }

    return KRootErr::OK;
}

/* Load a .kpm file via the self-hosted kernel KPM loader */
KRootErr skroot_kpm_load(const char* root_key, const char* kpm_path,
                         std::string& out_module_name) {
    out_module_name.clear();
    if (!root_key || !kpm_path) return KRootErr::ERR_PARAM;

    /* Read the .kpm file */
    std::vector<char> kpm_data = read_file_data(kpm_path);
    if (kpm_data.empty()) return KRootErr::ERR_OPEN_FILE;

    /* mmap the data to get a stable virtual address for the kernel to read */
    size_t data_size = kpm_data.size();
    void* mapped = mmap(nullptr, data_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped == MAP_FAILED) return KRootErr::ERR_SKROOT_KPM_MMAP_FAILED;

    memcpy(mapped, kpm_data.data(), data_size);

    /* Build the command string: @LD:<hex_addr>,<hex_size>,<name> */
    char cmd_buf[512];
    const char* basename = strrchr(kpm_path, '/');
    basename = basename ? basename + 1 : kpm_path;
    /* Remove .kpm extension for module name */
    char mod_name[256];
    strncpy(mod_name, basename, sizeof(mod_name) - 1);
    mod_name[sizeof(mod_name) - 1] = '\0';
    char* dot = strrchr(mod_name, '.');
    if (dot) *dot = '\0';

    snprintf(cmd_buf, sizeof(cmd_buf), "@LD:%lx,%lx,%s",
             (unsigned long)mapped, (unsigned long)data_size, mod_name);

    /* Clear dmesg before triggering */
    std::string tmp;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null >/dev/null", tmp);

    /* Trigger the KPM load */
    KRootErr err = exec_kpm_cmd(root_key, cmd_buf);

    /* Clean up mmap */
    munmap(mapped, data_size);

    if (is_failed(err)) return err;

    /* Check dmesg for load confirmation */
    std::string dmesg_out;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null | grep 'SKRoot KPM' || true", dmesg_out);

    if (dmesg_out.find("loaded") != std::string::npos) {
        out_module_name = mod_name;
        return KRootErr::OK;
    }

    /* Could be already loaded — check list */
    std::vector<SkrootKpmInfo> mods;
    KRootErr list_err = skroot_kpm_list(root_key, mods);
    if (is_ok(list_err)) {
        for (auto& m : mods) {
            if (m.name == mod_name) {
                out_module_name = mod_name;
                return KRootErr::OK;
            }
        }
    }

    return KRootErr::ERR_SKROOT_KPM_LOAD_FAILED;
}

/* Unload a KPM module by name */
KRootErr skroot_kpm_unload(const char* root_key, const char* module_name) {
    if (!root_key || !module_name) return KRootErr::ERR_PARAM;

    char cmd_buf[512];
    snprintf(cmd_buf, sizeof(cmd_buf), "@UL:%s", module_name);

    /* Clear dmesg */
    std::string tmp;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null >/dev/null", tmp);

    KRootErr err = exec_kpm_cmd(root_key, cmd_buf);
    if (is_failed(err)) return err;

    /* Verify unload */
    std::string dmesg_out;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null | grep 'SKRoot KPM' || true", dmesg_out);

    if (dmesg_out.find("unloaded") != std::string::npos) {
        return KRootErr::OK;
    }

    return KRootErr::ERR_SKROOT_KPM_UNLOAD_FAILED;
}

/* List loaded KPM modules by reading dmesg */
KRootErr skroot_kpm_list(const char* root_key,
                         std::vector<SkrootKpmInfo>& out_modules) {
    out_modules.clear();
    if (!root_key) return KRootErr::ERR_PARAM;

    /* Clear dmesg first */
    std::string tmp;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null >/dev/null", tmp);

    /* Trigger @LS to print module list to kernel log */
    KRootErr err = exec_kpm_cmd(root_key, "@LS");
    if (is_failed(err)) return err;

    /* Read back dmesg for module list */
    std::string dmesg_out;
    run_root_cmd(root_key, "dmesg -c 2>/dev/null | grep 'SKRoot KPM' || true", dmesg_out);

    /* Parse output: "SKRoot KPM: loaded modules:" followed by entries */
    std::stringstream ss(dmesg_out);
    std::string line;
    while (std::getline(ss, line)) {
        /* Look for "  [N] name base=..." pattern */
        size_t pos = line.find("  [");
        if (pos == std::string::npos) continue;
        size_t name_start = line.find(' ', pos + 4);
        if (name_start == std::string::npos) continue;
        /* Skip whitespace */
        while (name_start < line.size() && line[name_start] == ' ') ++name_start;
        size_t name_end = line.find(' ', name_start);
        if (name_end == std::string::npos) continue;

        SkrootKpmInfo info;
        info.name = line.substr(name_start, name_end - name_start);
        info.version = "unknown";
        out_modules.push_back(info);
    }

    return KRootErr::OK;
}

} /* namespace kernel_root */
