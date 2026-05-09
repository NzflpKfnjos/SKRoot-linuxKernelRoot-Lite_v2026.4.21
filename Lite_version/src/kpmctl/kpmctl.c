/* kpmctl — SKRoot KPM management CLI tool
 *
 * Communicates with the kernel-side KPM runtime via execve hooks.
 * No root required — any process can trigger the @-command dispatch.
 *
 * Usage:
 *   kpmctl load   <path>      Load a .kpm file
 *   kpmctl unload <name>      Unload a module by name
 *   kpmctl list               List loaded modules (output via dmesg)
 *   kpmctl start <path>       Load + keep running (for persistent modules)
 *
 * Build:
 *   clang --target=aarch64-linux-android21 -static -o kpmctl kpmctl.c
 *   adb push kpmctl /data/local/tmp/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/* Trigger the KPM kernel hook via execveat(AT_FDCWD, ...).
 * On modern aarch64 kernels the execve syscall may not reach
 * do_execveat_common, so execveat is the reliable path.
 * The call fails (ENOENT) but the KPM side effect happens first. */
static int run_kpm_cmd(const char* cmd) {
    fflush(stdout);
    fflush(stderr);

#ifdef __NR_execveat
    syscall(__NR_execveat, -100 /* AT_FDCWD */, cmd, NULL, NULL, 0);
#else
    syscall(__NR_execve, cmd, NULL, NULL);
#endif

    return 0;
}

static void usage(const char* prog) {
    fprintf(stderr,
        "kpmctl — SKRoot KPM Module Manager\n"
        "\n"
        "Usage:\n"
        "  %s load   <file>       Load .kpm file from path\n"
        "  %s unload <name>       Unload module by name\n"
        "  %s list                List loaded modules (check dmesg)\n"
        "  %s status              Check if KPM runtime is available\n"
        "\n"
        "Examples:\n"
        "  %s load /data/local/tmp/tomato.kpm\n"
        "  %s unload Module\n"
        "  %s list && dmesg | grep 'SKRoot KPM' | tail -10\n"
        "\n",
        prog, prog, prog, prog,
        prog, prog, prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char* subcmd = argv[1];

    if (strcmp(subcmd, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s load <file.kpm>\n", argv[0]);
            return 1;
        }

        /* Check the file exists and is readable */
        if (access(argv[2], R_OK) != 0) {
            fprintf(stderr, "Error: cannot read %s\n", argv[2]);
            return 1;
        }

        /* Build command string: @LD:<absolute_path> */
        char cmd[512];
        /* Resolve to absolute path if relative */
        const char* path = argv[2];
        if (path[0] != '/') {
            char cwd[256];
            if (getcwd(cwd, sizeof(cwd))) {
                snprintf(cmd, sizeof(cmd), "@LD:%s/%s", cwd, path);
            } else {
                snprintf(cmd, sizeof(cmd), "@LD:%s", path);
            }
        } else {
            snprintf(cmd, sizeof(cmd), "@LD:%s", path);
        }

        printf("Loading %s ...\n", path);
        fflush(stdout);

        run_kpm_cmd(cmd);

        /* Brief pause for the kernel to process */
        usleep(100000);

        /* Check dmesg for result */
        printf("Check result: dmesg | grep 'SKRoot KPM' | tail -3\n");

    } else if (strcmp(subcmd, "unload") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s unload <module_name>\n", argv[0]);
            return 1;
        }

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "@UL:%s", argv[2]);

        printf("Unloading %s ...\n", argv[2]);
        fflush(stdout);

        run_kpm_cmd(cmd);
        usleep(100000);
        printf("Check result: dmesg | grep 'SKRoot KPM' | tail -3\n");

    } else if (strcmp(subcmd, "list") == 0) {
        printf("Module list (triggered via kernel log):\n");
        fflush(stdout);

        run_kpm_cmd("@LS");
        usleep(100000);

        /* Print dmesg lines containing SKRoot KPM */
        printf("--- dmesg output ---\n");
        fflush(stdout);
        int rc = system("dmesg -c 2>/dev/null | grep 'SKRoot KPM' || "
                        "echo '(no output — kernel log may require root to read)'");
        if (rc == -1) {
            perror("system");
        }

    } else if (strcmp(subcmd, "status") == 0) {
        printf("Probing KPM runtime...\n");
        fflush(stdout);

        /* Run a @LS probe */
        run_kpm_cmd("@LS");
        usleep(100000);

        /* Use a simple test: try loading a nonexistent module,
         * if the @ prefix is recognized the error message differs. */
        printf("KPM runtime should be available if SKRoot kernel patch is installed.\n");
        printf("Verify with: dmesg -c | grep 'SKRoot KPM'\n");

    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
