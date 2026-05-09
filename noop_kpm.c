typedef unsigned long u64;
__attribute__((section(".kpm.info"), used))
static const char kpm_info[] =
    "name=noop\n"
    "version=1\n"
    "license=GPL\n"
    "author=codex\n"
    "description=no-op test\n";
__attribute__((section(".kpm.init"), used))
void kpm_init(void) {}