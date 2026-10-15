#include <sys/uio.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#include "mount_helpers.h"
#include "utils.h"
#include "types.h"

#define TARGET_1360_OFFSET 0x001e0e0a7

int remount_system_ex(void) {
    struct iovec iov[] = {
        IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
        IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
        IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
    };
    return nmount(iov, IOVEC_SIZE(iov), MNT_UPDATE);
}

int mount_nullfs(const char* src, const char* dst) {
    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("nullfs"),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(dst),
    };
    return nmount(iov, IOVEC_SIZE(iov), 0);
}

int is_mounted(const char* path) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return 0;
    return strcmp(sfs.f_fstypename, "nullfs") == 0;
}

void patch_1360_pkg_verification(uint64_t kernel_base) {
    // 1. Read CR0 and clear the 16th (Write Protect) bit to allow kernel page edits
    uint64_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0 & ~0x10000));

    // 2. Identify the exact signature check location coordinates
    volatile uint8_t *patch_target = (volatile uint8_t *)(kernel_base + TARGET_1360_OFFSET);
    
    // 3. Inject assembly instructions securely using proper array index assignment: XOR EAX, EAX; RET
    patch_target[0] = 0x31;
    patch_target[1] = 0xC0;
    patch_target[2] = 0xC3;

    // 4. Re-enable hardware CPU Write Protection immediately
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));
}
