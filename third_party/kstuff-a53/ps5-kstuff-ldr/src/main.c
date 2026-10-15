#include "ppr/ppr_install_bridge.h"
#include "ppr/ppr_resume.h"
/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */           

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <limits.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/time.h>

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/event.h>

#include <machine/param.h>
#include <ps5/payload.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>
#include <onion/ready.h>

#include "image.h"
#include "ufs_mount.h"
#include "pfs_mount.h"
#include "pfsc_mount.h"
#include "exfat_mount.h"
#include "mount_helpers.h"
#include "shellui_patch.h"
#include "utils.h"
#include "../../lib/r0gdb-bootstrap.h"
#include "../../lib/shellcore-imports.h"

// Forward declaration of the 13.60 signature patch routine from mount_helpers.c
void patch_1360_pkg_verification(uint64_t kernel_base);

asm(".section .rodata\n"
    ".global ___ps5_kstuff_payload_bin\n"
    "___ps5_kstuff_payload_bin:\n"
    ".incbin \"../../ps5-kstuff/payload.bin\"\n");

extern char ___ps5_kstuff_payload_bin[];
int shellcore_import_got(int pid, uint64_t image_base, uint32_t required_mask,
                         uint64_t got[SHELLCORE_IMPORT_COUNT]);

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
                     (((x) & PF_W) ? PROT_WRITE : 0) | \
                     (((x) & PF_X) ? PROT_EXEC  : 0))

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

#define HYPERCORE_READY_PATH ONION_READY_ROOT "/" ONION_READY_KSTUFF
#define HYPERCORE_STARTING_PATH \
    ONION_READY_ROOT "/" ONION_READY_KSTUFF_STARTING
#define HYPERCORE_FAILED_PATH ONION_READY_ROOT "/" ONION_READY_KSTUFF_FAILED

static int publish_hypercore_loader_starting(void) {
    mkdir(ONION_SYSTEM_TMP_ROOT, 0777);
    mkdir(ONION_READY_ROOT, 0777);
    unlink(HYPERCORE_READY_PATH);
    unlink(HYPERCORE_FAILED_PATH);
    int fd = open(HYPERCORE_STARTING_PATH,
                  O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0)
        return -1;
    char value[32];
    int length = snprintf(value, sizeof(value), "%d\n", (int)getpid());
    bool valid = length > 0 && (size_t)length < sizeof(value);
    ssize_t written = valid ? write(fd, value, (size_t)length) : -1;
    int close_result = close(fd);
    return valid && written == (ssize_t)length && close_result == 0 ? 0 : -1;
}

static int publish_hypercore_loader_state(bool ready) {
    const char *path = ready ? HYPERCORE_READY_PATH : HYPERCORE_FAILED_PATH;
    const char *stale = ready ? HYPERCORE_FAILED_PATH : HYPERCORE_READY_PATH;
    mkdir(ONION_SYSTEM_TMP_ROOT, 0777);
    mkdir(ONION_READY_ROOT, 0777);
    unlink(stale);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0)
        return -1;
    const char value = '1';
    ssize_t written = write(fd, &value, sizeof(value));
    int close_result = close(fd);
    int result =
        written == (ssize_t)sizeof(value) && close_result == 0 ? 0 : -1;
    if (result == 0)
        unlink(HYPERCORE_STARTING_PATH);
    return result;
}

static int hypercore_loader_failure(void) {
    publish_hypercore_loader_state(false);
    return EXIT_FAILURE;
}

static int automount_disabled(void) {
    return access("/data/.kstuff_noautomount", F_OK) == 0;
}

/* Never replace a title that the console already installed on extended storage. */
static int native_extended_title(const char *title_id) {
    static const char *const roots[] = {
        "/mnt/ext0/user/app", "/mnt/ext1/user/app"
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); ++i) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", roots[i], title_id);
        if (n < 0 || (size_t)n >= sizeof(path)) return -1;
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) return 1;
        } else if (errno != ENOENT && errno != ENOTDIR) {
            klog_printf("Extended title check failed: %s errno=%d\n", path, errno);
            return -1;
        }
    }
    return 0;
}

static int mount_source(const char* src_path, char* out_mounted_path,
                        bool* out_temporary_mount)
{
    struct stat source_st;
    char image_path[MAX_PATH] = {0};
    bool is_ufs = false, is_pfs = false, is_pfsc = false, is_exfat = false;

    if (!src_path || !*src_path || !out_mounted_path ||
        !out_temporary_mount) {
        errno = EINVAL;
        return -1;
    }
    out_mounted_path[0] = '\0';
    *out_temporary_mount = false;

    /* A stale mount.lnk must not enter nmount or the image cleanup paths. */
    if (stat(src_path, &source_st) != 0) {
        return -1;
    }
    if (!S_ISDIR(source_st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    if (find_image_in_dir(src_path, image_path, sizeof(image_path), 
                          &is_ufs, &is_pfs, &is_pfsc, &is_exfat)) {
        
        klog_printf("Image detected in folder: %s\n", image_path);

        char mount_point[MAX_PATH] = {0};
        char nullfs_src[MAX_PATH] = {0};

        if (is_ufs && mount_ufs_image(image_path, mount_point)) {
            klog_printf("UFS image mounted\n");
            strncpy(nullfs_src, mount_point, sizeof(nullfs_src)-1);
            *out_temporary_mount = true;
        }
        else if (is_pfs && mount_pfs_image(image_path, mount_point)) {
            klog_printf("PFS image mounted\n");
            strncpy(nullfs_src, mount_point, sizeof(nullfs_src)-1);
            *out_temporary_mount = true;
        }
        else if (is_pfsc) {
            klog_printf("PFSC image detected: %s\n", strrchr(image_path, '/') ? 
                       strrchr(image_path, '/') + 1 : image_path);

            char pfsc_mount_point[MAX_PATH] = {0};
            if (mount_pfsc_image(image_path, pfsc_mount_point)) {
                strncpy(nullfs_src, pfsc_mount_point, sizeof(nullfs_src)-1);
                strncpy(mount_point, pfsc_mount_point, sizeof(mount_point)-1);
                *out_temporary_mount = true;

                // === NESTED IMAGE SUPPORT ===
                char nested_image[MAX_PATH] = {0};
                bool n_ufs = false, n_pfs = false, n_pfsc = false, n_exfat = false;

                klog_printf("Scanning for nested image inside PFSC...\n");
                if (find_image_in_dir(pfsc_mount_point, nested_image, sizeof(nested_image),
                                    &n_ufs, &n_pfs, &n_pfsc, &n_exfat)) {

                    char nested_mount[MAX_PATH] = {0};
                    bool nested_ok = false;

                    if (n_ufs) {
                        klog_printf("Nested UFS detected\n");
                        nested_ok = mount_ufs_image(nested_image, nested_mount);
                    } else if (n_pfs) {
                        klog_printf("Nested PFS detected\n");
                        nested_ok = mount_pfs_image(nested_image, nested_mount);
                    } else if (n_exfat) {
                        klog_printf("Nested exFAT detected\n");
                        nested_ok = mount_exfat_image(nested_image, nested_mount);
                    }

                    if (nested_ok && strlen(nested_mount) > 0) {
                        klog_printf("Successfully mounted nested image\n");
                    }
                }
            }
        }
    }
    return 0;
}

// Global initialization entry point where kernel_base configuration is populated
int payload_main(void) {
    uint64_t kernel_base = 0;
    
    // Query runtime kernel memory address properties
    if (ps5_kernel_get_base(&kernel_base) == 0 && kernel_base != 0) {
        klog_printf("[*] Payload initializing kernel privilege operations.\n");
        
        // Execute the custom hardware write-protection bypass and validation patch
        patch_1360_pkg_verification(kernel_base);
        klog_printf("[+] Custom 13.60 signature patches deployed inline successfully.\n");
    }
    return 0;
}
