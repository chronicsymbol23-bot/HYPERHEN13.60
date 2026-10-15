#include "ppr/ppr_install_bridge.h"
#include "ppr/ppr_resume.h"
/* Copyright (C) 2025 John Törnblom
This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version. */           

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <ps5/payload.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>

asm(".section .rodata\n"
    ".global ___ps5_kstuff_payload_bin\n"
    "___ps5_kstuff_payload_bin:\n"
    ".incbin \"../../ps5-kstuff/payload.bin\"\n");

extern char ___ps5_kstuff_payload_bin[];

int payload_main(void) {
    uint64_t kernel_base = 0;
    
    if (ps5_kernel_get_base(&kernel_base) == 0 && kernel_base != 0) {
        klog_printf("[*] Running raw structural kernel bypass...\n");
        
        // Calculate the absolute destination memory address
        uint64_t target_addr = kernel_base + 0x001e0e0a7;

        // Raw Inline Assembly: Disables CR0 WP bit, force-injects \x31\xC0\xC3, restores CR0
        __asm__ volatile(
            "mov %%cr0, %%rax\n"
            "mov %%rax, %%rdx\n"
            "and $0xfffffffffffeffff, %%rax\n"
            "mov %%rax, %%cr0\n"
            "movb $0x31, (%0)\n"
            "movb $0xC0, 1(%0)\n"
            "movb $0xC3, 2(%0)\n"
            "mov %%rdx, %%cr0\n"
            :
            : "r"(target_addr)
            : "rax", "rdx", "memory"
        );
        
        klog_printf("[+] 13.60 kernel patch execution vector bypass complete.\n");
    }
    return 0;
}
