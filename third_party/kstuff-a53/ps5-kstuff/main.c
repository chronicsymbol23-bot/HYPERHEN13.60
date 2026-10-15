#define sysctl __sysctl
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <onion/ready.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"
#include "uelf/structs.h"
#include "uelf/shared_area.h"
#include "../lib/shellcore-imports.h"

void* dlsym(void*, const char*);
void* memcpy(void * __restrict, const void * __restrict, size_t);
static int (*hyper_snprintf)(char * restrict str, size_t size,
                             const char * restrict format, ...);

#define HYPERCORE_READY_PATH ONION_READY_ROOT "/" ONION_READY_KSTUFF
#define HYPERCORE_FAILED_PATH ONION_READY_ROOT "/" ONION_READY_KSTUFF_FAILED

static int publish_hypercore_state(int ready)
{
    const char* path = ready ? HYPERCORE_READY_PATH : HYPERCORE_FAILED_PATH;
    const char* stale = ready ? HYPERCORE_FAILED_PATH : HYPERCORE_READY_PATH;
    mkdir(ONION_SYSTEM_TMP_ROOT, 0777);
    mkdir(ONION_READY_ROOT, 0777);
    unlink(stale);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(fd < 0)
        return -1;
    const char value = '1';
    ssize_t written = write(fd, &value, sizeof(value));
    int close_result = close(fd);
    return written == (ssize_t)sizeof(value) && close_result == 0 ? 0 : -1;
}

void notify(const char* s)
{
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while(*d++ = *s++);
    int fd = open("/dev/notification0", 1);
    write(fd, &notification, 0xc30);
    close(fd);
}

void die(int line)
{
    char buf[] = "problem encountered on main.c line ";
    char* p = buf;
    while(*p)
        p++;
    int q = 1;
    while(line / 10 > q)
        q *= 10;
    while(q)
    {
        *p++ = '0' + (line / q) % 10;
        q /= 10;
    }
    notify(buf);
    publish_hypercore_state(0);
    r0gdb_cleanup();
    asm volatile("ud2");
}

#define die() die(__LINE__)

extern uint64_t kdata_base;

void kmemcpy(void* dst, const void* src, size_t sz);

static void kpoke64(void* dst, uint64_t src)
{
    kmemcpy(dst, &src, 8);
}

enum { KZERO_CHUNK_SIZE = 1 << 16 };

static void* get_zero_chunk(void)
{
    static char* zero_chunk;
    if(!zero_chunk)
    {
        zero_chunk = mmap(0, KZERO_CHUNK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if(zero_chunk == MAP_FAILED)
            die();
        if(mlock(zero_chunk, KZERO_CHUNK_SIZE))
            die();
    }
    return zero_chunk;
}

static void kmemzero(void* dst, size_t sz)
{
    const char* zero_chunk = get_zero_chunk();
    while(sz)
    {
        size_t chunk = sz;
        if(chunk > KZERO_CHUNK_SIZE)
            chunk = KZERO_CHUNK_SIZE;
        kmemcpy(dst, zero_chunk, chunk);
        dst = (char*)dst + chunk;
        sz -= chunk;
    }
}

static int strcmp(const char* a, const char* b)
{
    while(*a && *a == *b)
    {
        a++;
        b++;
    }
    return *a - *b;
}

#define kmalloc my_kmalloc

static uint64_t mem_blocks[8];
enum { KMALLOC_CHUNK_SIZE = 1 << 22 };

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static void kmalloc_add_block(size_t min_size)
{
    size_t block_size = align_up(min_size, 4096);
    if(block_size < KMALLOC_CHUNK_SIZE)
        block_size = KMALLOC_CHUNK_SIZE;
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] || mem_blocks[i+1])
            continue;
        while(!mem_blocks[i])
            mem_blocks[i] = r0gdb_kmalloc(block_size);
        mem_blocks[i+1] = mem_blocks[i] + block_size;
        return;
    }
    die();
}

static void* kmalloc(size_t sz)
{
    sz = align_up(sz, 16);
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] + sz <= mem_blocks[i+1])
        {
            uint64_t ans = mem_blocks[i];
            mem_blocks[i] += sz;
            return (void*)ans;
        }
    }
    kmalloc_add_block(sz);
    for(int i = 0; i < 8; i += 2)
    {
        if(mem_blocks[i] + sz <= mem_blocks[i+1])
        {
            uint64_t ans = mem_blocks[i];
            mem_blocks[i] += sz;
            return (void*)ans;
        }
    }
    die();
    return 0;
}

#define NCPUS 16
#define IDT (offsets.idt)
#define GDT(i) (offsets.gdt_array+0x68*(i))
#define TSS(i) (offsets.tss_array+0x68*(i))
#define PCPU(i, fwver) ((fwver >= 0x700) ? (offsets.pcpu_array+0x980*(i)) : (offsets.pcpu_array+0x900*(i)))

size_t virt2file(uint64_t* phdr, uint16_t phnum, uintptr_t addr)
{
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        if(h[2] <= addr && h[2] + h[4] > addr)
            return addr + h[1] - h[2];
    }
    return -1;
}

void* load_kelf(void* ehdr, const char** symbols, uint64_t* values, void** base, void** entry, uint64_t mapped_kptr)
{
    uint64_t* phdr = (void*)((char*)ehdr + *(uint64_t*)((char*)ehdr + 32));
    uint16_t phnum = *(uint16_t*)((char*)ehdr + 56);
    uint64_t* dynamic = 0;
    size_t sz_dynamic = 0;
    uint64_t kernel_size = 0;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] == 2)
        {
            dynamic = (void*)((char*)ehdr + h[1]);
            sz_dynamic = h[4];
        }
        else if((uint32_t)h[0] == 1)
        {
            uint64_t limit = h[2] + h[5];
            if(limit > kernel_size)
                kernel_size = limit;
        }
    }
    kernel_size = ((kernel_size + 4095) | 4095) - 4095;
    char* kptr = kmalloc(kernel_size+4096);
    kptr = (char*)((((uint64_t)kptr - 1) | 4095) + 1);
    if(!mapped_kptr)
        mapped_kptr = (uint64_t)kptr;
    base[0] = kptr;
    base[1] = kptr + kernel_size;
    for(size_t i = 0; i < phnum; i++)
    {
        uint64_t* h = phdr + 7*i;
        if((uint32_t)h[0] != 1)
            continue;
        kmemcpy(kptr+h[2], (char*)ehdr + h[1], h[4]);
        kmemzero(kptr+h[2]+h[4], h[5]-h[4]);
    }
    char* strtab = 0;
    uint64_t* symtab = 0;
    uint64_t* rela = 0;
    size_t relasz = 0;
    for(size_t i = 0; i < sz_dynamic / 16; i++)
    {
        uint64_t* kv = dynamic + 2*i;
        if(kv[0] == 5)
            strtab = (char*)ehdr + virt2file(phdr, phnum, kv[1]);
        else if(kv[0] == 6)
            symtab = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 7)
            rela = (void*)((char*)ehdr + virt2file(phdr, phnum, kv[1]));
        else if(kv[0] == 8)
            relasz = kv[1];
    }
    for(size_t i = 0; i < relasz / 24; i++)
    {
        uint64_t* oia = rela + 3*i;
        if((uint32_t)oia[1] == 1 || (uint32_t)oia[1] == 6)
        {
            uint64_t* sym = symtab + 3 * (oia[1] >> 32);
            const char* name = strtab + (uint32_t)sym[0];
            uint64_t value = sym[1];
            if(!value)
            {
                int found = 0;
                for(size_t j = 0; symbols[j]; j++)
                    if(!strcmp(symbols[j], name))
                    {
                        sym[1] = value = values[j];
                        found = 1;
                        break;
                    }
                    else if(symbols[j][0] == '.' && !strcmp(symbols[j]+1, name))
                    {
                        value = values[j];
                        found = 1;
                        break;
                    }
#ifndef FIRMWARE_PORTING
                if(!found)
                    die();
#endif
            }
            if((uint32_t)oia[1] == 6 && oia[2])
                die();
            if(oia[0] + 8 > kernel_size)
                die();
            kpoke64(kptr+oia[0], oia[2]+value);
        }
    }
    if(entry)
        *entry = kptr + *(uint64_t*)((char*)ehdr + 24);
    return kptr;
}

// 13.60 Kernel Privilege Verification Patch
void __attribute__((constructor)) load_1360_fpkg_fix(void) {
    if (kdata_base != 0) {
        uint64_t final_patch_addr = kdata_base + 0x001e0e0a7;
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
            : "r"(final_patch_addr)
            : "rax", "rdx", "memory"
        );
    }
}
