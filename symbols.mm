#include "symbols.h"
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "api.h"

mach_vm_address_t base_address = 0;
mach_vm_address_t current_address = 0;

extern "C" kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t,
                                                mach_vm_address_t, mach_vm_size_t *);

ssize_t read_from_memory(task_t task, void *buffer, size_t nbyte)
{
    mach_vm_size_t outsize;
    kern_return_t kr =
        mach_vm_read_overwrite(task, current_address, nbyte, (mach_vm_address_t)buffer, &outsize);
    if (kr == KERN_SUCCESS)
    {
        current_address += nbyte;
        return outsize;
    }
    else
    {
        return -1;
    }
}

off_t lseek_from_memory(task_t task, off_t offset, int whence)
{
    switch (whence)
    {
        case SEEK_SET:
            current_address = base_address + offset;
            break;
        case SEEK_CUR:
            current_address += offset;
            break;
        case SEEK_END:
            // not supported
            break;
    }
    return current_address - base_address;
}

uint64_t getImageSize64(task_t task, struct mach_header_64 *header)
{
    lseek_from_memory(task, 0, SEEK_SET);
    lseek_from_memory(task, sizeof(struct mach_header_64), SEEK_CUR);

    uint64_t image_size = 0;
    struct load_command lc;
    for (int i = 0; i < header->ncmds; i++)
    {
        read_from_memory(task, &lc, sizeof(struct load_command));

        if (lc.cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 seg;
            lseek_from_memory(task, -sizeof(struct load_command), SEEK_CUR);
            read_from_memory(task, &seg, sizeof(struct segment_command_64));

            image_size += seg.vmsize;
        }
        else
        {
            lseek_from_memory(task, lc.cmdsize - sizeof(struct load_command), SEEK_CUR);
        }
    }
    return image_size;
}

uint64_t getImageSize32(task_t task, struct mach_header *header)
{
    lseek_from_memory(task, 0, SEEK_SET);
    lseek_from_memory(task, sizeof(struct mach_header), SEEK_CUR);

    uint64_t image_size = 0;
    struct load_command lc;
    for (int i = 0; i < header->ncmds; i++)
    {
        read_from_memory(task, &lc, sizeof(struct load_command));

        if (lc.cmd == LC_SEGMENT)
        {
            struct segment_command seg;
            lseek_from_memory(task, -sizeof(struct load_command), SEEK_CUR);
            read_from_memory(task, &seg, sizeof(struct segment_command));
            image_size += seg.vmsize;
        }
        else
        {
            lseek_from_memory(task, lc.cmdsize - sizeof(struct load_command), SEEK_CUR);
        }
    }
    return image_size;
}

unsigned long long GetModuleSize(task_t task, void *lpAddress, uint32_t fileoffset,
                                 unsigned long long defaultsize)
{
    base_address = (mach_vm_address_t)lpAddress;
    current_address = base_address;
    uint32_t magic;
    read_from_memory(task, &magic, sizeof(uint32_t));

    if (magic == MH_MAGIC_64)
    {
        struct mach_header_64 header;
        lseek_from_memory(task, 0, SEEK_SET);
        read_from_memory(task, &header, sizeof(struct mach_header_64));
        return getImageSize64(task, &header);
    }
    else if (magic == MH_MAGIC)
    {
        struct mach_header header;
        lseek_from_memory(task, 0, SEEK_SET);
        read_from_memory(task, &header, sizeof(struct mach_header));
        return getImageSize32(task, &header);
    }
    else if (magic == FAT_MAGIC || magic == FAT_CIGAM)
    {
        struct fat_header fatHeader;
        lseek_from_memory(task, 0, SEEK_SET);
        read_from_memory(task, &fatHeader, sizeof(struct fat_header));

        struct fat_arch *archs =
            (struct fat_arch *)malloc(fatHeader.nfat_arch * sizeof(struct fat_arch));
        read_from_memory(task, archs, fatHeader.nfat_arch * sizeof(struct fat_arch));

        for (uint32_t i = 0; i < fatHeader.nfat_arch; i++)
        {
            lseek_from_memory(task, archs[i].offset, SEEK_SET);
            read_from_memory(task, &magic, sizeof(uint32_t));

            if (magic == MH_MAGIC_64)
            {
                struct mach_header_64 header;
                lseek_from_memory(task, archs[i].offset, SEEK_SET);
                read_from_memory(task, &header, sizeof(struct mach_header_64));
                return getImageSize64(task, &header);
            }
            else if (magic == MH_MAGIC)
            {
                struct mach_header header;
                lseek_from_memory(task, archs[i].offset, SEEK_SET);
                read_from_memory(task, &header, sizeof(struct mach_header));
                return getImageSize32(task, &header);
            }
        }

        free(archs);
    }

    return 0;
}
