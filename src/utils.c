#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

uint64_t fnv64a(const uint8_t *data, int data_size, uint64_t extra)
{
    uint64_t hval = 1099511628211ULL; //FNV1_32A_INIT
    int i;
    for (i = 0; i < data_size; ++i)
    {
        hval ^= data[i];
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
    }

    if (extra > 0)
    {
        hval ^= extra;
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
    }
    return hval;
}

uint32_t hash_fold(uint32_t a, uint32_t b)
{
    // TODO: implement better then just making 64bit value
    uint64_t key = a;
    key = (key << 32) | b;
    
    key = (~key) + (key << 18); // key = (key << 18) - key - 1;
    key = key ^ (key >> 31);
    key = key * 21; // key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 11);
    key = key + (key << 6);
    key = key ^ (key >> 22);
    return (uint32_t)key;
}

void trim_inplace(char *str)
{
    if (!str)
        return;

    char *ptr = str;
    int len = strlen(ptr);

    while (len - 1 > 0 && isspace(ptr[len - 1]))
        ptr[--len] = 0;

    while (*ptr && isspace(*ptr))
        ++ptr, --len;

    memmove(str, ptr, len + 1);
}

void normalize_path_inplace(char *path)
{
    int slash_start = -1, i;
    for (i = 0; i < strlen(path); i++)
    {
        if (path[i] == '/' && slash_start == -1)
        {
            slash_start = i;
        }
        else if (path[i] != '/' && slash_start != -1)
        {
            int slash_end = i - 1;
            if (slash_start == slash_end)
            {
                slash_start = -1;
            }
            else
            {
                // move null byte cause we lazy boi
                memmove(&(path[slash_start]), &(path[slash_end]), (strlen(path) + 1) - slash_end);
                i -= slash_end - slash_start;
                slash_start = -1;
            }
        }
    }
}

// stackoverflow coming in with the clutch paste as usual
void hexDump(char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);

    if (len == 0)
    {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0)
    {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++)
    {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0)
        {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0)
    {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}
