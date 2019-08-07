#include <stdint.h>

#ifndef CACHE_OPERATIONS_H
#define CACHE_OPERATIONS_H

#include "includes.h"

typedef struct
{
    uint32_t blocksize;
    uint64_t cachesize;
} cached_globals_t;

extern cached_globals_t cache_globals;

#define CACHE_FILE_VERSION 1
#define CACHE_FILE_MAGIC 0xDEADBEEFCAFEF00D

#define CACHE_META_MAGIC 0xDEADF00D
typedef struct
{
    uint32_t magic;

    uint8_t used;
    char path[4096];
    /* struct stat pasta incoming lul */
    uint16_t st_mode;    /* File type and mode */
    uint64_t st_size;    /* Total size, in bytes */
    uint32_t st_blksize; /* Block size for filesystem I/O */
    uint32_t st_blocks;  /* Number of 512B blocks allocated */
    uint64_t st_ino;
    uint64_t st_dev;

    // TODO actually use it
    // amount of data we have cached for this file
    uint64_t cached_size;

    //we future proof bruh
    uint64_t ctime;
    uint64_t atime;
} __attribute__((packed)) cached_metadata_block_t;

#define CACHE_DATA_MAGIC 0xCAFEBABE
typedef struct
{
    uint32_t magic;
    uint8_t used;

    char path[4096];
    uint32_t bytes_used;

    uint32_t metadata_index;
    uint32_t file_block_number;
} __attribute__((packed)) cached_data_block_t;

typedef struct
{
    uint64_t magic;

    uint8_t cache_file_version;
    uint32_t blocksize;

    uint64_t metadata_count;
    uint64_t metadata_offset;
    uint64_t data_count;
    uint64_t data_offset;
    uint64_t block_offset;
} __attribute__((packed)) cached_header_t;

// we are setting or clearing the last bit on the hashtable key
// depending if the stored value is a metadata block or a data block
// *queue infomercial* THERE MUST BE A BETTER WAY
//#define METADATA_FLAG ((uintptr_t)((intptr_t)-1) & (1ULL << ((sizeof(uintptr_t) * 8) - 1)))

// or we can just switch out the hashtable with a custom one and say yolo
#define METADATA_FLAG (1 << 31)
#define DATA_SEED(index) ((index + 1) & ~METADATA_FLAG)

BOOL cache_init(const char *cache_filename, uint32_t *blocksize, uint64_t *cachesize);
BOOL cache_thread_init(int index);
BOOL cache_has_file(const char *path);
uint64_t cache_get_cached_bytes(const char *path);
BOOL cache_get_block(const char *path, uint32_t block, uint32_t block_offset, unsigned char *data, uint32_t *out_size);
BOOL cache_write_block(const char *path, uint32_t block, unsigned char *data, uint32_t in_size);
BOOL cache_get_metadata(const char *path, cached_metadata_block_t *in_meta);
BOOL cache_write_metadata(const char *path, cached_metadata_block_t *out_meta);
BOOL cache_clear_metadata(const char *path);

#endif