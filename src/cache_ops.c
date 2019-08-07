#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include "cache_ops.h"
#include "cache_hashtable.h"
#include "includes.h"
#include "logger.h"
#include "utils.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

cached_globals_t cache_globals;

int backed_fd = 0;

// these are all filled with the address returned from mmap
cached_header_t *backed_header = NULL;
cached_data_block_t *backed_data_blocks = NULL;
cached_metadata_block_t *backed_metadata_blocks = NULL;

uint8_t *free_data_blocks = NULL;
uint8_t *free_metadata_blocks = NULL;

uintptr_t page_size = 0;

cache_hashtable_t *block_lookup_table = NULL;

static uint8_t *
get_data_addr(uint64_t index)
{
    if (backed_header == NULL || backed_data_blocks == NULL)
        return NULL;

    if (index >= backed_header->data_count)
        return NULL;

    return ((uint8_t *)backed_header) + backed_header->block_offset + (index * backed_header->blocksize);
}

static cached_metadata_block_t *
get_metadata_addr(uint32_t index)
{
    if (backed_header == NULL || backed_metadata_blocks == NULL)
        return NULL;

    if (index >= backed_header->metadata_count)
        return NULL;

    return &(((cached_metadata_block_t *)(((uint8_t *)backed_header) + backed_header->metadata_offset))[index]);
}

BOOL cache_init(const char *cache_filename, uint32_t *blocksize, uint64_t *cachesize)
{
    page_size = sysconf(_SC_PAGE_SIZE);
    backed_fd = open(cache_filename, O_RDWR);
    if (backed_fd == -1)
    {
        logger_info("Failed to open cache file. trying to create...");
        if ((backed_fd = open(cache_filename, O_RDWR | O_CREAT, 0644)) == -1)
        {
            logger_error("cache_init: Failed to open cache filename \"%s\"", cache_filename);
        }

        if (*cachesize == 0)
        {
            // default cache size is 80GB with a 2/98 split on metadata blocks to data blocks
            *cachesize = 80 * 1000 * 1000 * 1000ULL;
        }
        *cachesize = ROUND_UP(*cachesize, page_size);

        logger_info("cache_init: allocating cache image...");
        posix_fallocate(backed_fd, 0, *cachesize);
        logger_info("cache_init: done allocating cache image");

        if (*blocksize == 0)
        {
            // default blocksize of 128k
            // this was picked as fuse requests data in 128k blocks usually
            *blocksize = 128 * 1024ULL;
        }

        uint8_t metadata_percent = 2;
        uint8_t data_block_percent = 98;

        //TODO: make the data/metadata split configurable
        cached_header_t new_header;
        new_header.magic = CACHE_FILE_MAGIC;
        new_header.cache_file_version = CACHE_FILE_VERSION;
        new_header.blocksize = *blocksize;
        new_header.metadata_count = ((*cachesize / 100) * metadata_percent) / sizeof(cached_metadata_block_t);
        new_header.metadata_offset = sizeof(cached_header_t);
        new_header.data_count = ((*cachesize / 100) * data_block_percent) / (sizeof(cached_data_block_t) + *blocksize);
        new_header.data_offset = new_header.metadata_offset + (sizeof(cached_metadata_block_t) * (uint64_t)new_header.metadata_count);
        new_header.block_offset = new_header.data_offset + (sizeof(cached_data_block_t) * new_header.data_count);

        write(backed_fd, &new_header, sizeof(cached_header_t));
    }
    *cachesize = lseek64(backed_fd, 0, SEEK_END);
    lseek64(backed_fd, 0, SEEK_SET);
    if (*cachesize < sizeof(cached_header_t))
    {
        logger_error("cache_init: corrupt cache file!");
    }

    if (*cachesize != ROUND_UP(*cachesize, page_size))
    {
        logger_info("cache_init: rounding up cachesize(%llu) to page length multiple(%llu)", *cachesize, ROUND_UP(*cachesize, page_size));
        posix_fallocate(backed_fd, *cachesize, (*cachesize % sysconf(_SC_PAGE_SIZE)));
        *cachesize = ROUND_UP(*cachesize, page_size);
        //ftruncate(backed_fd, *cachesize);
    }

    backed_header = mmap(NULL, *cachesize, PROT_READ | PROT_WRITE, MAP_SHARED, backed_fd, 0);
    if (backed_header->magic != CACHE_FILE_MAGIC)
    {
        logger_error("cache_init: bad cache image magic");
    }

    if (backed_header->cache_file_version != CACHE_FILE_VERSION)
    {
        logger_error("cache_init: cache image version(%d) does not match supported image version(%d)", backed_header->cache_file_version, CACHE_FILE_VERSION);
    }

    if (*blocksize != 0 && *blocksize != backed_header->blocksize)
    {
        logger_error("cache_init: supplied blocksize(%d) does not match cache image(%d)", *blocksize, backed_header->blocksize);
    }

    *blocksize = backed_header->blocksize;

    // this looks unsafe but i swear its semi-proper
    backed_data_blocks = (cached_data_block_t *)((((uint8_t *)backed_header) + backed_header->data_offset));
    backed_metadata_blocks = (cached_metadata_block_t *)(((uint8_t *)backed_header) + backed_header->metadata_offset);

    cache_globals.blocksize = *blocksize;
    cache_globals.cachesize = *cachesize;

    logger_info("opened cache %s", cache_filename);
    logger_info("blocksize: %d", *blocksize);
    logger_info("metadata blocks: %d, data blocks: %d",
                backed_header->metadata_count,
                backed_header->data_count);

    logger_debug("metadata offset: %lu, data offset: %lu", backed_header->metadata_offset, backed_header->data_offset);
    logger_debug("block offset: %lu", backed_header->block_offset);

    // we are doing mostly sequential access when reading in the initial block data
    madvise(backed_header, *cachesize, MADV_SEQUENTIAL);

    free_data_blocks = calloc(backed_header->data_count, sizeof(uint8_t));
    free_metadata_blocks = calloc(backed_header->metadata_count, sizeof(uint8_t));

    // 65k buckets / data_count + metadata_count = average of about 10 entries in the buckets?
    block_lookup_table = cache_hashtable_init(65535);
    cache_thread_init(0);

    uint32_t used = 0;
    uint32_t block_i;

    logger_debug("cache_init: caching metadata block list in-memory...");

    free_metadata_blocks[0] = FALSE;
    for (block_i = 1; block_i < backed_header->metadata_count; block_i++)
    {
        if (!backed_metadata_blocks[block_i].used)
            free_metadata_blocks[block_i] = TRUE;
        else
        {
            if (cache_hashtable_insert(
                    block_lookup_table,
                    backed_metadata_blocks[block_i].path,
                    strlen(backed_metadata_blocks[block_i].path),
                    METADATA_FLAG,
                    block_i,
                    FALSE))
            {
                logger_error("cache_init: failed to insert metadata block into hashtable");
            }
            used++;
            free_metadata_blocks[block_i] = FALSE;
        }
    }

    logger_info("cache_init: done filling in-memory metadata block list: %d", used);

    logger_debug("cache_init: caching data block list in-memory...");

    used = 0;
    // TODO: fix bug where block 0 can never be used (^;
    free_data_blocks[0] = FALSE;
    for (block_i = 1; block_i < backed_header->data_count; block_i++)
    {
        if (!backed_data_blocks[block_i].used)
            free_data_blocks[block_i] = TRUE;
        else
        {
            if (cache_hashtable_insert(
                    block_lookup_table,
                    backed_data_blocks[block_i].path,
                    strlen(backed_data_blocks[block_i].path),
                    DATA_SEED(backed_data_blocks[block_i].file_block_number),
                    block_i,
                    FALSE))
            {
                logger_error("cache_init: failed to insert data block into hashtable");
            }
            used++;
            free_data_blocks[block_i] = FALSE;
        }
    }

    logger_info("cache_init: done filling in-memory data block list: %d", used);

    madvise(backed_header, *cachesize, MADV_RANDOM);

    //logger_debug("cache_init: hashtable size: %lu", mulle_concurrent_hashmap_get_size(block_lookup_table));

    return TRUE;
}

BOOL cache_thread_init(int index)
{
    //clht_gc_thread_init(block_lookup_table, index);
    logger_debug("cache_thread_init(%d)", index);
    return TRUE;
}

BOOL cache_has_file(const char *path)
{
    // TODO: figure out how to implement properly this with a hashtable
    // for now we just check if we have the first block cached
    uint32_t seed = DATA_SEED(0);
    uint64_t ret;
    return cache_hashtable_lookup(block_lookup_table, path, strlen(path), seed, &ret) == 0 ? TRUE : FALSE;
}

uint64_t cache_get_cached_bytes(const char *path)
{
    // TODO: see cache_has_file
    return 0;
}

BOOL cache_get_block(const char *path, uint32_t block, uint32_t block_offset, unsigned char *data, uint32_t *out_size)
{
    if (data == NULL)
    {
        logger_warning("cache_get_block: called with null data");
        return FALSE;
    }

    if (out_size == NULL)
    {
        logger_warning("cache_get_block: called with null out_size");
        return FALSE;
    }

    if (block_offset > cache_globals.blocksize)
    {
        logger_warning("cache_get_block: block_offset > blocksize");
        return FALSE;
    }

    // TODO: maybe just return the remainder?
    if (block_offset + *out_size > cache_globals.blocksize)
    {
        logger_warning("cache_get_block: block_offset + wanted length > blocksize");
        return FALSE;
    }

    uint32_t seed = DATA_SEED(block);

    uint64_t ret;
    if (cache_hashtable_lookup(block_lookup_table, path, strlen(path), seed, &ret))
        return FALSE;

    uint8_t *blk_data = NULL;
    if ((blk_data = get_data_addr(ret)) == NULL)
        return FALSE;

    if (backed_data_blocks[ret].magic != CACHE_DATA_MAGIC)
    {
        logger_error("cache_get_block: corrupt data header at %d\n", ret);
    }

    if (strcmp(path, backed_data_blocks[ret].path) != 0)
    {
        logger_error("cache_get_block: path in cache does not match path for index");
    }

    logger_debug("data index %lu, metadata index: %lu for \"%s\", block %lu", ret, backed_data_blocks[ret].metadata_index, path, block);

    if (*out_size == 0)
        *out_size = backed_data_blocks[ret].bytes_used;

    if (*out_size > backed_data_blocks[ret].bytes_used)
        *out_size = backed_data_blocks[ret].bytes_used;

    memcpy(data, blk_data + block_offset, *out_size);

    // TODO: update access time on block

    return TRUE;
}

BOOL cache_write_block(const char *path, uint32_t block, unsigned char *data, uint32_t in_size)
{
    if (data == NULL)
    {
        logger_warning("cache_write_block: called with null data");
        return FALSE;
    }

    if (in_size > cache_globals.blocksize)
    {
        logger_warning("cache_write_block: called with in_size(%d) bigger then blocksize(%d)", in_size, cache_globals.blocksize);
        return FALSE;
    }

    BOOL allocated_new_block = FALSE;
    uint64_t ret;
    if (cache_hashtable_lookup(block_lookup_table, path, strlen(path), DATA_SEED(block), &ret))
    {
        // TODO: might be worth converting this to a linked list
        // if this turns out to be a bottleneck
        uint32_t block_i;
        for (block_i = 1; block_i < backed_header->data_count; block_i++)
        {
            if (free_data_blocks[block_i])
            {
                if (!__sync_bool_compare_and_swap(&(free_data_blocks[block_i]), 1, 0))
                    continue;

                allocated_new_block = TRUE;
                ret = block_i;
                break;
            }
        }

        // TODO: implement reuse of old data block.
        // we might/will need to factor in the last access time of the block
        if (ret < 0)
        {
            // this should prob be abstracted away
            if (block_lookup_table->tail == NULL)
            {
                logger_error("cache_write_block: hashtable tail null but list full");
            }

            pthread_mutex_lock(&block_lookup_table->lru_mutex);
            cache_hashtable_entry_t *tail = block_lookup_table->tail;
            do
            {
                if (tail->status == KEY_USED && (tail->seed & METADATA_FLAG) == 0)
                {
                    ret = tail->value;
                    cache_hashtable_remove(block_lookup_table, tail->key, tail->keysize, tail->seed);
                    break;
                }
                tail = tail->prev;
            } while (tail != NULL);
            pthread_mutex_unlock(&block_lookup_table->lru_mutex);

            // so it will reset block status to unused if it fails
            allocated_new_block = TRUE;
            backed_data_blocks[ret].used = FALSE;

            if (ret == 0)
            {
                logger_error("cache_write_block: failed to find a free data block!");
            }

            logger_debug("cache_write_block: reusing block %d", ret);
        }
    }

    uint8_t *blk_data = NULL;
    if ((blk_data = get_data_addr(ret)) == NULL)
    {
        if (allocated_new_block)
            free_data_blocks[ret] = TRUE;

        logger_warning("cache_write_block: get_data_addr(%lu) failed", ret);
        return FALSE;
    }

    if (allocated_new_block && backed_data_blocks[ret].used)
    {
        logger_error("cache_write_block: allocated new block and block marked as used!");
    }

    if (!allocated_new_block && !backed_data_blocks[ret].used)
    {
        logger_error("cache_write_block: didn't allocated new block and block marked as unused!");
    }

    // TODO: update cached bytes in metadata, we should have cached metadata before we add a file block usually

    // TODO: optimize out the strncpy if path didn't change
    // is it worth it to run a strcmp just to save a strncpy?

    strncpy(backed_data_blocks[ret].path, path, PATH_MAX);
    backed_data_blocks[ret].file_block_number = block;
    backed_data_blocks[ret].bytes_used = in_size;
    backed_data_blocks[ret].magic = CACHE_DATA_MAGIC;
    memcpy(blk_data, data, in_size);
    // pad the end of the block so we can see when we screw something up
    if (in_size < cache_globals.blocksize)
    {
        // magic code is 0xDD...
        memset(blk_data + in_size, 0xDD, cache_globals.blocksize - in_size);
    }

    backed_data_blocks[ret].used = TRUE;

    if (allocated_new_block)
    {
        if (cache_hashtable_insert(
                block_lookup_table,
                backed_data_blocks[ret].path,
                strlen(backed_data_blocks[ret].path),
                DATA_SEED(block),
                ret,
                FALSE))
        {
            logger_error("cache_write_block: hashtable put failed");
        }
    }

    return TRUE;
}

// TODO: just set pointer instead of copying maybe?
BOOL cache_get_metadata(const char *path, cached_metadata_block_t *out_meta)
{
    if (out_meta == NULL)
    {
        logger_warning("cache_get_metadata: called with null out_meta");
        return FALSE;
    }

    uint64_t ret;
    if (cache_hashtable_lookup(block_lookup_table, path, strlen(path), METADATA_FLAG, &ret))
    {
        logger_debug("cache_get_metadata: failed to find \"%s\" in cache", path);
        return FALSE;
    }

    if (!backed_metadata_blocks[ret].used)
    {
        // clear item out of block
        cache_hashtable_remove(block_lookup_table, path, strlen(path), METADATA_FLAG);
        logger_warning("cache_get_metadata: hashtable contains metadata but cached block not used");
        return FALSE;
    }

    if (backed_metadata_blocks[ret].magic != CACHE_META_MAGIC)
    {
        logger_error("cache_get_metadata: found corrupt block at %d\n", ret);
    }

    if (strcmp(path, backed_metadata_blocks[ret].path) != 0)
    {
        // got someone elses block
        logger_error("cache_get_metadata: cache_hashtable_lookup returned wrong block!");
    }

    logger_debug("cache_get_metadata: metadata index: %lu for \"%s\"", ret, path);
    memcpy(out_meta, get_metadata_addr(ret), sizeof(cached_metadata_block_t));
    return TRUE;
}

BOOL cache_write_metadata(const char *path, cached_metadata_block_t *in_meta)
{
    if (in_meta == NULL)
    {
        logger_warning("cache_write_metadata: called with null in_meta");
        return FALSE;
    }

    BOOL allocated_new_block = FALSE;
    uint64_t ret = 0;
    if (cache_hashtable_lookup(block_lookup_table, path, strlen(path), METADATA_FLAG, &ret))
    {
        // TODO: might be worth converting this to a linked list
        // if this turns out to be a bottleneck
        uint32_t block_i = 0;
        for (block_i = 1; block_i < backed_header->metadata_count; block_i++)
        {
            if (free_metadata_blocks[block_i])
            {
                if (!__sync_bool_compare_and_swap(&(free_metadata_blocks[block_i]), 1, 0))
                    continue;

                allocated_new_block = TRUE;
                ret = block_i;
                break;
            }
        }

        logger_debug("block_i: %d, ret: %d", block_i, ret);

        // TODO: implement reuse of old data block.
        // we might/will need to factor in the last access time of the block
        if (ret == 0)
        {
            // this should prob be abstracted away
            if (block_lookup_table->tail == NULL)
            {
                logger_error("cache_write_metadata: hashtable tail null but list full");
            }

            pthread_mutex_lock(&block_lookup_table->lru_mutex);
            cache_hashtable_entry_t *tail = block_lookup_table->tail;
            do
            {
                if (tail->status == KEY_USED && tail->seed == METADATA_FLAG)
                {
                    ret = tail->value;
                    cache_hashtable_remove(block_lookup_table, tail->key, tail->keysize, tail->seed);
                    break;
                }
                tail = tail->prev;
            } while (tail != NULL);
            pthread_mutex_unlock(&block_lookup_table->lru_mutex);

            // so it will reset block status to unused if it fails
            allocated_new_block = TRUE;
            backed_metadata_blocks[ret].used = FALSE;

            if (ret == 0)
            {
                logger_error("cache_write_metadata: failed to find a free metadata block!");
            }

            logger_debug("cache_write_metadata: reusing block %d", ret);
        }
    }
    else
    {
        logger_debug("lookup success ret: %d", ret);
    }

    if (get_metadata_addr(ret) == NULL)
    {
        if (allocated_new_block)
            free_metadata_blocks[ret] = TRUE;

        logger_warning("cache_write_metadata: get_metadata_addr(%lu) failed", ret);
        return FALSE;
    }

    if (allocated_new_block && backed_metadata_blocks[ret].used)
    {
        logger_error("cache_write_metadata: allocated new block and block marked as used!");
    }

    if (!allocated_new_block && !backed_metadata_blocks[ret].used)
    {
        logger_error("cache_write_metadata: didn't allocated new block and block marked as unused!");
    }

    // TODO: maybe blindly trusting caller is bad?
    memcpy(&(backed_metadata_blocks[ret]), in_meta, sizeof(cached_metadata_block_t));
    // FIXME: do we need this?
    strncpy(backed_metadata_blocks[ret].path, path, PATH_MAX);
    backed_metadata_blocks[ret].used = TRUE;
    backed_metadata_blocks[ret].magic = CACHE_META_MAGIC;

    if (allocated_new_block)
    {
        if (cache_hashtable_insert(
                block_lookup_table,
                backed_metadata_blocks[ret].path,
                strlen(backed_metadata_blocks[ret].path),
                METADATA_FLAG,
                ret,
                FALSE))
        {
            logger_error("cache_write_block: hashtable put failed");
        }
    }

    logger_debug("cache_write_metadata: cached metadata for \"%s\"", path);

    return TRUE;
}

BOOL cache_clear_metadata(const char *path)
{
    uint64_t ret = 0;
    if (cache_hashtable_lookup(block_lookup_table, path, strlen(path), METADATA_FLAG, &ret))
        return FALSE;

    backed_metadata_blocks[ret].used = FALSE;
    backed_metadata_blocks[ret].magic = 0;

    cache_hashtable_remove(block_lookup_table, path, strlen(path), METADATA_FLAG);

    free_metadata_blocks[ret] = TRUE;

    return TRUE;
}