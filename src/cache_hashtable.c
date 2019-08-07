#include "cache_hashtable.h"
#include "logger.h"
#include "utils.h"

#include <errno.h>
#include <stdint.h>

static uint32_t hash_key_seed(const void *key, int keysize, uint32_t seed)
{
    if (keysize == 0)
        return hash_fold((uintptr_t)key, seed);

    return (uint32_t)fnv64a(key, keysize, seed);
}

cache_hashtable_t *cache_hashtable_init(int size)
{
    if (size == 0)
    {
        logger_warning("cache_hashtable_init: we do not support dynamic resizing yet.");
        return NULL;
    }

    cache_hashtable_t *ht = calloc(1, sizeof(cache_hashtable_t));
    if (ht == NULL)
    {
        logger_warning("cache_hashtable_init: ht calloc failed: %s", strerror(errno));
        return NULL;
    }
    ht->array_size = size;
    ht->buckets = calloc(size, sizeof(cache_hashtable_bucket_t));
    if (ht->buckets == NULL)
    {
        logger_warning("cache_hashtable_init: ht->buckets calloc failed: %s", strerror(errno));
        free(ht);
        return NULL;
    }

    // FIXME: fix so we dont need this
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);

    pthread_mutex_init(&ht->lru_mutex, &attr);
    ht->head = NULL;
    ht->tail = NULL;

    pthread_mutexattr_destroy(&attr);

    return ht;
}

int cache_hashtable_insert(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed, uint64_t value, uint8_t copy_key)
{
    // TODO: syncro
    if (ht == NULL)
        return 1;

    // TODO: check if power of two would be worthwhile to implement
    uint32_t hash = hash_key_seed(key, keysize, seed);
    uint32_t bucket_index = hash % ht->array_size;

    // we don't have to worry much about syncronization on this as its not really used yet
    ht->buckets[bucket_index].used = 1;

    int i;
    for (i = 0; i < CACHE_MAX_BUCKET_ENTRIES; i++)
    {
        cache_hashtable_entry_t *entry = &(ht->buckets[bucket_index].entries[i]);
        // dis ur entry?
        if (entry->status == KEY_USED)
        {
            if (entry->hash != hash)
                continue;

            if (entry->keysize != keysize)
            {
                logger_debug("cache_hashtable_insert: 1 found collision at entry %d in bucket %d", i, bucket_index);
                continue;
            }

            if (entry->keysize == 0 && entry->key != key)
            {
                logger_debug("cache_hashtable_insert: 2 found collision at entry %d in bucket %d", i, bucket_index);
                continue;
            }
            else if (entry->keysize != 0 && memcmp(entry->key, key, keysize) != 0)
            {
                logger_debug("cache_hashtable_insert: 3 found collision at entry %d in bucket %d", i, bucket_index);
                continue;
            }

            if (entry->seed != seed)
            {
                logger_debug("cache_hashtable_insert: 4 found collision at entry %d in bucket %d", i, bucket_index);
                continue;
            }

            logger_debug("cache_hashtable_insert: found existing bucket. old: %lu, new: %lu, updating value...", entry->value, value);
            entry->value = value;
            return 0;
        }
        else if (entry->status == KEY_FREE)
        {
            // this is the only real thing we have to worry about so that two threads dont overwrite the same entry box
            if (!__sync_bool_compare_and_swap(&(entry->status), KEY_FREE, KEY_LOCKED))
            {
                // restart the loop.
                // TODO: make less hacky
                // we use -1 cause continue will increment the value
                i = -1;
                continue;
            }

            if (copy_key == TRUE)
            {
                uint8_t *new_key = malloc(keysize);
                memcpy(new_key, key, keysize);
                entry->key = new_key;
                entry->copied_key = TRUE;
            }
            else
            {
                entry->key = key;
                entry->copied_key = FALSE;
            }

            // dis my entry.
            entry->keysize = keysize;
            entry->seed = seed;
            entry->value = value;
            entry->hash = hash;

            pthread_mutex_lock(&ht->lru_mutex);
            if (ht->head == NULL)
            {
                ht->head = entry;
                ht->tail = entry;
            }
            else
            {
                entry->next = ht->head;
                ht->head->prev = entry;
                ht->head = entry;
            }
            pthread_mutex_unlock(&ht->lru_mutex);

            //logger_debug("cache_hashtable_insert: inserted key %s, seed %lx at entry %d in bucket %lu", key, seed, i, bucket_index);

            entry->status = KEY_USED;

            return 0;
        }
    }

    logger_warning("failed to insert key into hashmap, is the entry list full?");
    return 1;
}

int cache_hashtable_lookup(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed, uint64_t *value)
{
    // TODO: syncro
    if (ht == NULL)
        return 1;

    // TODO: check if power of two would be worthwhile to implement
    uint32_t hash = hash_key_seed(key, keysize, seed);
    uint32_t bucket_index = hash % ht->array_size;

    if (!ht->buckets[bucket_index].used)
    {
        logger_debug("cache_hashtable_lookup: bucket %lu not marked as used", bucket_index);
        return 1;
    }

    int i;
    for (i = 0; i < CACHE_MAX_BUCKET_ENTRIES; i++)
    {
        cache_hashtable_entry_t *entry = &(ht->buckets[bucket_index].entries[i]);

        // again not too worried about syncronization on this. worst case we dont find the item
        if (entry->status == KEY_USED)
        {
            uint64_t val = entry->value;

            logger_debug("entry %d used in bucket %d, val: %lu", i, bucket_index, val);

            if (entry->hash != hash)
                continue;

            if (entry->keysize != keysize)
                continue;

            if (entry->keysize == 0 && entry->key != key)
                continue;
            else if (entry->keysize != 0 && memcmp(entry->key, key, keysize) != 0)
                continue;

            if (entry->seed != seed)
                continue;

            *value = val;

            // TODO: figure out how to do this without using slow mutex
            pthread_mutex_lock(&ht->lru_mutex);
            if (ht->head != entry)
            {
                if (ht->tail == entry)
                {
                    ht->tail = ht->tail->prev;
                    ht->tail->next = NULL;
                }
                else
                {
                    entry->prev->next = entry->next;
                    entry->next->prev = entry->prev;
                }

                entry->next = ht->head;
                entry->prev = NULL;
                ht->head->prev = entry;
                ht->head = entry;
            }
            pthread_mutex_unlock(&ht->lru_mutex);

            return 0;
        }
        else if (entry->status == KEY_LOCKED)
        {
            // should we reset the loop and try to search again?
            logger_debug("found locked key in bucket %d", bucket_index);
        }
    }

    logger_debug("cache_hashtable_lookup: hit end of entry list at bucket %lu", bucket_index);

    return 1;
}

int cache_hashtable_remove(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed)
{
    // TODO: syncro
    if (ht == NULL)
        return 1;

    // TODO: check if power of two would be worthwhile to implement
    uint32_t hash = hash_key_seed(key, keysize, seed);
    uint32_t bucket_index = hash % ht->array_size;

    int i;
    for (i = 0; i < CACHE_MAX_BUCKET_ENTRIES; i++)
    {
        cache_hashtable_entry_t *entry = &(ht->buckets[bucket_index].entries[i]);
        // dis ur entry?
        if (entry->status == KEY_USED)
        {
            if (entry->hash != hash)
                continue;

            if (entry->keysize != keysize)
                continue;

            if (entry->keysize == 0 && entry->key != key)
                continue;
            else if (entry->keysize != 0 && memcmp(entry->key, key, keysize) != 0)
                continue;

            if (entry->seed != seed)
                continue;

            if (!__sync_bool_compare_and_swap(&(entry->status), KEY_USED, KEY_LOCKED))
            {
                logger_debug("cache_hashtable_remove: key contention");
                // someone else was working on this item
                i = 0;
                continue;
            }

            // dump it from the list
            logger_debug("entry->prev = %p", entry->prev);
            logger_debug("entry->next = %p", entry->next);

            pthread_mutex_lock(&ht->lru_mutex);
            if (ht->tail == entry)
            {
                ht->tail = ht->tail->prev;
                ht->tail->next = NULL;
            }
            else
            {
                if (entry->next != NULL)
                    entry->next->prev = entry->prev;

                if (entry->prev != NULL)
                    entry->prev->next = entry->next;
            }
            pthread_mutex_unlock(&ht->lru_mutex);

            // if the hashmap is currently being used we have
            // a small chance of someone updating the key when we swap status
            uint8_t copied_key = entry->copied_key;
            void *saved_key = (void *)entry->key;

            if (__sync_bool_compare_and_swap(&(entry->status), KEY_LOCKED, KEY_FREE))
            {
                // TODO: maybe memset entry to 0
                if (copied_key == TRUE)
                    free(saved_key);
                return 0;
            }
        }
    }

    return 1;
}
