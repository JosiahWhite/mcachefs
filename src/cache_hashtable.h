#include <pthread.h>
#include <stdint.h>

#ifndef CACHE_HASHTABLE_H
#define CACHE_HASHTABLE_H

enum entry_status
{
    KEY_FREE = 0,
    KEY_USED = 1,
    KEY_LOCKED = 2
};

// TODO: d y n a m i c  a l l o c a t i o n
#define CACHE_MAX_BUCKET_ENTRIES 32

// a unique item has differing seed values and/or differing keys
typedef struct cache_hashtable_entry_t
{
    uint8_t status;

    uint32_t hash;

    uint8_t copied_key;
    const void *key;
    int keysize;
    // call this a second "hash"
    uint32_t seed;

    uint64_t value;

    struct cache_hashtable_entry_t *next;
    struct cache_hashtable_entry_t *prev;
} cache_hashtable_entry_t;

typedef struct
{
    // TODO: syncro
    uint8_t used;
    cache_hashtable_entry_t entries[CACHE_MAX_BUCKET_ENTRIES];
} cache_hashtable_bucket_t;

typedef struct
{
    // TODO: maybe implement dynamic resizing?
    // could do via linked list of bucket arrays but thats ugly af
    unsigned int key_count;
    unsigned int array_size;
    cache_hashtable_bucket_t *buckets;
    unsigned int collisions;
    // TODO: implement
    //double max_load_factor;
    double current_load_factor;

    pthread_mutex_t lru_mutex;
    // easily check most recently and least recently used
    // also ghetto tho
    cache_hashtable_entry_t *head;
    cache_hashtable_entry_t *tail;
} cache_hashtable_t;

// now these may look odd with the whole keysize + seed thing but
// its ez for me since i need to store two things in the key and im lazy.

cache_hashtable_t *cache_hashtable_init(int size);
int cache_hashtable_insert(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed, uint64_t value, uint8_t copy_key);
int cache_hashtable_lookup(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed, uint64_t *value);
int cache_hashtable_remove(cache_hashtable_t *ht, const void *key, int keysize, uint32_t seed);

#endif
