#include <stdint.h>

#ifndef UTILS_H
#define UTILS_H

void normalize_path_inplace(char *path);
void trim_inplace(char *str);
uint64_t fnv64a(const uint8_t *data, int data_size, uint64_t extra);
uint32_t hash_fold(uint32_t a, uint32_t b);
void hexDump(char *desc, void *addr, int len);

#endif
