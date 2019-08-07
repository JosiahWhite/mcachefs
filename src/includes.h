#ifndef INCLUDES_H
#define INCLUDES_H

#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include <assert.h>
#include <fuse_lowlevel.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef int BOOL;
#define TRUE 1
#define FALSE 0

// yes i know this isnt safe as it could cause
// double evaluation but do i care right now? no. will i care later? probably.
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define ROUND_UP(x, y) (((x) + (y)-1) & ~((y)-1))
#define ROUND_DOWN(x, y) ((x) & ~((y)-1))

typedef struct lo_inode_t lo_inode_t;

struct lo_data
{
	char *mountpoint;
	char *root_path;
	char *cache_image;
	uint32_t blocksize;
	uint64_t cache_size;
	int debug;
	int foreground;
	lo_inode_t *root;
};

#endif
