#include <fuse_lowlevel.h>
#include <limits.h>

#ifndef FUSE_REQUESTS
#define FUSE_REQUESTS

#include "inode_tracker.h"

enum
{
    FUSE_NOP = 0,
    FUSE_OPEN,
    FUSE_READ,
    FUSE_LOOKUP,
    FUSE_GETATTR,
    FUSE_READLINK,
    FUSE_FORGET,
    FUSE_RELEASE
};

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
} __attribute__((packed)) generic_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
    struct fuse_file_info fi;
} __attribute__((packed)) open_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
    size_t size;
    off_t offset;
    struct fuse_file_info fi;
} __attribute__((packed)) read_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char name[PATH_MAX];
    fuse_ino_t parent;
} __attribute__((packed)) lookup_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
    struct fuse_file_info fi;
} __attribute__((packed)) getattr_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
} __attribute__((packed)) readlink_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
    fuse_ino_t ino;
    uint64_t nlookup;
} __attribute__((packed)) forget_request_t;

typedef struct
{
    fuse_req_t req;
    uint8_t type;
    lo_inode_t *inode;
    char path[PATH_MAX];
    fuse_ino_t ino;
    struct fuse_file_info fi;
} __attribute__((packed)) release_request_t;

#endif
