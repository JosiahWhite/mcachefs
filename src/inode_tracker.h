#ifndef INODE_TRACKER_H
#define INODE_TRACKER_H 1

#include "includes.h"

#include <dirent.h>
#include <sys/types.h>

//typedef struct lo_inode_t lo_inode_t;
struct lo_inode_t
{
    lo_inode_t *next;
    lo_inode_t *prev;
    int fd;
    ino_t ino;
    dev_t dev;
    uint64_t nlookup;
    // path from root of tree
    char path[PATH_MAX];
    char full_path[PATH_MAX];
};

typedef struct
{
    int fd;
    DIR *dp;
    struct dirent *entry;
    off_t offset;
} lo_dirp_t;

typedef struct
{
    int fd;
    BOOL opened;
} lo_filep_t;

struct lo_data *lo_data(fuse_req_t req);
lo_inode_t *lo_inode(fuse_req_t req, fuse_ino_t ino);
int lo_fd(fuse_req_t req, fuse_ino_t ino);
char *lo_path(fuse_req_t req, fuse_ino_t ino);
char *lo_real_path(fuse_req_t req, fuse_ino_t ino);
int lo_debug(fuse_req_t req);
int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name, struct fuse_entry_param *e);
void lo_do_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
lo_inode_t *lo_find(struct lo_data *lo, struct stat *st);
void lo_free(lo_inode_t *inode);
lo_dirp_t *lo_dirp(struct fuse_file_info *fi);
lo_filep_t *lo_filep(struct fuse_file_info *fi);

#endif
