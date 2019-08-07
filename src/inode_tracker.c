#include "inode_tracker.h"
#include "cache_ops.h"
#include "includes.h"
#include "logger.h"
#include "utils.h"

#include <errno.h>
#include <unistd.h>

// FIXME: fix code so its not the bottleneck

pthread_mutex_t inode_tree = PTHREAD_MUTEX_INITIALIZER;

struct lo_data *lo_data(fuse_req_t req)
{
    return (struct lo_data *)fuse_req_userdata(req);
}

lo_inode_t *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
    if (ino == FUSE_ROOT_ID)
        return lo_data(req)->root;
    else
        return (lo_inode_t *)(uintptr_t)ino;
}

int lo_fd(fuse_req_t req, fuse_ino_t ino)
{
    return lo_inode(req, ino)->fd;
}

char *lo_path(fuse_req_t req, fuse_ino_t ino)
{
    return lo_inode(req, ino)->path;
}

char *lo_real_path(fuse_req_t req, fuse_ino_t ino)
{
    return lo_inode(req, ino)->full_path;
}

int lo_debug(fuse_req_t req)
{
    return lo_data(req)->debug != 0;
}

int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name, struct fuse_entry_param *e)
{
    int res;
    int saverr;
    lo_inode_t *inode;
    char pathtmp[PATH_MAX];

    memset(e, 0, sizeof(*e));
    e->attr_timeout = 1.0;
    e->entry_timeout = 1.0;

    snprintf(pathtmp, PATH_MAX, "%s/%s/%s", lo_data(req)->root_path, lo_path(req, parent), name);
    normalize_path_inplace(pathtmp);
    cached_metadata_block_t meta_block;
    if (cache_get_metadata(pathtmp, &meta_block) &&
        meta_block.st_dev != 0 &&
        meta_block.st_ino != 0)
    {
        e->attr.st_dev = meta_block.st_dev;
        e->attr.st_ino = meta_block.st_ino;
        e->attr.st_mode = meta_block.st_mode;
        e->attr.st_uid = geteuid();
        e->attr.st_gid = getegid();
        e->attr.st_size = meta_block.st_size;
        e->attr.st_blksize = meta_block.st_blksize;
        e->attr.st_blocks = meta_block.st_blocks;
        e->attr.st_atime = meta_block.atime;
        e->attr.st_ctime = meta_block.ctime;
        e->attr.st_mtime = meta_block.ctime;
    }
    else
    {
        res = lstat(pathtmp, &e->attr);
        if (res == -1)
            goto out_err;

        meta_block.st_dev = e->attr.st_dev;
        meta_block.st_ino = e->attr.st_ino;
        meta_block.st_mode = e->attr.st_mode;
        meta_block.st_size = e->attr.st_size;
        meta_block.st_blksize = e->attr.st_blksize;
        meta_block.st_blocks = e->attr.st_blocks;
        meta_block.atime = e->attr.st_atime;
        meta_block.ctime = e->attr.st_ctime;
        if (cache_write_metadata(pathtmp, &meta_block) == FALSE)
        {
            logger_error("lookup: failed writing metadata to cache: %s", pathtmp);
        }

        // update these just for consistency
        e->attr.st_mtime = e->attr.st_ctime;
        e->attr.st_uid = geteuid();
        e->attr.st_gid = getegid();
    }

    inode = lo_find(lo_data(req), &e->attr);
    if (!inode)
    {
        saverr = ENOMEM;
        inode = calloc(1, sizeof(lo_inode_t));
        if (!inode)
            goto out_err;

        snprintf(inode->path, PATH_MAX, "%s/%s", lo_path(req, parent), name);
        strncpy(inode->full_path, pathtmp, PATH_MAX);
        inode->ino = e->attr.st_ino;
        inode->dev = e->attr.st_dev;

        pthread_mutex_lock(&inode_tree);
        lo_inode_t *prev = lo_data(req)->root;
        lo_inode_t *next = prev->next;
        next->prev = inode;
        inode->next = next;
        inode->prev = prev;
        prev->next = inode;
        pthread_mutex_unlock(&inode_tree);
    }
    inode->nlookup++;
    e->ino = (uintptr_t)inode;

    if (lo_debug(req))
        fprintf(stderr, "  %s(%lli/%s) -> %lli\n",
                inode->path, (unsigned long long)parent, name, (unsigned long long)e->ino);

    return 0;

out_err:
    saverr = errno;
    return saverr;
}

lo_inode_t *lo_find(struct lo_data *lo, struct stat *st)
{
    lo_inode_t *p, *ret = NULL;

    uint32_t distance = 0;
    pthread_mutex_lock(&inode_tree);
    for (p = lo->root->next; p != lo->root; p = p->next, distance++)
    {
        if (p->ino == st->st_ino && p->dev == st->st_dev)
        {
            ret = p;
            break;
        }
    }
    pthread_mutex_unlock(&inode_tree);

    return ret;
}

void lo_free(lo_inode_t *inode)
{
    pthread_mutex_lock(&inode_tree);
    lo_inode_t *prev = inode->prev;
    lo_inode_t *next = inode->next;

    next->prev = prev;
    prev->next = next;
    if (inode->fd)
        close(inode->fd);
    free(inode);
    pthread_mutex_unlock(&inode_tree);
}

void lo_do_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    pthread_mutex_lock(&inode_tree);
    lo_inode_t *inode = lo_inode(req, ino);

    if (lo_debug(req))
        fprintf(stderr, "  forget %lli %lli -%lli\n",
                (unsigned long long)ino, (unsigned long long)inode->nlookup,
                (unsigned long long)nlookup);

    assert(inode->nlookup >= nlookup);
    inode->nlookup -= nlookup;

    if (!inode->nlookup)
    {
        lo_inode_t *prev = inode->prev;
        lo_inode_t *next = inode->next;

        next->prev = prev;
        prev->next = next;
        if (inode->fd)
            close(inode->fd);
        free(inode);
    }
    pthread_mutex_unlock(&inode_tree);
}

lo_dirp_t *lo_dirp(struct fuse_file_info *fi)
{
    return (lo_dirp_t *)(uintptr_t)fi->fh;
}

lo_filep_t *lo_filep(struct fuse_file_info *fi)
{
    return (lo_filep_t *)(uintptr_t)fi->fh;
}