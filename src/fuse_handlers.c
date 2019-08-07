#include "fuse_handlers.h"
#include "fuse_requests.h"
#include "includes.h"
#include "inode_tracker.h"
#include "utils.h"
#include "worker_thread.h"

#include <errno.h>
#include <unistd.h>

static void lo_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi, int plus);

struct fuse_lowlevel_ops lo_oper = {
    .init = lo_init,
    .open = lo_open,
    .read = lo_read,
    .lookup = lo_lookup,
    .forget = lo_forget,
    .getattr = lo_getattr,
    .readlink = lo_readlink,
    .opendir = lo_opendir,
    .readdir = lo_readdir,
    .readdirplus = lo_readdirplus,
    .releasedir = lo_releasedir,
    .release = lo_release,
};

void lo_init(void *userdata, struct fuse_conn_info *conn)
{
    (void)userdata;
    conn->want |= FUSE_CAP_EXPORT_SUPPORT;
    conn->want &= ~(FUSE_CAP_AUTO_INVAL_DATA);
}

void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    open_request_t *worker_req = (open_request_t *)calloc(1, sizeof(open_request_t));
    worker_req->type = FUSE_OPEN;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);

    if (fi)
        memcpy(&(worker_req->fi), fi, sizeof(struct fuse_file_info));

    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    read_request_t *worker_req = (read_request_t *)calloc(1, sizeof(read_request_t));
    worker_req->type = FUSE_READ;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);
    worker_req->size = size;
    worker_req->offset = offset;

    if (fi)
        memcpy(&(worker_req->fi), fi, sizeof(struct fuse_file_info));

    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    lookup_request_t *worker_req = (lookup_request_t *)calloc(1, sizeof(lookup_request_t));
    worker_req->type = FUSE_LOOKUP;
    worker_req->req = req;
    worker_req->inode = lo_inode(req, parent);
    worker_req->parent = parent;
    strncpy(worker_req->name, name, PATH_MAX);
    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    forget_request_t *worker_req = (forget_request_t *)calloc(1, sizeof(forget_request_t));
    worker_req->type = FUSE_FORGET;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);
    worker_req->ino = ino;
    worker_req->nlookup = nlookup;
    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    getattr_request_t *worker_req = (getattr_request_t *)calloc(1, sizeof(getattr_request_t));
    worker_req->type = FUSE_GETATTR;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);

    if (fi)
        memcpy(&(worker_req->fi), fi, sizeof(struct fuse_file_info));

    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_readlink(fuse_req_t req, fuse_ino_t ino)
{
    readlink_request_t *worker_req = (readlink_request_t *)calloc(1, sizeof(readlink_request_t));
    worker_req->type = FUSE_READLINK;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);
    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    char pathtmp[PATH_MAX];
    int error = ENOMEM;
    lo_dirp_t *d = calloc(1, sizeof(lo_dirp_t));
    if (d == NULL)
        goto out_err;

    snprintf(pathtmp, PATH_MAX, "%s/%s/%s", lo_data(req)->root_path, lo_path(req, ino), ".");
    normalize_path_inplace(pathtmp);
    d->fd = open(pathtmp, O_RDONLY);
    if (d->fd == -1)
        goto out_errno;

    d->dp = fdopendir(d->fd);
    if (d->dp == NULL)
        goto out_errno;

    d->offset = 0;
    d->entry = NULL;

    fi->fh = (uintptr_t)d;
    fuse_reply_open(req, fi);
    return;

out_errno:
    error = errno;
out_err:
    if (d)
    {
        if (d->fd != -1)
            close(d->fd);
        free(d);
    }
    fuse_reply_err(req, error);
}

void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    lo_do_readdir(req, ino, size, offset, fi, 0);
}

void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    lo_do_readdir(req, ino, size, offset, fi, 1);
}

void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    lo_dirp_t *d = lo_dirp(fi);
    (void)ino;
    closedir(d->dp);
    free(d);
    fuse_reply_err(req, 0);
}

void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    release_request_t *worker_req = (release_request_t *)calloc(1, sizeof(release_request_t));
    worker_req->type = FUSE_RELEASE;
    worker_req->inode = lo_inode(req, ino);
    worker_req->req = req;
    strncpy(worker_req->path, lo_real_path(req, ino), PATH_MAX);

    if (fi)
        memcpy(&(worker_req->fi), fi, sizeof(struct fuse_file_info));

    worker_thread_push_request((generic_request_t *)worker_req);
}

void lo_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi, int plus)
{
    lo_dirp_t *d = lo_dirp(fi);
    char *buf;
    char *p;
    size_t rem;
    int err;

    (void)ino;

    buf = calloc(size, 1);
    if (!buf)
        return (void)fuse_reply_err(req, ENOMEM);

    if (offset != d->offset)
    {
        seekdir(d->dp, offset);
        d->entry = NULL;
        d->offset = offset;
    }
    p = buf;
    rem = size;
    while (1)
    {
        size_t entsize;
        off_t nextoff;

        if (!d->entry)
        {
            errno = 0;
            d->entry = readdir(d->dp);
            if (!d->entry)
            {
                if (errno && rem == size)
                {
                    err = errno;
                    goto error;
                }
                break;
            }
        }
        nextoff = telldir(d->dp);
        if (plus)
        {
            struct fuse_entry_param e;

            err = lo_do_lookup(req, ino, d->entry->d_name, &e);
            if (err)
                goto error;

            // TODO: enable writeback caching
            e.attr.st_mode &= 0xF000 | (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

            entsize = fuse_add_direntry_plus(req, p, rem,
                                             d->entry->d_name,
                                             &e, nextoff);
        }
        else
        {
            struct stat st = {
                .st_ino = d->entry->d_ino,
                .st_mode = d->entry->d_type << 12,
            };

            // TODO: enable writeback caching
            st.st_mode &= 0xF000 | (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

            entsize = fuse_add_direntry(req, p, rem,
                                        d->entry->d_name,
                                        &st, nextoff);
        }
        if (entsize > rem)
            break;

        p += entsize;
        rem -= entsize;

        d->entry = NULL;
        d->offset = nextoff;
    }

    fuse_reply_buf(req, buf, size - rem);
    free(buf);
    return;

error:
    free(buf);
    fuse_reply_err(req, err);
}
