#include "worker_thread.h"
#include "cache_ops.h"
#include "fuse_requests.h"
#include "includes.h"
#include "inode_tracker.h"
#include "logger.h"
#include "utils.h"
#include "worker_queue.h"

#include <errno.h>
#include <unistd.h>

struct worker_thread_t
{
    int index;
    pthread_t thread;
    worker_queue_t *queue;
};

static worker_thread_t *workers = NULL;
static int worker_threads = 0;
static void *worker_thread(void *_arg);

void worker_thread_init(int threads)
{
    if (workers != NULL)
        return;

    workers = calloc(threads, sizeof(worker_thread_t));
    worker_threads = threads;

    int i;
    for (i = 0; i < threads; i++)
    {
        workers[i].index = i + 1;
        workers[i].queue = worker_queue_init();
        if (pthread_create(&(workers[i].thread), NULL, worker_thread, &(workers[i])))
        {
            logger_error("worker_thread_init: pthread_create failed. %s", strerror(errno));
        }
    }
}

void worker_thread_push_request(generic_request_t *request)
{
    uint8_t thread_id = fnv64a((uint8_t *)request->path, strlen(request->path), 0) % worker_threads;
    worker_queue_push(workers[thread_id].queue, request);
}

void interupt_func(fuse_req_t req, void *data)
{
    logger_debug("interupt_func called: %p", data);
    fuse_reply_err(req, EINTR);
    free(data);
}

void *worker_thread(void *_arg)
{
    worker_thread_t *self = (worker_thread_t *)_arg;
    generic_request_t *request = NULL;

    cache_thread_init(self->index);

    while ((request = (generic_request_t *)worker_queue_pop(self->queue)) != NULL)
    {
        //fuse_req_interrupt_func(request->req, interupt_func, request);

        if (fuse_req_interrupted(request->req))
        {
            logger_debug("request has been interrupted: %p", request);
            fuse_reply_err(request->req, EINTR);
            free(request);
            continue;
        }

        logger_debug("thread: %d, got request type: %d, req addr: %p", self->index, request->type, request->req);

        switch (request->type)
        {
        case FUSE_OPEN:
        {
            open_request_t *open_req = (open_request_t *)request;
            lo_filep_t *f = calloc(1, sizeof(lo_filep_t));
            if (f == NULL)
            {
                fuse_reply_err(open_req->req, ENOMEM);
                break;
            }

            if (!cache_has_file(open_req->path))
            {
                errno = 0;
                f->fd = open(open_req->path, open_req->fi.flags & ~O_NOFOLLOW);
                if (f->fd == -1)
                {
                    free(f);
                    fuse_reply_err(open_req->req, errno);
                    break;
                }
                f->opened = TRUE;
            }
            else
            {
                f->opened = FALSE;
            }

            open_req->fi.fh = (uintptr_t)f;

            if (fuse_req_interrupted(request->req))
            {
                if (f->opened)
                    close(f->fd);

                free(f);
                fuse_reply_err(open_req->req, EINTR);
                break;
            }

            fuse_reply_open(open_req->req, &(open_req->fi));
        }
        break;
        case FUSE_READ:
        {
            read_request_t *read_req = (read_request_t *)request;
            lo_filep_t *f = lo_filep(&(read_req->fi));
            if (!f)
            {
                fuse_reply_err(read_req->req, EBADF);
                break;
            }

            unsigned char buf[read_req->size];
            int bytes_read = 0;
            uint32_t first_block = read_req->offset / cache_globals.blocksize;
            uint32_t last_block = (read_req->offset + read_req->size) / cache_globals.blocksize;
            uint64_t block;
            size_t buf_offset = 0;
            for (block = first_block; block <= last_block; block++)
            {
                off_t block_offset;
                size_t block_size;

                if (block == first_block)
                {
                    block_offset = (uint64_t)read_req->offset - block * (uint64_t)cache_globals.blocksize;
                }
                else
                {
                    block_offset = 0;
                }

                if (block == last_block)
                {
                    block_size = (read_req->offset + (uint64_t)read_req->size) - (block * (uint64_t)cache_globals.blocksize) - block_offset;
                }
                else
                {
                    block_size = cache_globals.blocksize - block_offset;
                }

                if (block_size == 0)
                    continue;

                uint32_t bread = block_size;
                BOOL result = cache_get_block(read_req->path, block, block_offset, buf + buf_offset, &bread);

                // if the cache grab worked, move onto the next block
                if (result)
                {
                    bytes_read += bread;

                    if (bread != block_size)
                    {
                        logger_warning("FUSE_READ: cache_get_block returned less(%lu) then the wanted amount(%lu) of bytes", bread, block_size);
                        break;
                    }

                    buf_offset += block_size;
                    continue;
                }

                if (!f->opened)
                {
                    errno = 0;
                    f->fd = open(read_req->path, read_req->fi.flags & ~O_NOFOLLOW);
                    if (f->fd == -1)
                    {
                        logger_warning("FUSE_READ: delayed open failed with error: %s", strerror(errno));
                        bytes_read = -1;
                        fuse_reply_err(read_req->req, errno);
                        break;
                    }
                    f->opened = TRUE;
                }

                logger_debug("cache does not have block %d in \"%s\"", block, read_req->path);

                unsigned char block_buf[cache_globals.blocksize];

                int ret = 0;
                int nread = 0, read_ret = 0;
                uint64_t real_off = cache_globals.blocksize * block;
                while (nread < cache_globals.blocksize)
                {
                    errno = 0;
                    read_ret = pread(f->fd, block_buf + nread, cache_globals.blocksize - nread, real_off + nread);
                    if (read_ret == -1)
                    {
                        // its possible that the cached metadata is old now, just clear it and hope for the best
                        cache_clear_metadata(read_req->path);
                        logger_warning("FUSE_READ: read error on real file");
                        ret = -EIO;
                        break;
                    }

                    if (read_ret == 0)
                    {
                        logger_debug("FUSE_READ: real read returned EOF?, errno: %d", errno);
                        break;
                    }

                    if (read_ret < (cache_globals.blocksize - nread))
                    {
                        logger_debug("FUSE_READ: real read returned early, trying again: %s", read_req->path);
                    }

                    nread += read_ret;
                }

                if (ret < 0)
                {
                    logger_warning("FUSE_READ: read from backing file returned error. bailing.");
                    bytes_read = -1;
                    fuse_reply_err(read_req->req, -ret);
                    break;
                }

                logger_debug("FUSE_READ: got %d bytes from underlying file", nread);

                if (!cache_write_block(read_req->path, block, block_buf, nread))
                {
                    logger_warning("FUSE_READ: cache_write_block failed");
                }

                memcpy(buf + buf_offset, block_buf + block_offset,
                       ((nread < block_size) ? nread : block_size));

                if (nread < block_size)
                {
                    logger_debug("FUSE_READ: read less than requested, %lu instead of %lu", nread, block_size);
                    bytes_read += nread;
                    logger_debug("FUSE_READ: bytes_read=%lu\n", bytes_read);
                    break;
                }
                else
                {
                    logger_debug("FUSE_READ: %lu bytes for fuse buffer", block_size);
                    bytes_read += block_size;
                    logger_debug("FUSE_READ: bytes_read=%lu", bytes_read);
                }

                buf_offset += block_size;
            }

            // means we already handled some shit in the loop
            if (bytes_read < 0)
                break;

            fuse_reply_buf(read_req->req, (char *)buf, bytes_read);
        }
        break;
        case FUSE_LOOKUP:
        {
            lookup_request_t *lookup_req = (lookup_request_t *)request;
            struct fuse_entry_param e;
            int err;

            err = lo_do_lookup(lookup_req->req, lookup_req->parent, lookup_req->name, &e);
            if (err)
                fuse_reply_err(lookup_req->req, err);
            else
                fuse_reply_entry(lookup_req->req, &e);
        }
        break;
        case FUSE_FORGET:
        {
            forget_request_t *forget_req = (forget_request_t *)request;
            lo_do_forget(forget_req->req, forget_req->ino, forget_req->nlookup);
            fuse_reply_none(forget_req->req);
        }
        break;
        case FUSE_GETATTR:
        {
            getattr_request_t *getattr_req = (getattr_request_t *)request;
            struct stat buf;

            cached_metadata_block_t meta_block;
            if (cache_get_metadata(getattr_req->path, &meta_block) &&
                meta_block.st_dev != 0 &&
                meta_block.st_ino != 0)
            {
                buf.st_dev = meta_block.st_dev;
                buf.st_ino = meta_block.st_ino;
                buf.st_mode = meta_block.st_mode;
                buf.st_uid = geteuid();
                buf.st_gid = getegid();
                buf.st_size = meta_block.st_size;
                buf.st_blksize = meta_block.st_blksize;
                buf.st_blocks = meta_block.st_blocks;
                buf.st_atime = meta_block.atime;
                buf.st_ctime = meta_block.ctime;
                buf.st_mtime = meta_block.ctime;
            }
            else
            {
                if (lstat(getattr_req->path, &buf) == -1)
                {
                    fuse_reply_err(getattr_req->req, errno);
                    break;
                }

                meta_block.st_dev = buf.st_dev;
                meta_block.st_ino = buf.st_ino;
                meta_block.st_mode = buf.st_mode;
                meta_block.st_size = buf.st_size;
                meta_block.st_blksize = buf.st_blksize;
                meta_block.st_blocks = buf.st_blocks;
                meta_block.atime = buf.st_atime;
                meta_block.ctime = buf.st_ctime;
                if (cache_write_metadata(getattr_req->path, &meta_block) == FALSE)
                {
                    logger_error("1 failed writing metadata to cache: %s", getattr_req->path);
                }

                // update these just for consistency
                buf.st_mtime = buf.st_ctime;
                buf.st_uid = geteuid();
                buf.st_gid = getegid();
            }

            // TODO: enable writeback caching
            buf.st_mode &= 0xF000 | (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
            fuse_reply_attr(getattr_req->req, &buf, 1.0);
        }
        break;
        case FUSE_READLINK:
        {
            readlink_request_t *readlink_req = (readlink_request_t *)request;
            char buf[PATH_MAX + 1];
            int res;

            res = readlink(readlink_req->path, buf, sizeof(buf));
            if (res == -1)
            {
                fuse_reply_err(readlink_req->req, errno);
                break;
            }

            if (res == sizeof(buf))
            {
                fuse_reply_err(readlink_req->req, ENAMETOOLONG);
                break;
            }

            buf[res] = '\0';

            fuse_reply_readlink(readlink_req->req, buf);
        }
        break;
        case FUSE_RELEASE:
        {
            release_request_t *release_req = (release_request_t *)request;

            lo_filep_t *f = lo_filep(&(release_req->fi));
            if (f)
            {
                if (f->opened)
                    close(f->fd);
                free(f);
            }
            fuse_reply_err(release_req->req, 0);
        }
        break;
        default:
            fuse_reply_err(request->req, ENOSYS);
            break;
        }

        free(request);
    }

    return NULL;
}
