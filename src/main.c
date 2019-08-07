/*
  pasta4dayz
*/
#include "cache_ops.h"
#include "fuse_handlers.h"
#include "includes.h"
#include "inode_tracker.h"
#include "logger.h"
#include "utils.h"
#include "worker_thread.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum
{
    MCACHEFS_ARG_HELP,
    MCACHEFS_ARG_VERSION,
    MCACHEFS_ARG_CACHESIZE,
    MCACHEFS_ARG_CACHE,
};

#define OPTION(t, p)                      \
    {                                     \
        t, offsetof(struct lo_data, p), 1 \
    }
static const struct fuse_opt mcache_option_spec[] = {
    OPTION("sourcefs=%s", root_path),
    OPTION("blocksize=%lu", blocksize),
    FUSE_OPT_KEY("cache=%s", MCACHEFS_ARG_CACHE),
    FUSE_OPT_KEY("cachesize=%s", MCACHEFS_ARG_CACHESIZE),
    OPTION("-d", debug),
    OPTION("debug", debug),
    OPTION("-f", foreground),
    OPTION("foreground", foreground),
    FUSE_OPT_KEY("-h", MCACHEFS_ARG_HELP),
    FUSE_OPT_KEY("--help", MCACHEFS_ARG_HELP),
    FUSE_OPT_KEY("-V", MCACHEFS_ARG_VERSION),
    FUSE_OPT_KEY("--version", MCACHEFS_ARG_VERSION),
    FUSE_OPT_END};

static void mcache_usage(void)
{
    printf(
        "usage: mcachefs [options] <mountpoint>\n"
        "    -h   --help            print help\n"
        "    -V   --version         print version\n"
        "    -d   -o debug          enable debug output (implies -f)\n"
        "    -f   -o foreground     foreground operation\n"
        "    -o sourcefs=           backing filesystem\n"
        "    -o cache=              filename of cache image\n"
        "    -o cachesize=          size of cache image\n");
    fuse_lowlevel_help();
}

static int mcache_opt_proc(void *data, const char *arg, int key,
                           struct fuse_args *outargs)
{
    (void)outargs;
    struct lo_data *opts = data;

    switch (key)
    {
    case MCACHEFS_ARG_CACHE:
        if (!opts->cache_image)
        {
            char cache_image[PATH_MAX];
            errno = 0;
            if (realpath(arg + 6, cache_image) == NULL && errno != ENOENT)
            {
                printf("mCacheFS: bad cache image path `%s`: %s", arg + 6, strerror(errno));
                exit(-1);
            }
            return fuse_opt_add_opt(&opts->cache_image, cache_image);
        }
        else
        {
            fprintf(stderr, "fuse: invalid argument `%s'\n", arg);
            return -1;
        }
    case MCACHEFS_ARG_CACHESIZE:
        if (opts->cache_size == 0)
        {
            //shouldnt update the const string
            char *arg_copy = strdup(arg + 10);
            trim_inplace(arg_copy);
            if (arg_copy[0] == '-')
            {
                printf("mCacheFS: negative cache size specified!\n");
                return -1;
            }

            uint64_t res = 0; // Initialize result
            int i;
            for (i = 0; arg_copy[i] != '\0'; ++i)
            {
                if (arg_copy[i] > '9' || arg_copy[i] < '0')
                {
                    switch (tolower(arg_copy[i]))
                    {
                    case 'g':
                        res = res * 1024 * 1024 * 1024;
                        break;
                    case 'm':
                        res = res * 1024 * 1024;
                    case 'k':
                        res = res * 1024;
                    default:
                        res = 0;
                        break;
                    }
                    break;
                }

                res = res * 10 + arg_copy[i] - '0';
            }

            if (res == 0)
            {
                printf("mCacheFS: invalid cache size specified\n");
                return -1;
            }

            free(arg_copy);

            opts->cache_size = res;

            return 0;
        }
    case MCACHEFS_ARG_HELP:
        mcache_usage();
        exit(0);

    case MCACHEFS_ARG_VERSION:
        printf("mCacheFS version: 0.1\n");
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        exit(0);

    case FUSE_OPT_KEY_NONOPT:
        if (!opts->mountpoint)
        {
            char mountpoint[PATH_MAX];
            if (realpath(arg, mountpoint) == NULL)
            {
                printf("mCacheFS: bad mount point `%s`: %s", arg, strerror(errno));
                exit(-1);
            }
            return fuse_opt_add_opt(&opts->mountpoint, mountpoint);
        }
        else
        {
            fprintf(stderr, "fuse: invalid argument `%s'\n", arg);
            return -1;
        }

    default:
        /* Pass through unknown options */
        return 1;
    }
}

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct lo_data lo = {.debug = 0, .root_path = NULL, .mountpoint = NULL};
    int ret = -1;

    lo.root = calloc(1, sizeof(lo_inode_t));

    lo.root->next = lo.root->prev = lo.root;
    lo.root->fd = -1;

    if (fuse_opt_parse(&args, &lo, mcache_option_spec, mcache_opt_proc) == -1)
    {
        mcache_usage();
        return 0;
    }

    if (lo.root_path == NULL || lo.cache_image == NULL)
    {
        printf("root path null or cache image path null\n");
        mcache_usage();
        return 0;
    }

    if (lo.debug)
    {
        logger_init(TRUE, LOG_LEVEL_DEBUG);
        lo.foreground = TRUE;
        fuse_opt_add_arg(&args, "-d");
    }
    else
    {
        logger_init(FALSE, LOG_LEVEL_WARN);
    }

    if (!cache_init(lo.cache_image, &lo.blocksize, &lo.cache_size))
    {
        logger_error("failed initalizing cache!");
    }

    // TODO: read number of cpus or add option
    worker_thread_init(4);

    se = fuse_session_new(&args, &lo_oper, sizeof(lo_oper), &lo);
    if (se == NULL)
        goto err_out1;

    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

    char root_path[PATH_MAX];
    if (realpath(lo.root_path, root_path) == NULL)
    {
        printf("mCacheFS: bad mount point `%s`: %s\n", lo.root_path, strerror(errno));
        exit(-1);
    }
    else
    {
        free(lo.root_path);
        lo.root_path = strdup(root_path);
    }

    printf("lo.root_path: %s\n", lo.root_path);

    strncpy(lo.root->path, "/", PATH_MAX);
    strncpy(lo.root->full_path, lo.root_path, PATH_MAX);
    lo.root->nlookup = 2;

    if (fuse_session_mount(se, lo.mountpoint) != 0)
        goto err_out3;

    printf("foreground: %d\n", lo.foreground);

    fuse_daemonize(lo.foreground);

    struct fuse_buf fbuf = {
        .mem = NULL,
    };

    int ops = 0;

    while (!fuse_session_exited(se))
    {
        ret = fuse_session_receive_buf(se, &fbuf);

        if (ret == -EINTR)
            continue;
        if (ret <= 0)
            break;

        fuse_session_process_buf(se, &fbuf);
        
        ops++;
    }

    //free(fbuf.mem);
    fuse_session_reset(se);

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    fuse_opt_free_args(&args);

    while (lo.root->next != lo.root)
        lo_free(lo.root->next);
    if (lo.root->fd >= 0)
        close(lo.root->fd);

    return ret ? 1 : 0;
}
