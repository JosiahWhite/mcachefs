#ifndef FUSE_HANDLERS_H
#define FUSE_HANDLERS_H 1

#include "includes.h"

void lo_init(void *userdata, struct fuse_conn_info *conn);
void lo_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
void lo_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
void lo_readlink(fuse_req_t req, fuse_ino_t ino);
void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);

extern struct fuse_lowlevel_ops lo_oper;

#endif
