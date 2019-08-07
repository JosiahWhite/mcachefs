#ifndef THREADED_WORKER_H
#define THREADED_WORKER_H

#include "includes.h"
#include "fuse_requests.h"

typedef struct worker_thread_t worker_thread_t;

void worker_thread_init(int threads);
void worker_thread_push_request(generic_request_t *request);

#endif
