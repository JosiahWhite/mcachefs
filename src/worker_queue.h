#include <stdint.h>
#include <pthread.h>

#ifndef LOCKLESS_QUEUE_H
#define LOCKLESS_QUEUE_H

#include "includes.h"

typedef struct worker_queue worker_queue_t;

worker_queue_t *worker_queue_init(void);
void worker_queue_free(worker_queue_t *queue);
void worker_queue_push(worker_queue_t *queue, void *value);
void *worker_queue_pop(worker_queue_t *queue);
int worker_queue_size(worker_queue_t *queue);

#endif