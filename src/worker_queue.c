#include "worker_queue.h"
#include "logger.h"

#define QUEUE_BUFFER_SIZE 1000
struct worker_queue
{
	void *buffer[QUEUE_BUFFER_SIZE];
	int size;
	int in;
	int out;
	pthread_mutex_t mutex;
	pthread_cond_t cond_full;
	pthread_cond_t cond_empty;
};

worker_queue_t *worker_queue_init(void)
{
	worker_queue_t *ret = (worker_queue_t *)calloc(1, sizeof(worker_queue_t));
	if (ret == NULL)
		return NULL;

	pthread_mutex_init(&(ret->mutex), NULL);
	pthread_cond_init(&(ret->cond_full), NULL);
	pthread_cond_init(&(ret->cond_empty), NULL);
	return ret;
}

void worker_queue_free(worker_queue_t *queue)
{
	if (queue == NULL)
		return;

	if (queue->size > 0)
		logger_warning("worker_queue_free: queue not empty");

	free(queue);
}

void worker_queue_push(worker_queue_t *queue, void *value)
{
	pthread_mutex_lock(&(queue->mutex));
	while (queue->size == QUEUE_BUFFER_SIZE)
		pthread_cond_wait(&(queue->cond_full), &(queue->mutex));
	queue->buffer[queue->in] = value;
	++queue->size;
	++queue->in;
	queue->in %= QUEUE_BUFFER_SIZE;
	pthread_mutex_unlock(&(queue->mutex));
	pthread_cond_broadcast(&(queue->cond_empty));
}

void *worker_queue_pop(worker_queue_t *queue)
{
	pthread_mutex_lock(&(queue->mutex));
	while (queue->size == 0)
		pthread_cond_wait(&(queue->cond_empty), &(queue->mutex));
	void *value = queue->buffer[queue->out];
	--queue->size;
	++queue->out;
	queue->out %= QUEUE_BUFFER_SIZE;
	pthread_mutex_unlock(&(queue->mutex));
	pthread_cond_broadcast(&(queue->cond_full));
	return value;
}

int worker_queue_size(worker_queue_t *queue)
{
	pthread_mutex_lock(&(queue->mutex));
	int size = queue->size;
	pthread_mutex_unlock(&(queue->mutex));
	return size;
}