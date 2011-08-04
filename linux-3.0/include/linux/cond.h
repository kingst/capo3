#ifndef __COND_H__
#define __COND_H__

#include <linux/wait.h>
#include <linux/mutex.h>

typedef struct cond_struct {
        wait_queue_head_t wait;
        uint64_t thread_count;
        uint64_t wait_num;
} cond_t;

void cond_init(cond_t *cond);
void cond_wait(cond_t *cond, struct mutex *mutex);
void cond_signal(cond_t *cond);
void cond_broadcast(cond_t *cond);

#endif
