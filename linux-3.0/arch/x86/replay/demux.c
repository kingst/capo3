/*======================================================== 
** University of Illinois/NCSA 
** Open Source License 
**
** Copyright (C) 2011,The Board of Trustees of the University of 
** Illinois. All rights reserved. 
**
** Developed by: 
**
**    Research Group of Professor Sam King in the Department of Computer 
**    Science The University of Illinois at Urbana-Champaign 
**    http://www.cs.uiuc.edu/homes/kingst/Research.html 
**
** Copyright (C) Sam King
**
** Permission is hereby granted, free of charge, to any person obtaining a 
** copy of this software and associated documentation files (the 
** Software), to deal with the Software without restriction, including 
** without limitation the rights to use, copy, modify, merge, publish, 
** distribute, sublicense, and/or sell copies of the Software, and to 
** permit persons to whom the Software is furnished to do so, subject to 
** the following conditions: 
**
** Redistributions of source code must retain the above copyright notice, 
** this list of conditions and the following disclaimers. 
**
** Redistributions in binary form must reproduce the above copyright 
** notice, this list of conditions and the following disclaimers in the 
** documentation and/or other materials provided with the distribution. 
** Neither the names of Sam King or the University of Illinois, 
** nor the names of its contributors may be used to endorse or promote 
** products derived from this Software without specific prior written 
** permission. 
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
** IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR 
** ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
** SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE. 
**========================================================== 
*/

/*
 * Overall there are two key ordering constraints we need to enforce.  First,
 * we need to make sure that per processor entries are processed serially and
 * in chunk log order.  Second, we need to ensure that per thread entries are
 * also in processed in chunk log order.  To enforce these contraints we use
 * per processor queues and only clear chunks from the per processor queue
 * after a thread has finished with the chunk.  To enforce per thread ordering
 * constraints we use a ticket mechanism where each chunk is given a per thread
 * ticket, and threads can only grab a chunk when the ticket matches.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <asm/io.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <linux/file.h>
#include <linux/syscalls.h>

#include <trace/syscall.h>
#include <trace/events/syscalls.h>

#include <asm/replay.h>
#include <asm/mrr/simics_if.h>

#define DEMUX_BUF_SIZE (1024*4096)

typedef struct demux_chunk_struct {
        chunk_t chunk;
        uint64_t ticket;
} demux_chunk_t;


demux_t *demux_alloc(void) {
        demux_t *dm = kmalloc(sizeof(demux_t), GFP_KERNEL);
        BUG_ON(dm == NULL);
        memset(dm, 0, sizeof(demux_t));

        demux_reset(dm);

        return dm;
}


void demux_reset(demux_t *dm) {
        demux_ent_t *ent;
        int proc_id;

        cond_init(&dm->next_chunk_cond);
        for(proc_id=0; proc_id < NUM_CHUNK_PROC; proc_id++) {                
                ent = dm->entries + proc_id;
                if(ent->buf == NULL) 
                        ent->buf = kmalloc(DEMUX_BUF_SIZE, GFP_KERNEL);
                kfifo_init(&ent->fifo, ent->buf, DEMUX_BUF_SIZE);
                cond_init(&ent->fifo_full_cond);
        }
}

void demux_free(demux_t *dm) {
        kfree(dm);
}


static uint64_t alloc_next_ticket(demux_t *dm, uint32_t thread_id) {
        uint64_t ticket;
        uint32_t idx = thread_id-1;
        BUG_ON(idx >= NUM_CHUNK_PROC);

        ticket = dm->next_ticket[idx];
        dm->next_ticket[idx]++;
        
        return ticket;
}

static uint64_t get_current_ticket(demux_t *dm, uint32_t thread_id) {
        uint32_t idx = thread_id-1;
        BUG_ON(idx >= NUM_CHUNK_PROC);
        
        return dm->curr_ticket[idx];
}

static void inc_current_ticket(demux_t *dm, uint32_t thread_id) {
        uint32_t idx = thread_id-1;
        BUG_ON(idx >= NUM_CHUNK_PROC);
        dm->curr_ticket[idx]++;
}

int demux_from_user(demux_t *dm, const char __user *buf, size_t count, struct mutex *mutex) {
        demux_chunk_t *dchunk = kmalloc(sizeof(demux_chunk_t), GFP_KERNEL);
        chunk_t *chunk;
        int ret = 0;
        demux_ent_t *ent = NULL;

        BUG_ON(dchunk == NULL);

        chunk = &dchunk->chunk;

        while(count >= sizeof(chunk_t)) {
                // the usermode program is going to operate on chunk_t structures
                // read these in
                if(copy_from_user(chunk, buf, sizeof(chunk_t))) {
                        kfree(chunk);
                        return -EFAULT;
                }                

                ret += sizeof(chunk_t);
                count -= sizeof(chunk_t);

                // the kernel fifo operates on demux_chunk_t structures
                // which include tickets
                BUG_ON(chunk->processor_id >= NUM_CHUNK_PROC);
                ent = dm->entries + chunk->processor_id;
                dchunk->ticket = alloc_next_ticket(dm, chunk->thread_id);

                while(kfifo_avail(&ent->fifo) < sizeof(demux_chunk_t))
                        cond_wait(&ent->fifo_full_cond, mutex);
                
                printk(KERN_CRIT "pushing chunk tid=%u, ticket=%llu\n", dchunk->chunk.thread_id, dchunk->ticket);
                
                kfifo_in(&ent->fifo, dchunk, sizeof(demux_chunk_t));
                if(kfifo_len(&ent->fifo) == sizeof(demux_chunk_t))
                        cond_broadcast(&dm->next_chunk_cond);
        }

        kfree(dchunk);

        return ret;
}

static int has_chunk(demux_t *dm, uint32_t thread_id, demux_chunk_t *dchunk) {
        uint32_t proc_id;
        int ret;
        demux_ent_t *ent;
        uint64_t curr_ticket;

        curr_ticket = get_current_ticket(dm, thread_id);
        for(proc_id = 0; proc_id < NUM_CHUNK_PROC; proc_id++) {
                ent = dm->entries + proc_id;

                if(kfifo_len(&ent->fifo) >= sizeof(demux_chunk_t)) {
                        // leave the chunk in place on the queue to make sure
                        // that no other threads execute on behalf of this
                        // processor until we are done
                        ret = kfifo_out_peek(&ent->fifo, dchunk, sizeof(demux_chunk_t));
                        BUG_ON(ret != sizeof(demux_chunk_t));
                        BUG_ON(dchunk->chunk.processor_id != proc_id);
                        if((thread_id == dchunk->chunk.thread_id) && (curr_ticket == dchunk->ticket))
                                return 1;
                }
        }

        return 0;
}

chunk_t *demux_chunk_begin(demux_t *dm, uint32_t thread_id, struct mutex *mutex) {
        demux_chunk_t *dchunk;
        chunk_t *chunk;

        dchunk = kmalloc(sizeof(demux_chunk_t), GFP_KERNEL);
        memset(dchunk, 0, sizeof(demux_chunk_t));

        chunk = &dchunk->chunk;
        // the calling code is going to call kfree on the chunk so it has
        // to be at the beginning of the dchunk
        BUG_ON(chunk != (chunk_t *) dchunk);

        my_magic_message_int("waiting for the next chunk entry", thread_id);
        while(!has_chunk(dm, thread_id, dchunk)) {
                my_magic_message_int("waiting for the next chunk entry", thread_id);
                cond_wait(&dm->next_chunk_cond, mutex);
        }
        my_magic_message_int("got the next chunk entry", thread_id);

        return chunk;
}


void demux_chunk_end(demux_t *dm, struct mutex *mutex, chunk_t *chunk) {
        demux_ent_t *ent;
        int ret;
        demux_chunk_t *dchunk = (demux_chunk_t *) chunk;

        ent = dm->entries + chunk->processor_id;

        // clear the chunk we just processed so that the next chunk can run on
        // this processor
        ret = kfifo_out(&ent->fifo, dchunk, sizeof(demux_chunk_t));
        BUG_ON(ret != sizeof(demux_chunk_t));
        inc_current_ticket(dm, dchunk->chunk.thread_id);

        cond_broadcast(&dm->next_chunk_cond);
        cond_signal(&ent->fifo_full_cond);
}
