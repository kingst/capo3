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

#define DMUX_BUF_SIZE 4096

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
                        ent->buf = kmalloc(DMUX_BUF_SIZE, GFP_KERNEL);
                kfifo_init(&ent->fifo, ent->buf, DMUX_BUF_SIZE);
                cond_init(&ent->fifo_full_cond);
        }
}

void demux_free(demux_t *dm) {
        kfree(dm);
}


int demux_from_user(demux_t *dm, const char __user *buf, size_t count, struct mutex *mutex) {
        chunk_t *chunk = kmalloc(sizeof(chunk_t), GFP_KERNEL);
        int ret = 0;
        demux_ent_t *ent = NULL;

        BUG_ON(chunk == NULL);

        while(count >= sizeof(chunk_t)) {
                if(copy_from_user(chunk, buf, sizeof(chunk_t))) {
                        kfree(chunk);
                        return -EFAULT;
                }                

                ret += sizeof(chunk_t);
                BUG_ON(chunk->processor_id >= NUM_CHUNK_PROC);
                ent = dm->entries + chunk->processor_id;

                while(kfifo_avail(&ent->fifo) < sizeof(chunk_t))
                        cond_wait(&ent->fifo_full_cond, mutex);

                kfifo_in(&ent->fifo, chunk, sizeof(chunk_t));
                if(kfifo_len(&ent->fifo) == sizeof(chunk_t))
                        cond_broadcast(&dm->next_chunk_cond);

                count -= sizeof(chunk_t);
        }

        kfree(chunk);

        return ret;
}

static int has_chunk(demux_t *dm, uint32_t thread_id, chunk_t *chunk) {
        uint32_t proc_id;
        int ret;
        demux_ent_t *ent;

        for(proc_id = 0; proc_id < NUM_CHUNK_PROC; proc_id++) {
                ent = dm->entries + proc_id;

                if(kfifo_len(&ent->fifo) >= sizeof(chunk_t)) {
                        // leave the chunk in place on the queue to make sure
                        // that no other threads execute on behalf of this
                        // processor until we are done
                        ret = kfifo_out_peek(&ent->fifo, chunk, sizeof(chunk_t));
                        BUG_ON(ret != sizeof(chunk_t));
                        BUG_ON(chunk->processor_id != proc_id);
                        if(thread_id == chunk->thread_id)
                                return 1;
                }
        }

        return 0;
}

chunk_t *demux_chunk_begin(demux_t *dm, uint32_t thread_id, struct mutex *mutex) {
        chunk_t *chunk;

        chunk = kmalloc(sizeof(chunk_t), GFP_KERNEL);
        memset(chunk, 0, sizeof(chunk_t));

        while(!has_chunk(dm, thread_id, chunk))
                cond_wait(&dm->next_chunk_cond, mutex);

        return chunk;
}


void demux_chunk_end(demux_t *dm, struct mutex *mutex, chunk_t *chunk) {
        demux_ent_t *ent;
        int ret;

        ent = dm->entries + chunk->processor_id;

        // clear the chunk we just processed so that the next chunk can run on
        // this processor
        ret = kfifo_out(&ent->fifo, chunk, sizeof(chunk_t));
        BUG_ON(ret != sizeof(chunk_t));

        cond_broadcast(&dm->next_chunk_cond);
        cond_signal(&ent->fifo_full_cond);
}
