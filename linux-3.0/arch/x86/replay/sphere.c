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

#include <trace/syscall.h>
#include <trace/events/syscalls.h>

#include <asm/replay.h>

#define LOG_BUFFER_SIZE (8*1024*1024)

replay_sphere_t *sphere_alloc(void) {
        replay_sphere_t *sphere;
        sphere = kmalloc(sizeof(replay_sphere_t), GFP_KERNEL);
        if(sphere == NULL) {
                BUG();
                return NULL;
        }
        
        sphere->state = done;
        sphere->next_thread_id = 0;
        sphere->fifo_buffer = vmalloc(LOG_BUFFER_SIZE);
        if(sphere->fifo_buffer == NULL) {
                kfree(sphere);
                BUG();
                return NULL;
        }
        
        spin_lock_init(&sphere->lock);
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        init_waitqueue_head(&sphere->readers_wait);
        sphere->num_threads = 0;
        atomic_set(&sphere->fd_count, 0);
        atomic_set(&sphere->num_readers, 0);
        atomic_set(&sphere->num_writers, 0);

        return sphere;
}

void sphere_reset(replay_sphere_t *sphere) {
        spin_lock(&sphere->lock);
        if(sphere->num_threads > 0)
                BUG();
        sphere->state = idle;
        sphere->next_thread_id = 1;
        if(kfifo_len(&sphere->fifo) > 0)
                printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        spin_unlock(&sphere->lock);
}

void sphere_inc_fd(replay_sphere_t *sphere) {
        atomic_inc(&sphere->fd_count);
}

void sphere_dec_fd(replay_sphere_t *sphere) {
        if(atomic_dec_return(&sphere->fd_count) < 0)
                BUG();
}

static int sphere_has_data(replay_sphere_t *sphere) {
        int len, ret;

        spin_lock(&sphere->lock);
        len = kfifo_len(&sphere->fifo);
        ret = (len > 0) || (sphere->state == done);
        spin_unlock(&sphere->lock);

        return ret;
}

int sphere_is_done_recording(replay_sphere_t *sphere) {
        spin_lock(&sphere->lock);
        if((sphere->state == done) && (kfifo_len(&sphere->fifo) == 0)) {
                spin_unlock(&sphere->lock);
                return 1;
        } else if(sphere->state == replaying) {
                spin_unlock(&sphere->lock);
                BUG();
                return 1;
        }
        spin_unlock(&sphere->lock);

        return 0;
}

int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count) {
        int ret;
        int bytesRead=0;
        int flen;
        replay_state_t state;

        spin_lock(&sphere->lock);
        flen = kfifo_len(&sphere->fifo);
        if(flen == 0) {
                state = sphere->state;
                spin_unlock(&sphere->lock);
                if(state != done)
                        BUG();
                return 0;
        }

        if(flen < count)
                count = flen;

        if(flen < 0)
                BUG();

        ret = kfifo_to_user(&sphere->fifo, buf, count, &bytesRead);
        spin_unlock(&sphere->lock);

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesRead;
}

int sphere_wait_readers(replay_sphere_t *sphere) {
        int ret;

        ret = wait_event_interruptible(sphere->readers_wait, sphere_has_data(sphere));

        return (ret == -ERESTARTSYS) ? -ERESTARTSYS : 0;
}

void sphere_wake_readers(replay_sphere_t *sphere) {
        // we should be able to avoid these if there is no one 
        // waiting, but I am assuming that the wake up
        // handler handles this reasonable efficiently
        wake_up_interruptible(&sphere->readers_wait);
}


int sphere_start_recording(replay_sphere_t *sphere) {
        int num_threads;
        spin_lock(&sphere->lock);
        if(sphere->state != idle) {
                spin_unlock(&sphere->lock);
                return -EINVAL;
        }
        sphere->state = recording;
        num_threads = sphere->num_threads;
        spin_unlock(&sphere->lock);
        
        if(num_threads != 0)
                BUG();

        return 0;

}

uint32_t sphere_next_thread_id(replay_sphere_t *sphere) {
        uint32_t id;
        spin_lock(&sphere->lock);
        id = sphere->next_thread_id++;
        sphere->num_threads++;
        spin_unlock(&sphere->lock);

        return id;
}

void sphere_thread_exit(replay_sphere_t *sphere) {
        spin_lock(&sphere->lock);
        sphere->num_threads--;
        if(sphere->num_threads < 0) {
                spin_unlock(&sphere->lock);
                BUG();
        }
        
        if(sphere->num_threads == 0) {
                sphere->state = done;
                sphere_wake_readers(sphere);
        }
        spin_unlock(&sphere->lock);
}
