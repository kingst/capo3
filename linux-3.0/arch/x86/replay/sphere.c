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

static void sphere_wake_usermode(replay_sphere_t *sphere);

replay_sphere_t *sphere_alloc(void) {
        replay_sphere_t *sphere;
        sphere = kmalloc(sizeof(replay_sphere_t), GFP_KERNEL);
        if(sphere == NULL) {
                BUG();
                return NULL;
        }
        memset(sphere, 0, sizeof(replay_sphere_t));
 
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
        init_waitqueue_head(&sphere->usermode_wait);
        init_waitqueue_head(&sphere->replay_thread_wait);
        sphere->num_threads = 0;
        atomic_set(&sphere->fd_count, 0);
        atomic_set(&sphere->num_readers, 0);
        atomic_set(&sphere->num_writers, 0);
        sphere->header = NULL;

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

int sphere_is_recording_replaying(replay_sphere_t *sphere) {
        int ret = 0;

        spin_lock(&sphere->lock);
        if((sphere->state == recording) || (sphere->state == replaying))
                ret = 1;
        spin_unlock(&sphere->lock);

        return ret;
}

static int sphere_is_state(replay_sphere_t *sphere, uint32_t state) {
        int ret=0;
        spin_lock(&sphere->lock);
        if(sphere->state == state)
                ret = 1;
        spin_unlock(&sphere->lock);

        return ret;
}

int sphere_is_recording(replay_sphere_t *sphere) {
        return sphere_is_state(sphere, recording);
}

int sphere_is_replaying(replay_sphere_t *sphere) {
        return sphere_is_state(sphere, replaying);
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

int sphere_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count) {
        int ret;
        int bytesWritten=0;
        int flen, favail;

        if(kfifo_is_full(&sphere->fifo))
                BUG();

        spin_lock(&sphere->lock);
        if((sphere->state != replaying) && (sphere->state != idle)) {
                spin_unlock(&sphere->lock);
                BUG();
                return -EINVAL;
        }

        flen = kfifo_len(&sphere->fifo);
        favail = kfifo_avail(&sphere->fifo);

        if(favail < count)
                count = favail;

        ret = kfifo_from_user(&sphere->fifo, buf, count, &bytesWritten);
        spin_unlock(&sphere->lock);

        if(flen < sizeof(replay_header_t))
                sphere_wake_rthreads(sphere);

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesWritten;
}

int sphere_wait_usermode(replay_sphere_t *sphere, int full) {
        int ret;
        
        if(current->rtcb)
                BUG();

        if(full) {
                // if the fifo is full then wait
                ret = wait_event_interruptible(sphere->usermode_wait, 
                                               !kfifo_is_full(&sphere->fifo));
        } else {
                // if the fifo is empty then wait
                ret = wait_event_interruptible(sphere->usermode_wait, 
                                               sphere_has_data(sphere));
        }

        return (ret == -ERESTARTSYS) ? -ERESTARTSYS : 0;
}

static void sphere_wake_usermode(replay_sphere_t *sphere) {
        // we should be able to avoid these if there is no one 
        // waiting, but I am assuming that the wake up
        // handler handles this reasonable efficiently
        wake_up_interruptible(&sphere->usermode_wait);
}

static int start_record_replay(replay_sphere_t *sphere, replay_state_t state) {
        int num_threads;
        spin_lock(&sphere->lock);
        if(sphere->state != idle) {
                spin_unlock(&sphere->lock);
                return -EINVAL;
        }
        sphere->state = state;
        num_threads = sphere->num_threads;
        spin_unlock(&sphere->lock);
        
        if(num_threads != 0)
                BUG();

        return 0;
}

int sphere_start_recording(replay_sphere_t *sphere) {
        return start_record_replay(sphere, recording);
}

int sphere_start_replaying(replay_sphere_t *sphere) {
        return start_record_replay(sphere, replaying);
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
                sphere_wake_usermode(sphere);
        }
        spin_unlock(&sphere->lock);
}


/********************************** Helpers for recording *************************************/

static int record_header_locked(replay_sphere_t *sphere, replay_event_t event, 
                                uint32_t thread_id, struct pt_regs *regs) {
        int ret;
        uint32_t type = (uint32_t) event;

        if(sphere->state != recording)
                BUG();

        ret = kfifo_in(&sphere->fifo, &type, sizeof(type));
        if(ret != sizeof(type)) return -1;
        ret = kfifo_in(&sphere->fifo, &thread_id, sizeof(thread_id));
        if(ret != sizeof(thread_id)) return -1;
        ret = kfifo_in(&sphere->fifo, regs, sizeof(*regs));
        if(ret != sizeof(*regs)) return -1;

        sphere_wake_usermode(sphere);

        return 0;
}

static int record_buffer_locked(replay_sphere_t *sphere, uint64_t to_addr,
                                void *buf, uint32_t len) {

        int ret;
        if(sphere->state != recording)
                BUG();

        ret = kfifo_in(&sphere->fifo, &to_addr, sizeof(to_addr));
        if(ret != sizeof(to_addr)) return -1;
        ret = kfifo_in(&sphere->fifo, &len, sizeof(len));
        if(ret != sizeof(len)) return -1;
        ret = kfifo_in(&sphere->fifo, buf, len);
        if(ret != len) return -1;

        sphere_wake_usermode(sphere);

        return 0;
}

void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs) {
        int ret;

        spin_lock(&sphere->lock);
        ret = record_header_locked(sphere, event, thread_id, regs);
        spin_unlock(&sphere->lock);

        if(ret)
                BUG();
}

void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len) {
        int ret;
        unsigned long flags;

        spin_lock_irqsave(&sphere->lock, flags);
        ret = record_header_locked(sphere, copy_to_user_event,
                                   current->rtcb->thread_id, task_pt_regs(current));
        if(ret) {
                spin_unlock_irqrestore(&sphere->lock, flags);
                BUG();
                return;
        }
        ret = record_buffer_locked(sphere, to_addr, buf, len);
        spin_unlock_irqrestore(&sphere->lock, flags);

        if(ret)
                BUG();
}

/**********************************************************************************************/

/********************************* Helpers for replaying **************************************/

void sphere_wake_rthreads(replay_sphere_t *sphere) {
        wake_up_interruptible_all(&sphere->replay_thread_wait);
}

static int is_next_log(replay_sphere_t *sphere, uint32_t thread_id) {
        int len, ret;

        if(sphere->header == NULL) {
                len = kfifo_len(&sphere->fifo);
                if(len >= sizeof(replay_header_t)) {
                        sphere->header = kmalloc(sizeof(replay_header_t), GFP_KERNEL);
                        memset(sphere->header, 0, sizeof(replay_header_t));
                        ret = kfifo_out(&sphere->fifo, sphere->header, sizeof(replay_header_t));
                        if(ret != sizeof(replay_header_t))
                                BUG();
                        sphere_wake_usermode(sphere);
                }
        }

        if(sphere->header != NULL)
                return sphere->header->thread_id == thread_id;

        return 0;
}


// for this function we are going to use the replay_thread_wait lock
// and it will protect the sphere->header and the out end of the fifo. 
// No other code should touch the sphere->header unless it holds this lock also
//
// Also, the caller needs to kfree the memory returned from this function
static replay_header_t *replay_wait_for_log(replay_sphere_t *sphere, uint32_t thread_id) {
        int ret;
        replay_header_t *header;

        spin_lock(&sphere->replay_thread_wait.lock);
        ret = wait_event_interruptible_locked(sphere->replay_thread_wait, 
                                              is_next_log(sphere, thread_id));

        if(ret == -ERESTARTSYS) {
            spin_unlock(&sphere->replay_thread_wait.lock);
            return NULL;
        }

        if((sphere->header == NULL) || (sphere->header->thread_id != thread_id))
                BUG();
        header = sphere->header;
        sphere->header = NULL;
        spin_unlock(&sphere->replay_thread_wait.lock);

        sphere_wake_rthreads(sphere);

        return header;
}

void replay_event(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                  struct pt_regs *regs) {
        
        replay_header_t *header;

        header = replay_wait_for_log(sphere, thread_id);
        if(header == NULL)
                BUG();

        if(header->type == instruction_event) {
                regs->ax = header->regs.ax;
                regs->dx = header->regs.dx;
                regs->ip = header->regs.ip;
        }

        kfree(header);
}

/**********************************************************************************************/
