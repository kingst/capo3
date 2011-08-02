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
#include <linux/mman.h>

#include <trace/syscall.h>
#include <trace/events/syscalls.h>

#include <asm/replay.h>

#define LOG_BUFFER_SIZE (8*1024*1024)

static void sphere_wake_usermode(replay_sphere_t *sphere);
static int sphere_wait_usermode(replay_sphere_t *sphere, int full);
static void sphere_wake_rthreads(replay_sphere_t *sphere);
static void replay_event_locked(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                                struct pt_regs *regs);
static int record_header_locked(replay_sphere_t *sphere, replay_event_t event, 
                                uint32_t thread_id, struct pt_regs *regs);


/********************************* Helpers for usermode ***************************************/

static int sphere_is_state(replay_sphere_t *sphere, uint32_t state) {
        replay_state_t s = atomic_read(&sphere->state);
        return s == state;
}

static int sphere_has_data(replay_sphere_t *sphere) {
        if(atomic_read(&sphere->state) == done)
                return 1;
        
        if(kfifo_len(&sphere->fifo) > 0)
                return 1;

        return 0;
}

static int sphere_is_done_recording(replay_sphere_t *sphere) {
        return (atomic_read(&sphere->state) == done) && (kfifo_len(&sphere->fifo) == 0);
}

static int sphere_fifo_to_user_ll(replay_sphere_t *sphere, char __user *buf, size_t count) {
        int ret;
        int bytesRead=0;
        int flen;

        if(sphere_is_done_recording(sphere))
                return 0;

        ret = sphere_wait_usermode(sphere, 0);
        if(ret)
                return ret;

        flen = kfifo_len(&sphere->fifo);
        BUG_ON(flen < 0);
        if(flen == 0) {
                BUG_ON(atomic_read(&sphere->state) != done);
                return 0;
        }

        if(flen < count)
                count = flen;

        ret = kfifo_to_user(&sphere->fifo, buf, count, &bytesRead);

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesRead;
}

static int sphere_fifo_from_user_ll(replay_sphere_t *sphere, const char __user *buf, size_t count) {
        int ret;
        int bytesWritten=0;
        int favail;
        replay_state_t state;

        ret = sphere_wait_usermode(sphere, 1);
        if(ret)
                return ret;

        if(kfifo_is_full(&sphere->fifo))
                BUG();

        state = atomic_read(&sphere->state);
        BUG_ON((state != replaying) && (state != idle));

        favail = kfifo_avail(&sphere->fifo);

        if(favail < count)
                count = favail;

        ret = kfifo_from_user(&sphere->fifo, buf, count, &bytesWritten);

        sphere_wake_rthreads(sphere);

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesWritten;
}


static int sphere_wait_usermode(replay_sphere_t *sphere, int full) {
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

/**********************************************************************************************/

/************************* Helpers for starting/exiting threads *******************************/

static int start_record_replay(replay_sphere_t *sphere, replay_state_t state) {
        int num_threads;                

        BUG_ON(atomic_read(&sphere->state) != idle);
        atomic_set(&sphere->state, state);

        num_threads = sphere->num_threads;

        BUG_ON(num_threads != 0);

        return 0;
}

static uint32_t sphere_next_thread_id(replay_sphere_t *sphere) {
        uint32_t id;

        id = sphere->next_thread_id++;
        sphere->num_threads++;

        return id;
}

/**********************************************************************************************/


/********************************** Helpers for recording *************************************/

static int record_header_locked(replay_sphere_t *sphere, replay_event_t event, 
                                uint32_t thread_id, struct pt_regs *regs) {
        int ret;
        uint32_t type = (uint32_t) event;

        if(atomic_read(&sphere->state) != recording)
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
        if(atomic_read(&sphere->state) != recording)
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

/**********************************************************************************************/

/********************************* Helpers for replaying **************************************/

static void sphere_wake_rthreads(replay_sphere_t *sphere) {
        wake_up_interruptible_all(&sphere->rr_thread_wait);
}

static int is_next_log(replay_sphere_t *sphere, uint32_t thread_id) {
        int len, ret;

        // if someone is in the middle of processing a copy to
        // user buffer, just exit immediately
        if(sphere->fifo_head_ctu_buf)
                return 0;

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


// for this function we are going to use the rr_thread_wait lock
// and it will protect the sphere->header and the out end of the fifo. 
// No other code should touch the sphere->header unless it holds this lock also
//
// Also, the caller needs to kfree the memory returned from this function
static replay_header_t *replay_wait_for_log(replay_sphere_t *sphere, uint32_t thread_id) {
        int ret;
        replay_header_t *header;

        ret = wait_event_interruptible_locked(sphere->rr_thread_wait, 
                                              is_next_log(sphere, thread_id));

        if(ret == -ERESTARTSYS)
                return NULL;

        if((sphere->header == NULL) || (sphere->header->thread_id != thread_id))
                BUG();
        header = sphere->header;
        sphere->header = NULL;

        return header;
}

static void replay_copy_to_user(replay_sphere_t *sphere, int make_copy) {
        uint64_t to_addr=0;
        uint32_t i, idx, ctu_len=0;
        int ret, bytesWritten, len;
        unsigned char c;

        sphere->fifo_head_ctu_buf = 1;

        // reuse the same wait queue, but this time we have a different condition
        // by setting fifo_head_ctu_buf = 1 we are ensuring that this thread
        // will be the only one that wakes up
        ret = wait_event_interruptible_locked(sphere->rr_thread_wait,
                                              kfifo_len(&sphere->fifo) >= (sizeof(to_addr)+sizeof(len)));

        if(ret == -ERESTARTSYS) {
                BUG();
                return;
        }
        
        ret = kfifo_out(&sphere->fifo, &to_addr, sizeof(to_addr));
        if(ret != sizeof(to_addr)) BUG();
        ret = kfifo_out(&sphere->fifo, &ctu_len, sizeof(ctu_len));
        if(ret != sizeof(ctu_len)) BUG();

        idx = 0;
        while(idx < ctu_len) {
                ret = wait_event_interruptible_locked(sphere->rr_thread_wait, kfifo_len(&sphere->fifo) > 0);
                
                if(ret == -ERESTARTSYS) {
                        BUG();
                        return;
                }

                len = kfifo_len(&sphere->fifo);
                if(len > (ctu_len-idx))
                        len = ctu_len-idx;
                if(make_copy) {
                        // this is for an emulated system call, we need to replay
                        // the copy to user calls to emulate it properly
                        ret = kfifo_to_user(&sphere->fifo, (void __user *) (to_addr+idx), len, 
                                            &bytesWritten);
                        if(ret || (len != bytesWritten)) BUG();
                } else {
                        // we are re-executing so squash the copy to user logs
                        bytesWritten = len;
                        // XXX FIXME we should put something here to check and make 
                        // sure the values are the same
                        for(i = 0; i < len; i++) {
                                ret = kfifo_out(&sphere->fifo, &c, sizeof(c));
                                if(ret != sizeof(c)) BUG();
                        }
                }
                idx += bytesWritten;
                sphere_wake_usermode(sphere);                                
        }

        sphere->fifo_head_ctu_buf = 0;

}

static int reexecute_syscall(struct pt_regs *regs) {
        if(regs->orig_ax == __NR_mmap) {
                if(regs->r10 == (MAP_ANONYMOUS | MAP_PRIVATE)) {
                        // this is effectively a way for the system to
                        // allocate memory, it is not backed by a file
                        return 1;
                } else {
                        // XXX FIXME for now I do not want to mess around
                        // with the mmap optimization so I don't want to
                        // support dlls.
                        BUG();
                }
        }
        switch (regs->orig_ax) {

        case __NR_execve: case __NR_brk: case __NR_arch_prctl:
        case __NR_exit_group:
                return 1;

        case __NR_uname: case __NR_open: case __NR_read: case __NR_close:
        case __NR_getuid: case __NR_geteuid: case __NR_getgid: case __NR_fstat:
        case __NR_ioctl: case __NR_write: case __NR_getegid:
                return 0;

        default:
                printk(KERN_CRIT "unhandled syscall %lu\n", regs->orig_ax);
                BUG();
                return 0;
        }
}

static void check_reg(char *reg, unsigned long a, unsigned long b) {
        if(a != b) {
                printk(KERN_CRIT "mismatch: %s %lu(0x%08lx) %lu(0x%08lx)\n",
                       reg, a, a, b, b);
                BUG();
        }
}

static void check_regs(struct pt_regs *regs, struct pt_regs *stored_regs) {
        // for now we will just check syscall parameters and a few others
        check_reg("orig_ax", regs->orig_ax, stored_regs->orig_ax);
        check_reg("ax", regs->ax, stored_regs->ax);
        check_reg("cx", regs->cx, stored_regs->cx);
        check_reg("dx", regs->dx, stored_regs->dx);
        check_reg("si", regs->si, stored_regs->si);
        check_reg("di", regs->di, stored_regs->di);
        check_reg("r8", regs->r8, stored_regs->r8);
        check_reg("r9", regs->r9, stored_regs->r9);
        check_reg("r10", regs->r10, stored_regs->r10);
        check_reg("r11", regs->r11, stored_regs->r11);
        check_reg("ip", regs->ip, stored_regs->ip);
        check_reg("sp", regs->sp, stored_regs->sp);
}

static void replay_handle_event(replay_sphere_t *sphere, replay_event_t event, 
                                struct pt_regs *regs, replay_header_t *header) {
        
        if((header->type == syscall_exit_event) && (header->regs.orig_ax == __NR_execve))
                sphere->replay_first_execve = 1;

        if(header->type == syscall_enter_event) {
                if(sphere->replay_first_execve)
                        check_regs(regs, &header->regs);
                if(!reexecute_syscall(regs))
                        regs->orig_ax = __NR_getpid;
        } else if(header->type == syscall_exit_event) {                
                if(regs->orig_ax == __NR_getpid) {
                        // emulate system call by copying registers
                        *regs = header->regs;
                } else if(sphere->replay_first_execve) {
                        // re-executed syscall, check regs to make sure
                        // everything is on track after first execve
                        check_regs(regs, &header->regs);
                }
        } else if(header->type == instruction_event) {
                // This is only for rdtsc for now, we can probably copy the entire regs struct
                regs->ax = header->regs.ax;
                regs->dx = header->regs.dx;
                regs->ip = header->regs.ip;
        }
}

// All of the replay helpers execute with the rr_thread_wait.lock held.  The wait
// queue will release the lock when a thread waits, but ensures that it is held when
// it resumes
static void replay_event_locked(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                                struct pt_regs *regs) {
        
        replay_header_t *header;
        int is_ctu = 0;
        do {
                header = replay_wait_for_log(sphere, thread_id);
                if(header == NULL)
                        BUG();
                
                // on emulated system calls we will get a number of copy to user
                // log entries between the system call enter and exit events
                // so we loop here on copy to user events until we finally
                // get to the system call exit event
                if(header->type == copy_to_user_event) {
                        is_ctu = 1;
                        replay_copy_to_user(sphere, regs->orig_ax == __NR_getpid);
                } else {
                        is_ctu = 0;
                        if(header->type != event)
                                BUG();
                }

                replay_handle_event(sphere, event, regs, header);

                kfree(header);
                header = NULL;

        } while(is_ctu);
}

/**********************************************************************************************/


/******************************** Public functions ********************************************/

// this is where all of the locking should take place

replay_sphere_t *sphere_alloc(void) {
        replay_sphere_t *sphere;
        sphere = kmalloc(sizeof(replay_sphere_t), GFP_KERNEL);
        if(sphere == NULL) {
                BUG();
                return NULL;
        }
        memset(sphere, 0, sizeof(replay_sphere_t));
 
        atomic_set(&sphere->state, done);
        sphere->next_thread_id = 0;
        sphere->replay_first_execve = 0;
        sphere->fifo_buffer = vmalloc(LOG_BUFFER_SIZE);
        if(sphere->fifo_buffer == NULL) {
                kfree(sphere);
                BUG();
                return NULL;
        }
        
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        init_waitqueue_head(&sphere->usermode_wait);
        init_waitqueue_head(&sphere->rr_thread_wait);
        sphere->num_threads = 0;
        atomic_set(&sphere->fd_count, 0);
        sphere->header = NULL;

        mutex_init(&sphere->usermode_mutex);

        return sphere;
}

void sphere_reset(replay_sphere_t *sphere) {
        spin_lock(&sphere->rr_thread_wait.lock);
        if(sphere->num_threads > 0)
                BUG();
        atomic_set(&sphere->state, idle);
        sphere->next_thread_id = 1;
        sphere->replay_first_execve = 0;
        if(kfifo_len(&sphere->fifo) > 0)
                printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");        
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        sphere->fifo_head_ctu_buf = 0;
        spin_unlock(&sphere->rr_thread_wait.lock);
}

int sphere_is_recording_replaying(replay_sphere_t *sphere) {
        replay_state_t state = atomic_read(&sphere->state);
        return (state == recording) || (state == replaying);
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

int sphere_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count) {
        int ret;
        mutex_lock(&sphere->usermode_mutex);
        ret = sphere_fifo_from_user_ll(sphere, buf, count);
        mutex_unlock(&sphere->usermode_mutex);
        return ret;
}

int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count) {
        int ret;
        mutex_lock(&sphere->usermode_mutex);
        ret = sphere_fifo_to_user_ll(sphere, buf, count);
        mutex_unlock(&sphere->usermode_mutex);
        return ret;
}

int sphere_start_recording(replay_sphere_t *sphere) {
        int ret;
        spin_lock(&sphere->rr_thread_wait.lock);
        ret = start_record_replay(sphere, recording);
        spin_unlock(&sphere->rr_thread_wait.lock);

        return ret;
}

int sphere_start_replaying(replay_sphere_t *sphere) {
        int ret;
        spin_lock(&sphere->rr_thread_wait.lock);
        ret = start_record_replay(sphere, replaying);
        spin_unlock(&sphere->rr_thread_wait.lock);

        return ret;
}

uint32_t sphere_thread_create(replay_sphere_t *sphere, struct pt_regs *regs) {
        uint32_t thread_id;
        int wake = 0;

        spin_lock(&sphere->rr_thread_wait.lock);
        thread_id = sphere_next_thread_id(sphere);
        if(sphere_is_recording(sphere)) {
                record_header_locked(sphere, thread_create_event, thread_id, regs);
        } else {
                replay_event_locked(sphere, thread_create_event, thread_id, regs);
                wake = 1;
        }

        spin_unlock(&sphere->rr_thread_wait.lock);

        // need this wake call because we replayed an event using
        // replay_event_locked
        if(wake)
                sphere_wake_rthreads(sphere);

        return thread_id;

}

void sphere_thread_exit(replay_sphere_t *sphere, uint32_t thread_id, struct pt_regs *regs) {
        int wake = 0;
        int wake_r = 0;

        spin_lock(&sphere->rr_thread_wait.lock);
        if(sphere_is_recording(sphere)) {
                record_header_locked(sphere, thread_exit_event, thread_id, regs);
        } else {
                replay_event_locked(sphere, thread_exit_event, thread_id, regs);
                wake_r = 1;
        }

        sphere->num_threads--;
        BUG_ON(sphere->num_threads < 0);
        
        if(sphere->num_threads == 0) {
                atomic_set(&sphere->state, done);
                wake = 1;
        }
        spin_unlock(&sphere->rr_thread_wait.lock);

        if(wake)
                sphere_wake_usermode(sphere);

        // need this wake call because we replayed an event using
        // replay_event_locked
        if(wake_r)
                sphere_wake_rthreads(sphere);
}


void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs) {
        int ret;

        spin_lock(&sphere->rr_thread_wait.lock);
        ret = record_header_locked(sphere, event, thread_id, regs);
        spin_unlock(&sphere->rr_thread_wait.lock);

        if(ret)
                BUG();
}

void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len) {
        int ret;
        unsigned long flags;

        spin_lock_irqsave(&sphere->rr_thread_wait.lock, flags);
        ret = record_header_locked(sphere, copy_to_user_event,
                                   current->rtcb->thread_id, task_pt_regs(current));
        if(ret) {
                spin_unlock_irqrestore(&sphere->rr_thread_wait.lock, flags);
                BUG();
                return;
        }
        ret = record_buffer_locked(sphere, to_addr, buf, len);
        spin_unlock_irqrestore(&sphere->rr_thread_wait.lock, flags);

        if(ret)
                BUG();
}


void replay_event(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                  struct pt_regs *regs) {
        spin_lock(&sphere->rr_thread_wait.lock);
        replay_event_locked(sphere, event, thread_id, regs);
        spin_unlock(&sphere->rr_thread_wait.lock);
        sphere_wake_rthreads(sphere);
}



/**********************************************************************************************/
