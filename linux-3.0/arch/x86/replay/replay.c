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
#define NUM_REPLAY_MINOR 4

typedef enum {idle, recording, replaying, done} replay_state_t;

typedef struct replay_sphere {
        replay_state_t state;
        unsigned char *fifo_buffer;
        spinlock_t lock;
        struct kfifo fifo;
        wait_queue_head_t wait;
        uint32_t next_thread_id;
        atomic_t fd_count;
        atomic_t num_threads;
        atomic_t num_readers;
        atomic_t num_writers;
} replay_sphere_t;

void replay_thread_create(struct task_struct *tsk, replay_sphere_t *sphere);
static void wake_readers(replay_sphere_t *sphere);

static struct class *replay_class = NULL;
static struct file_operations replay_fops;
static int replay_major = 0;

#define REPLAY_VERSION	"0.3"

static int replay_open(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere;

        if(inode->i_private == NULL) {
                sphere = kmalloc(sizeof(replay_sphere_t), GFP_KERNEL);
                if(sphere == NULL) {
                        BUG();
                        return -ENOMEM;
                }

                sphere->state = done;
                sphere->next_thread_id = 0;
                sphere->fifo_buffer = vmalloc(LOG_BUFFER_SIZE);
                if(sphere->fifo_buffer == NULL) {
                        kfree(sphere);
                        BUG();
                        return -ENOMEM;
                }

                spin_lock_init(&sphere->lock);
                kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
                init_waitqueue_head(&sphere->wait);
                atomic_set(&sphere->fd_count, 0);
                atomic_set(&sphere->num_threads, 0);
                atomic_set(&sphere->num_readers, 0);
                atomic_set(&sphere->num_writers, 0);
                inode->i_private = sphere;
        } else {
                sphere = (replay_sphere_t *) inode->i_private;
        }

        atomic_inc(&sphere->fd_count);
        file->private_data = sphere;

	return 0;
}

static int replay_release(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere = file->private_data;

        if(inode->i_private != file->private_data)
                BUG();

        if(atomic_dec_return(&sphere->fd_count) < 0)
                BUG();

	return 0;
}

static int kfifo_has_data(replay_sphere_t *sphere) {
        int len, ret;
        len = kfifo_len(&sphere->fifo);

        spin_lock(&sphere->lock);
        ret = (len > 0) || (sphere->state == done);
        spin_unlock(&sphere->lock);

        return ret;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        int ret = 0;
        replay_sphere_t *sphere;
        int flen, bytesRead=0;

        sphere = (replay_sphere_t *) file->private_data;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }

        spin_lock(&sphere->lock);
        if((sphere->state == done) && (kfifo_len(&sphere->fifo) == 0)) {
                spin_unlock(&sphere->lock);
                return 0;
        } else if(sphere->state == replaying) {
                spin_unlock(&sphere->lock);
                return -EINVAL;
        }
        spin_unlock(&sphere->lock);

        if(atomic_inc_return(&sphere->num_readers) > 1)
                return -EINVAL;

        // We enforce mutual exclusion on all threads that are being
        // recorded when they access the kfifo that is in the sphere.
        // So as long as there is only one reader we can access kfifo
        // data without holding any locks
        ret = wait_event_interruptible(sphere->wait, kfifo_has_data(sphere));

        if(ret == -ERESTARTSYS) {
                atomic_dec(&sphere->num_readers);
                return ret;
        }

        flen = kfifo_len(&sphere->fifo);
        if(flen < count)
                count = flen;

        if(flen <= 0)
                BUG();

        ret = kfifo_to_user(&sphere->fifo, buf, count, &bytesRead);
        
        atomic_dec(&sphere->num_readers);

        if(ret)
                return ret;

        return bytesRead;
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
        replay_sphere_t *sphere;

        if(file->private_data == NULL)
                BUG();

        if(current->rtcb != NULL)
                BUG();

        sphere = (replay_sphere_t *) file->private_data;

        if(cmd == REPLAY_IOC_START_RECORDING) {
                // the process will call this on itself before
                // calling exec.  From this point on the process is being
                // traced
                printk(KERN_CRIT "starting recording on process %d\n", current->pid);

                spin_lock(&sphere->lock);
                if(sphere->state != idle) {
                        spin_unlock(&sphere->lock);
                        return -EINVAL;
                }
                sphere->state = recording;
                spin_unlock(&sphere->lock);

                replay_thread_create(current, sphere);

                if(atomic_read(&sphere->num_threads) != 1)
                        BUG();

        } else if(cmd == REPLAY_IOC_RESET_SPHERE) {
                spin_lock(&sphere->lock);
                if(atomic_read(&sphere->num_threads) > 0)
                        BUG();
                sphere->state = idle;
                sphere->next_thread_id = 1;
                if(kfifo_len(&sphere->fifo) > 0)
                    printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");
                kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
                spin_unlock(&sphere->lock);
        } else {
                BUG();
                return -EINVAL;
        }

        return 0;
}

static int __init replay_init(void) {
        int idx;
        struct device *dev;

        memset(&replay_fops, 0, sizeof(replay_fops));
        replay_fops.read = replay_read;
        replay_fops.open = replay_open;
        replay_fops.unlocked_ioctl = replay_ioctl;
        replay_fops.release = replay_release;
        replay_major = register_chrdev(0, "replay", &replay_fops);
        if(replay_major < 0) {
                printk("could not register replay char device\n");
                BUG();
        }

        replay_class = class_create(THIS_MODULE, "replay");
        if(IS_ERR(replay_class)) {
                printk(KERN_ERR "could not create replay class.\n");
                BUG();
        } else {
                printk(KERN_INFO "************* replay: version %s, Sam King, replay_major = %d\n", 
                       REPLAY_VERSION, replay_major);
                for(idx = 0; idx < NUM_REPLAY_MINOR; idx++) {
                        dev = device_create(replay_class, NULL, MKDEV(replay_major, idx), 
                                            NULL, "replay%d", idx);
                        if(IS_ERR(dev)) {
                                printk(KERN_CRIT "************* replay module could not create device\n");
                        } else {
                                printk(KERN_INFO "created replay driver replay%d\n", idx);
                        }
                }
        }

	return 0;
}

static void __exit replay_exit(void) {
        int idx;
        printk(KERN_INFO "exiting replay module\n");

        if(!IS_ERR(replay_class)) {
                for(idx = 0; idx < NUM_REPLAY_MINOR; idx++)
                        device_destroy(replay_class, MKDEV(replay_major, idx));
                class_destroy(replay_class);
        }

        if(replay_major >= 0) {
                unregister_chrdev(replay_major, "replay");
        }

        printk(KERN_INFO "done exiting replay module\n");
}

module_init(replay_init);
module_exit(replay_exit);

MODULE_AUTHOR("Sam King");
MODULE_DESCRIPTION("Provides control of replay hardware.");
MODULE_LICENSE("BSD");
MODULE_VERSION(REPLAY_VERSION);

/*********************************** Helpers for logging **************************************/

static void wake_readers(replay_sphere_t *sphere) {
        // we should be able to avoid these if there is no one 
        // waiting, but I am assuming that the wake up
        // handler handles this reasonable efficiently
        wake_up_interruptible(&sphere->wait);
}


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

        wake_readers(sphere);

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

        wake_readers(sphere);

        return 0;
}

static void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                          struct pt_regs *regs) {
        int ret;

        spin_lock(&sphere->lock);
        ret = record_header_locked(sphere, event, thread_id, regs);
        spin_unlock(&sphere->lock);

        if(ret)
                BUG();
}

/**********************************************************************************************/

/*********************************** Callbacks from kernel ************************************/
static void sanity_check(void) {
        if(current->rtcb == NULL)
                BUG();

        if(current->rtcb->sphere == NULL)
                BUG();
}

void replay_syscall_enter(struct pt_regs *regs) {        
        sanity_check();

        if(regs->orig_ax == __NR_execve)
                current->rtcb->wait_for_execve = 0;

        if(current->rtcb->wait_for_execve)
                return;

        record_header(current->rtcb->sphere, syscall_enter_event, 
                      current->rtcb->thread_id, regs);
}

void replay_syscall_exit(struct pt_regs *regs) {
        sanity_check();

        if(current->rtcb->wait_for_execve)
                return;

        record_header(current->rtcb->sphere, syscall_exit_event, 
                      current->rtcb->thread_id, regs);
}

void replay_thread_create(struct task_struct *tsk, replay_sphere_t *sphere) {
        rtcb_t *rtcb;
        int ret;
        struct pt_regs *regs = task_pt_regs(tsk);
        if(tsk->rtcb != NULL)
                BUG();

        set_ti_thread_flag(task_thread_info(tsk), TIF_RECORD_REPLAY);
        if(current == tsk)
                disable_TSC();
        set_ti_thread_flag(task_thread_info(tsk), TIF_NOTSC);

        rtcb = kmalloc(sizeof(rtcb_t), GFP_KERNEL);

        spin_lock(&sphere->lock);
        rtcb->sphere = sphere;
        rtcb->thread_id = sphere->next_thread_id++;
        rtcb->wait_for_execve = (rtcb->thread_id == 1) ? 1 : 0;
        tsk->rtcb = rtcb;

        atomic_inc(&rtcb->sphere->num_threads);

        ret = record_header_locked(rtcb->sphere, thread_create_event, 
                                   rtcb->thread_id, regs);
        spin_unlock(&sphere->lock);        

        if(ret)
                BUG();
}

void replay_thread_exit(struct pt_regs *regs) {
        rtcb_t *rtcb = current->rtcb;
        int num_threads, ret;

        sanity_check();

        current->rtcb = NULL;
        clear_thread_flag(TIF_RECORD_REPLAY);

        spin_lock(&rtcb->sphere->lock);
        ret = record_header_locked(rtcb->sphere, thread_exit_event, 
                                   rtcb->thread_id, regs);
        num_threads = atomic_dec_return(&rtcb->sphere->num_threads);
        if(num_threads == 0) {
                rtcb->sphere->state = done;
                wake_readers(rtcb->sphere);
        }
        spin_unlock(&rtcb->sphere->lock);

        if((num_threads < 0) || ret)
                BUG();

        kfree(rtcb);
}

void replay_switch_to(struct task_struct *prev_p, struct task_struct *next_p) {
        
}

int replay_general_protection(struct pt_regs *regs) {
        rtcb_t *rtcb = current->rtcb;
        uint16_t opcode;
        long low, high;

        sanity_check();

        if(copy_from_user(&opcode, (void *) regs->ip, sizeof(opcode)))
                return 0;

        // this code is for rdtsc emulation
        if(opcode != 0x310f)
                return 0;
        
        __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));

        regs->ax = low;
        regs->dx = high;
        regs->ip += 2;

        record_header(rtcb->sphere, instruction_event, rtcb->thread_id, regs);

        return 1;
}

void replay_copy_to_user(unsigned long to_addr, void *buf, int len) {
        replay_sphere_t *sphere;
        int ret;
        unsigned long flags;

        sanity_check();

        if(current->rtcb->wait_for_execve)
                BUG();

        sphere = current->rtcb->sphere;

        // check for kernel addresses and return if we get one
        if(to_addr > PAGE_OFFSET)
                return;

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
