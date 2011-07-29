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

#define NUM_REPLAY_MINOR 4

static struct class *replay_class = NULL;
static struct file_operations replay_fops;
static int replay_major = 0;
//DEFINE_MUTEX(replay_mutex);
static struct mutex replay_mutex;

#define REPLAY_VERSION	"0.3"


/******************************** Driver interface functions ***********************************/

static int replay_open(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere;

        mutex_lock(&replay_mutex);
        if(inode->i_private == NULL) {
                sphere = sphere_alloc();
                if(sphere == NULL) {
                        mutex_unlock(&replay_mutex);
                        return -ENOMEM;
                }
                inode->i_private = sphere;
        } else {
                sphere = (replay_sphere_t *) inode->i_private;
        }

        sphere_inc_fd(sphere);
        file->private_data = sphere;
        mutex_unlock(&replay_mutex);

	return 0;
}

static int replay_release(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere = file->private_data;

        if(inode->i_private != file->private_data)
                BUG();

        sphere_dec_fd(sphere);

	return 0;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        int ret = 0;
        replay_sphere_t *sphere;
        int bytesCopied=0;

        sphere = (replay_sphere_t *) file->private_data;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }
        if(current->rtcb != NULL) {
                BUG();
                return -EINVAL;
        }

        if(sphere_is_done_recording(sphere))
                return 0;

        if(atomic_inc_return(&sphere->num_readers) > 1)
                return -EINVAL;

        ret = sphere_wait_readers(sphere);
        if(ret) {
                atomic_dec(&sphere->num_readers);
                return ret;
        }
        bytesCopied = sphere_fifo_to_user(sphere, buf, count);
        
        atomic_dec(&sphere->num_readers);

        return bytesCopied;
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
        replay_sphere_t *sphere;
        int ret = 0;

        if(file->private_data == NULL)
                BUG();

        if(current->rtcb != NULL)
                BUG();

        sphere = (replay_sphere_t *) file->private_data;

        if(cmd == REPLAY_IOC_START_RECORDING) {
                // the process will call this on itself before
                // calling exec.  From this point on the process is being
                // traced
                ret = sphere_start_recording(sphere);
                rr_thread_create(current, sphere);
        } else if(cmd == REPLAY_IOC_RESET_SPHERE) {
                sphere_reset(sphere);
        } else {
                BUG();
                ret = -EINVAL;
        }

        return ret;
}

/**********************************************************************************************/

/********************************* Initialization functions ***********************************/

static int __init replay_init(void) {
        int idx;
        struct device *dev;

        mutex_init(&replay_mutex);

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

/**********************************************************************************************/

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

        sphere_wake_readers(sphere);

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

        sphere_wake_readers(sphere);

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

static void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len) {
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

/*********************************** Callbacks from kernel ************************************/
static void sanity_check(void) {
        if(current->rtcb == NULL)
                BUG();

        if(current->rtcb->sphere == NULL)
                BUG();

        if((current->rtcb->sphere->state != recording) && (current->rtcb->sphere->state != replaying))
                BUG();
}

void rr_syscall_enter(struct pt_regs *regs) {
        sanity_check();

        record_header(current->rtcb->sphere, syscall_enter_event, 
                      current->rtcb->thread_id, regs);
}

void rr_syscall_exit(struct pt_regs *regs) {
        sanity_check();

        record_header(current->rtcb->sphere, syscall_exit_event, 
                      current->rtcb->thread_id, regs);
}

void rr_send_signal(struct pt_regs *regs) {
        sanity_check();

        record_header(current->rtcb->sphere, signal_event, 
                      current->rtcb->thread_id, regs);
}

void rr_thread_create(struct task_struct *tsk, replay_sphere_t *sphere) {
        rtcb_t *rtcb;
        struct pt_regs *regs = task_pt_regs(tsk);
        if(tsk->rtcb != NULL)
                BUG();

        set_ti_thread_flag(task_thread_info(tsk), TIF_RECORD_REPLAY);
        if(current == tsk)
                disable_TSC();
        set_ti_thread_flag(task_thread_info(tsk), TIF_NOTSC);

        rtcb = kmalloc(sizeof(rtcb_t), GFP_KERNEL);

        rtcb->sphere = sphere;
        rtcb->thread_id = sphere_next_thread_id(sphere);
        tsk->rtcb = rtcb;

        record_header(rtcb->sphere, thread_create_event, rtcb->thread_id, regs);
}

void rr_thread_exit(struct pt_regs *regs) {
        rtcb_t *rtcb = current->rtcb;

        sanity_check();

        current->rtcb = NULL;
        clear_thread_flag(TIF_RECORD_REPLAY);

        
        record_header(rtcb->sphere, thread_exit_event, rtcb->thread_id, regs);
        
        sphere_thread_exit(rtcb->sphere);

        kfree(rtcb);
}

void rr_switch_to(struct task_struct *prev_p, struct task_struct *next_p) {
        
}

int rr_general_protection(struct pt_regs *regs) {
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

void rr_copy_to_user(unsigned long to_addr, void *buf, int len) {
        sanity_check();

        // check for kernel addresses and return if we get one
        if(to_addr > PAGE_OFFSET)
                return;

        record_copy_to_user(current->rtcb->sphere, to_addr, buf, len);
}

/**********************************************************************************************/
