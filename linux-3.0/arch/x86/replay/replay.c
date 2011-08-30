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
#include <asm/capo_perfct.h>

#define NUM_REPLAY_MINOR 4

static struct class *replay_class = NULL;
static struct file_operations replay_fops;
static int replay_major = 0;
static struct mutex replay_mutex;

typedef struct sphere_file_data {
        replay_sphere_t *sphere;
        int is_chunk_log_fd;
} sphere_fd_t;

#define REPLAY_VERSION	"0.3"


/*********************************** Callbacks from kernel ************************************/
static void sanity_check(struct task_struct *tsk) {
        if(tsk->rtcb == NULL)
                BUG();

        if(tsk->rtcb->sphere == NULL)
                BUG();

        if(!sphere_is_recording_replaying(tsk->rtcb->sphere))
                BUG();
}

static int get_signr(rtcb_t *rtcb) {
        int idx;
        uint64_t def_sig = rtcb->def_sig;

        for(idx = 0; idx < 64; idx++) {
                if(def_sig & (1<<idx)) {
                        rtcb->def_sig = (def_sig & ~(1<<idx));
                        return idx;
                }
        }

        BUG();
        return -1;       
}

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
static int check_for_end_of_chunk(rtcb_t *rtcb) {
        u32 inst_count;
        u64 perf_count;

        perf_count = perf_counter_read(rtcb->pevent);
        inst_count = perf_count - rtcb->perf_count;
        
        if((inst_count+15) >= rtcb->chunk->inst_count) {
                if(inst_count > rtcb->chunk->inst_count) {
                        printk(KERN_CRIT "went past by %u inst for %u chunk\n",
                               inst_count - rtcb->chunk->inst_count, rtcb->chunk->inst_count);
                } else if(inst_count < rtcb->chunk->inst_count) {
                        printk(KERN_CRIT "stil had %u inst to go\n",
                               rtcb->chunk->inst_count - inst_count);
                }
                
#ifdef DEBUG_BREAKPOINTS
                {
                        int ret;
                        ret = access_process_vm(current, rtcb->chunk->ip, &(rtcb->saved_inst), 1, 1);
                        BUG_ON(ret != 1);
                }
#endif                

                
                rtcb->perf_count = perf_count;
                // assuming the last chunk is from a syscall exit, the the thread exit call
                // end the chunk
                if(rtcb->chunk->ip != 1) {
                        sphere_chunk_end(current);
                        sphere_chunk_begin(current);
                        sphere_set_breakpoint(current->rtcb->chunk->ip);
                }

                return 1;
        }

        return 0;
}
#endif

static void rr_syscall_enter(struct pt_regs *regs) {
        rtcb_t *rtcb;
 
        sanity_check(current);

        rtcb = current->rtcb;

        if(!sphere_has_first_execve(rtcb->sphere))
                return;

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        if(rtcb->chunk) {
                long dr7, dr0;
                get_debugreg(dr7, 7);
                if((dr7 & 0xf) != 0x1) {
                        get_debugreg(dr0, 0);
                        printk(KERN_CRIT "############# resetting tid %u system call %ld chunkip = 0x%p dr7 0x%08lx, dr0 0x%08lx\n", 
                               rtcb->thread_id, regs->orig_ax, (void *) rtcb->chunk->ip, dr7, dr0);
                        sphere_set_breakpoint(rtcb->chunk->ip);
                }
        }
#endif

        // we clear send_sig here because we use it to prevent recording spurious
        // syscall_exit events that happen when we send signals on the syscall
        // return path
        if(rtcb->send_sig)
                rtcb->send_sig = 0;

        if(sphere_is_recording(rtcb->sphere)) {
                record_header(rtcb->sphere, syscall_enter_event, rtcb->thread_id, regs);
        } else {
                replay_event(rtcb->sphere, syscall_enter_event, rtcb->thread_id, regs);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
                if(sphere_is_chunk_replaying(rtcb->sphere)) {
                        if(rtcb->chunk->ip == regs->ip) {
                                check_for_end_of_chunk(rtcb);
                        }
                }
#endif

        }
}

/*
static void print_stack(struct pt_regs *regs) {
        unsigned long arg;
        unsigned long start;

        for(start = regs->sp; start < STACK_TOP; start += sizeof(arg)) {
                if(copy_from_user(&arg, (void __user *) start, sizeof(arg)) == 0)
                        printk(KERN_CRIT "%p: 0x%08lx\n", (void *) start, arg);
        }
}
*/

static void rr_send_signal(int signo) {
        unsigned long syscallno;
        struct pt_regs *regs;
        sanity_check(current);

        regs = task_pt_regs(current);

        if(sphere_is_recording(current->rtcb->sphere)) {
                printk(KERN_CRIT "sending signal, orig ax = %ld\n", regs_syscallno(regs));
                syscallno = regs_syscallno(regs);
                set_regs_syscallno(regs, signo);
                record_header(current->rtcb->sphere, signal_event, 
                              current->rtcb->thread_id, regs);
                set_regs_syscallno(regs, syscallno);
        } else {
                BUG();
        }
}


static void rr_syscall_exit(struct pt_regs *regs) {
        uint64_t mask = 1;
        int signr;
        rtcb_t *rtcb;

        sanity_check(current);

        rtcb = current->rtcb;

        sphere_check_first_execve(rtcb->sphere, regs);
        if(!sphere_has_first_execve(rtcb->sphere))
                return;

        // This will skip syscall_exit calls in two situations.  First, when the
        // kernel restarts a system call (as a result of a signal).  Second, on 
        // an sigreturn system call.  Because we re-execute the sigreturn
        // system call then it should be ok to do this.
        if(((long) regs_syscallno(regs)) < 0)
                return;

        // the logic here deals with signal delivery and the interactions with
        // the syscall_exit callback mechanism.  The way it works is that the
        // kernel will call this callback after a system call and then after it
        // returns the kernel checks for pending signals.  If there are any it
        // will deal with them and call the syscall exit handler again.  Our
        // goal is to log the signal event before the syscall exit event, and
        // to log only one syscall exit event.
        //
        // To deal with this we don't log syscall exits when there is a
        // pending signal because we know that this callback will be called
        // again.  If the def_sig var is set, the do_signal function set it
        // before squashing the signal, so we log the syscall exit and signal
        // here, then we set send_sig.  Send_sig tells do_signal to actually
        // deliver the signal, and it is not cleared until the next syscall
        // enter to prevent duplicate logging of syscall exits.
        //
        // the only thing I am unsure about is if there is a race condition
        // where you can recieve a pending signal after logging the system call
        // exit but before checking for any pending signals.
        if(sphere_is_recording(rtcb->sphere)) {
                if(rtcb->def_sig) {
                        signr = get_signr(rtcb);
                        mask <<= signr;
                        rtcb->def_sig &= ~mask;
                        BUG_ON(rtcb->send_sig != 0);
                        rtcb->send_sig |= mask;
                        rr_send_signal(signr);
                        send_sig(signr, current, 1);
                        record_header(rtcb->sphere, syscall_exit_event, rtcb->thread_id, regs);
                } else if((rtcb->send_sig == 0) && !test_thread_flag(TIF_SIGPENDING)) {
                        record_header(rtcb->sphere, syscall_exit_event, rtcb->thread_id, regs);
                }
        } else {
                if(rtcb->send_sig == 0)
                        replay_event(rtcb->sphere, syscall_exit_event, rtcb->thread_id, regs);
        }
}

static int rr_deliver_signal(int signr, struct pt_regs *regs) {
        int async = 0;
        uint64_t mask;

        if(signr < 0)
                return signr;

        switch(signr) {
                case SIGTERM: 
                case SIGHUP: 
                case SIGINT: 
                case SIGQUIT: 
                case SIGKILL: 
                case SIGUSR1: 
                case SIGUSR2: 
                case SIGALRM: 
                case SIGVTALRM:
                case SIGPROF:
                case SIGCHLD:
                case SIGCONT:
                case SIGSTOP:
                case SIGTSTP:
                case SIGTTIN:
                case SIGTTOU:
                case SIGIO: // also SIGPOLL -> 29
                case SIGURG:
                case SIGPIPE:
                case SIGSTKFLT:
                case SIGPWR:
                case SIGSYS:
                case SIGXCPU: 
                case SIGXFSZ:
                case SIGWINCH:
                        async = 1;
                        break;
        }

        // check if this is an async signal
        if(!async)
                return signr;

        BUG_ON(signr >= SIGRTMAX);        
        mask = 1;
        mask <<= signr;
        if((current->rtcb->send_sig & mask) != 0) {
                printk(KERN_CRIT "do_signal sending signal %d\n", signr);
                return signr;
        } else {
                if(sphere_is_recording(current->rtcb->sphere))
                        current->rtcb->def_sig |= mask;
                printk(KERN_CRIT "defer signal\n");
                return -1;
        }

        return signr;
}

static void rr_thread_create(struct task_struct *tsk, replay_sphere_t *sphere) {
        rtcb_t *rtcb;
        struct pt_regs *regs = task_pt_regs(tsk);
        
        if(tsk->rtcb != NULL)
                BUG();

        if(current == tsk)
                disable_TSC();
        set_ti_thread_flag(task_thread_info(tsk), TIF_NOTSC);

        rtcb = kmalloc(sizeof(rtcb_t), GFP_KERNEL);
        memset(rtcb, 0, sizeof(rtcb_t));

        rtcb->sphere = sphere;
        rtcb->thread_id = sphere_thread_create(rtcb->sphere, regs);
        rtcb->def_sig = 0;
        rtcb->send_sig = 0;
        rtcb->chunk = NULL;
        rtcb->needs_chunk_start = current != tsk;
        rtcb->perf_count = 0;
        rtcb->pevent = NULL;
        tsk->rtcb = rtcb;
        set_ti_thread_flag(task_thread_info(tsk), TIF_RECORD_REPLAY);
}

static void rr_thread_exit(struct pt_regs *regs) {

        rtcb_t *rtcb = current->rtcb;
        sanity_check(current);

        if(sphere_is_chunk_replaying(rtcb->sphere)) {
                sphere_chunk_end(current);
        }

        current->rtcb = NULL;
        clear_thread_flag(TIF_RECORD_REPLAY);
        sphere_thread_exit(rtcb, regs);

        //BUG_ON(rtcb->chunk != NULL);

        kfree(rtcb);
}

static void rr_switch_from(struct task_struct *prev_p) {
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        if(prev_p->rtcb != NULL) {
                long dr7;
                chunk_t *chunk = prev_p->rtcb->chunk;

                if(chunk != NULL) {
                        get_debugreg(dr7, 7);
                        if(((dr7 & 0xf) != 0x1) && !prev_p->rtcb->needs_chunk_start) {
                                printk("BUG!!!!!!!! breakpoint not set\n");
                        }
                        sphere_set_breakpoint(0);
                }
        }
#endif
}

static void rr_switch_to(struct task_struct *next_p) {

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        if(next_p->rtcb != NULL) {
                replay_sphere_t *sphere = next_p->rtcb->sphere;
                chunk_t *chunk = next_p->rtcb->chunk;
                BUG_ON(sphere == NULL);
                if(sphere_is_chunk_replaying(sphere) && (chunk != NULL)) {
                        task_pt_regs(next_p)->flags &= ~X86_EFLAGS_RF;
                        sphere_set_breakpoint(chunk->ip);
                }
        }
#endif
}

static int rr_general_protection(struct pt_regs *regs) {
        rtcb_t *rtcb = current->rtcb;
        uint16_t opcode;
        long low, high;

        sanity_check(current);

        if(copy_from_user(&opcode, (void *) regs_ip(regs), sizeof(opcode)))
                return 0;

        // this code is for rdtsc emulation
        if(opcode != 0x310f)
                return 0;
        if(sphere_is_recording(rtcb->sphere)) {
                __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
                
                regs->ax = low;
                regs->dx = high;
                regs->ip += 2;
                
                record_header(rtcb->sphere, instruction_event, rtcb->thread_id, regs);
        } else {                
                replay_event(rtcb->sphere, instruction_event, rtcb->thread_id, regs);
                // make sure we can trap if the next instruction is a chunk boundary
                regs->flags &= ~X86_EFLAGS_RF;
        }

        return 1;
}

static void rr_copy_to_user(unsigned long to_addr, void *buf, int len) {
        sanity_check(current);
        
        if(!sphere_has_first_execve(current->rtcb->sphere))
                return;

        // check for kernel addresses and return if we get one
        if(to_addr > PAGE_OFFSET)
                return;

        if(sphere_is_recording(current->rtcb->sphere)) {
                record_copy_to_user(current->rtcb->sphere, to_addr, buf, len);
        } else {
                //BUG();
        }
}
EXPORT_SYMBOL_GPL(rr_copy_to_user);

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT

static int rr_do_debug(struct pt_regs *regs, long error_code) {
        rtcb_t *rtcb = current->rtcb;
        unsigned long dr6;
        int step = 0;

        if(rtcb == NULL)
                return 0;

        if(rtcb->chunk == NULL)
                return 0;
        get_debugreg(dr6, 6);

        BUG_ON(!user_mode(regs));

        if(dr6 & (1<<14)) {
                printk(KERN_CRIT "single step ip = 0x%08lx\n", regs->ip);
                return 1;
        }

        if(dr6 & 1) {
                BUG_ON(regs->ip != rtcb->chunk->ip);

                printk(KERN_CRIT "****** breakpoint (tid=%u)\n", 
                       rtcb->thread_id);

                if(check_for_end_of_chunk(rtcb)) {
                        if(rtcb->chunk->ip == 0xffffffffff600115) {
                                printk(KERN_CRIT "enabling single stepping\n");
                                user_enable_single_step(current);
                                regs->flags |= X86_EFLAGS_TF;
                                regs->flags &= ~X86_EFLAGS_RF;
                        }
                        // this chunk will refer to the new chunk that just got loaded
                        if((regs->ip == rtcb->chunk->ip) && (rtcb->chunk->inst_count > 0)) {
                                step = 1;
                        }
                } else {
                        step = 1;
                }

                if(step) {
                        // setting the RF here will make sure that the
                        // software can execute the instruction pointed
                        // to by the breakpoint without causing a breakpoint
                        // exception
                        regs->flags |= X86_EFLAGS_RF;
#ifdef DEBUG_BREAKPOINTS
                        {
                                int ret;
                                ret = access_process_vm(current, regs->ip, &(rtcb->saved_inst), 1, 1);
                                BUG_ON(ret != 1);
                        }
#endif
                }
        } else {
                BUG();
        }

        set_debugreg(0, 6);

        return 1;
}
#endif

/**********************************************************************************************/


/******************************** Driver interface functions ***********************************/

static int replay_open(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere;
        sphere_fd_t *sfd;

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
        sfd = kmalloc(sizeof(sphere_fd_t), GFP_KERNEL);
        if(sfd == NULL) {
                mutex_unlock(&replay_mutex);
                return -ENOMEM;
        }
        sfd->sphere = sphere;
        sfd->is_chunk_log_fd = 0;
        file->private_data = sfd;
        mutex_unlock(&replay_mutex);

	return 0;
}

static int replay_release(struct inode *inode, struct file *file) {
        sphere_fd_t *sfd = file->private_data;
        replay_sphere_t *sphere;

        sphere = sfd->sphere;

        if(inode->i_private != sphere)
                BUG();

        sphere_dec_fd(sphere);

        kfree(sfd);
        file->private_data = NULL;

	return 0;
}

static ssize_t replay_write(struct file *file, const char __user *buf, size_t count,
                            loff_t *f_pos) {
        sphere_fd_t *sfd = file->private_data;
        int ret;
        replay_sphere_t *sphere;

        sphere = sfd->sphere;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }
        if(current->rtcb != NULL) {
                BUG();
                return -EINVAL;
        }

        if(sfd->is_chunk_log_fd) {
                ret = sphere_chunk_fifo_from_user(sphere, buf, count);
        } else {
                ret = sphere_fifo_from_user(sphere, buf, count);
        }

        return ret;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        sphere_fd_t *sfd = file->private_data;
        replay_sphere_t *sphere;

        sphere = sfd->sphere;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }
        if(current->rtcb != NULL) {
                BUG();
                return -EINVAL;
        }
        
        return sphere_fifo_to_user(sphere, buf, count);
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
        sphere_fd_t *sfd = file->private_data;
        replay_sphere_t *sphere;
        int ret = 0;

        if(file->private_data == NULL)
                BUG();

        BUG_ON(current->rtcb != NULL);

        sphere = sfd->sphere;

        if(cmd == REPLAY_IOC_START_RECORDING) {
                // the process will call this on itself before
                // calling exec.  From this point on the process is being
                // traced
                ret = sphere_start_recording(sphere);
                rr_thread_create(current, sphere);
        } else if(cmd == REPLAY_IOC_START_REPLAYING) {
                ret = sphere_start_replaying(sphere);
                rr_thread_create(current, sphere);
        } else if(cmd == REPLAY_IOC_RESET_SPHERE) {
                sphere_reset(sphere);
        } else if(cmd == REPLAY_IOC_START_CHUNKING) {
                printk(KERN_CRIT "ioctl start chunking %ld\n", sys_getpid());
                ret = sphere_start_replaying(sphere);
                ret = sphere_start_chunking(sphere);
                rr_thread_create(current, sphere);
        } else if(cmd == REPLAY_IOC_SET_CHUNK_LOG_FD) {
                sfd->is_chunk_log_fd = 1;
        } else {
                BUG();
                ret = -EINVAL;
        }

        return ret;
}

/**********************************************************************************************/


/********************************* Initialization functions ***********************************/

void set_rr_syscall_enter_cb(rr_syscall_enter_cb_t cb);
void set_rr_syscall_exit_cb(rr_syscall_exit_cb_t cb);
void set_rr_thread_create_cb(rr_thread_create_cb_t cb);
void set_rr_thread_exit_cb(rr_thread_exit_cb_t cb);
void set_rr_switch_from_cb(rr_switch_from_cb_t cb);
void set_rr_switch_to_cb(rr_switch_to_cb_t cb);
void set_rr_general_protection_cb(rr_general_protection_cb_t cb);
void set_rr_copy_to_user_cb(rr_copy_to_user_cb_t cb);
void set_rr_deliver_signal_cb(rr_deliver_signal_cb_t cb);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
void set_rr_do_debug_cb(rr_do_debug_cb_t cb);
#endif

static int __init replay_init(void) {
        int idx;
        struct device *dev;

        mutex_init(&replay_mutex);

        memset(&replay_fops, 0, sizeof(replay_fops));
        replay_fops.read = replay_read;
        replay_fops.write = replay_write;
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

        // kernel call-backs
        set_rr_syscall_enter_cb(rr_syscall_enter);
        set_rr_syscall_exit_cb(rr_syscall_exit);
        set_rr_thread_create_cb(rr_thread_create);
        set_rr_thread_exit_cb(rr_thread_exit);
        set_rr_switch_from_cb(rr_switch_from);
        set_rr_switch_to_cb(rr_switch_to);
        set_rr_general_protection_cb(rr_general_protection);
        set_rr_copy_to_user_cb(rr_copy_to_user);
        set_rr_deliver_signal_cb(rr_deliver_signal);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        set_rr_do_debug_cb(rr_do_debug);
#endif

    	return 0;
}

static void __exit replay_exit(void) {
        int idx;
        printk(KERN_INFO "exiting replay module\n");

        // kernel call-backs
        set_rr_syscall_enter_cb(NULL);
        set_rr_syscall_exit_cb(NULL);
        set_rr_thread_create_cb(NULL);
        set_rr_thread_exit_cb(NULL);
        set_rr_switch_from_cb(NULL);
        set_rr_switch_to_cb(NULL);
        set_rr_general_protection_cb(NULL);
        set_rr_copy_to_user_cb(NULL);
        set_rr_deliver_signal_cb(NULL);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        set_rr_do_debug_cb(NULL);
#endif

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


/************* Performance Monitoring Overflow Interrupt Handler ******************************/
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
void capo_overflow_handler(struct perf_event * event, int unused, struct
                perf_sample_data * data, struct pt_regs *regs) {

}
#endif
/**********************************************************************************************/

