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
#include <linux/syscalls.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <trace/syscall.h>
#include <trace/events/syscalls.h>

#include <asm/replay.h>
#include <asm/capo_perfct.h>
#include <asm/hw_breakpoint.h>
#include <asm/debugreg.h>

#ifdef CONFIG_MRR
#include "mrr_if.h"
#endif
#include <asm/mrr/simics_if.h>

#define LOG_BUFFER_SIZE (8*1024*1024)
#define PRINT_DEBUG 0

static void replay_event_locked(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                                struct pt_regs *regs);
static int record_header_locked(replay_sphere_t *sphere, replay_event_t event, 
                                uint32_t thread_id, struct pt_regs *regs);
static void sphere_chunk_begin_locked(replay_sphere_t *sphere, rtcb_t *rtcb);
static void sphere_chunk_end_locked(struct task_struct *tsk);


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


        BUG_ON(current->rtcb != NULL);
        BUG_ON(sphere->has_fifo_reader);

        if(sphere_is_done_recording(sphere))
                return 0;

        while(!sphere_has_data(sphere))
                cond_wait(&sphere->queue_empty_cond, &sphere->mutex);

        flen = kfifo_len(&sphere->fifo);
        BUG_ON(flen < 0);
        if(flen == 0) {
                BUG_ON(atomic_read(&sphere->state) != done);
                return 0;
        }

        if(flen < count)
                count = flen;

        sphere->has_fifo_reader = 1;
        mutex_unlock(&sphere->mutex);

        ret = kfifo_to_user(&sphere->fifo, buf, count, &bytesRead);

        mutex_lock(&sphere->mutex);
        sphere->has_fifo_reader = 0;

        // don't worry about signalling anyone, we assume that rthreads don't block
        // when writing to the queue

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesRead;
}

static int sphere_fifo_from_user_ll(replay_sphere_t *sphere, const char __user *buf, size_t count, 
                                    struct kfifo *fifo, cond_t *full_cond, cond_t *next_rec_cond,
                                    int *writer) {
        int ret;
        int bytesWritten=0;
        int favail;
        replay_state_t state;

        BUG_ON(*writer);

        while(kfifo_is_full(fifo))
                cond_wait(full_cond, &sphere->mutex);

        if(kfifo_is_full(fifo))
                BUG();

        state = atomic_read(&sphere->state);
        BUG_ON((state != replaying) && (state != idle));
        
        favail = kfifo_avail(fifo);

        if(favail < count)
                count = favail;

        // the fifo to/from user calls can sleep, make sure we give up lock.
        *writer = 1;
        mutex_unlock(&sphere->mutex);

        ret = kfifo_from_user(fifo, buf, count, &bytesWritten);

        mutex_lock(&sphere->mutex);
        *writer = 0;
        cond_broadcast(next_rec_cond);

        // it might return -EFAULT, which we will pass back
        if(ret)
                return ret;

        return bytesWritten;
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

        if(PRINT_DEBUG) {
                printk(KERN_CRIT "thread_id = %u\n", thread_id);
                if((event == syscall_enter_event) || (event == syscall_exit_event)) {
                        printk(KERN_CRIT "syscall event %u, orig_ax = %lu\n", event, regs_syscallno(regs));
                } else {
                        printk(KERN_CRIT "event %u\n", event);
                }
        }

#ifdef CONFIG_MRR
        // cut the chunk on all recorded events, if any,
        // to avoid deadlocks between chunks log and input log
        mrr_terminate_chunk();
#endif

        ret = kfifo_in(&sphere->fifo, &type, sizeof(type));
        if(ret != sizeof(type)) return -1;
        ret = kfifo_in(&sphere->fifo, &thread_id, sizeof(thread_id));
        if(ret != sizeof(thread_id)) return -1;
        ret = kfifo_in(&sphere->fifo, regs, sizeof(*regs));
        if(ret != sizeof(*regs)) return -1;

        cond_broadcast(&sphere->queue_empty_cond);

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
        
        cond_broadcast(&sphere->queue_empty_cond);

        return 0;
}

/**********************************************************************************************/

/********************************* Helpers for replaying **************************************/


static int is_next_log(replay_sphere_t *sphere, uint32_t thread_id) {
        int len, ret;

        // if someone is in the middle of processing a copy to
        // user buffer, just exit immediately because the data on the fifo
        // will not be a header, it will be copy to user data
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
                        cond_broadcast(&sphere->queue_full_cond);
                }
        }

        if(sphere->header != NULL) {
                return (sphere->header->thread_id == thread_id);
        }

        return 0;
}

static replay_header_t *replay_wait_for_log(replay_sphere_t *sphere, uint32_t thread_id) {
        replay_header_t *header;

        while(!is_next_log(sphere, thread_id)) {
                cond_wait(&sphere->next_record_cond, &sphere->mutex);
        }

        if((sphere->header == NULL) || (sphere->header->thread_id != thread_id))
                BUG();
        header = sphere->header;
        // make sure to set the ctu_buf value before setting the sphere header back to NULL
        // this prevents any other threads from accesing the fifo even though the header is
        // NULL
        if(header->type == copy_to_user_event)
                sphere->fifo_head_ctu_buf = 1;
        sphere->header = NULL;

        return header;
}

static int kfifo_has_ctu_header(replay_sphere_t *sphere) {
        return kfifo_len(&sphere->fifo) >= (sizeof(uint64_t)+sizeof(uint32_t));
}

static void replay_copy_to_user(replay_sphere_t *sphere, int make_copy) {
        uint64_t to_addr=0;
        uint32_t i, idx, ctu_len=0;
        int ret, bytesWritten, len, cret;
        unsigned char c, ref;        

        while(!kfifo_has_ctu_header(sphere))
                cond_wait(&sphere->next_record_cond, &sphere->mutex);
        
        ret = kfifo_out(&sphere->fifo, &to_addr, sizeof(to_addr));
        if(ret != sizeof(to_addr)) BUG();
        ret = kfifo_out(&sphere->fifo, &ctu_len, sizeof(ctu_len));
        if(ret != sizeof(ctu_len)) BUG();

        cond_broadcast(&sphere->queue_full_cond);

        idx = 0;
        while(idx < ctu_len) {
                while(kfifo_len(&sphere->fifo) == 0)
                        cond_wait(&sphere->next_record_cond, &sphere->mutex);
                
                len = kfifo_len(&sphere->fifo);
                if(len > (ctu_len-idx))
                        len = ctu_len-idx;
                if(make_copy) {
                        // this is for an emulated system call, we need to replay
                        // the copy to user calls to emulate it properly
                        ret = kfifo_to_user(&sphere->fifo, (void __user *) ((long) (to_addr+idx)), len, 
                                            &bytesWritten);
                        if(ret || (len != bytesWritten)) BUG();
                } else {
                        // we are re-executing so squash the copy to user logs
                        bytesWritten = len;
                        // XXX FIXME we should put something here to check and make 
                        // sure the values are the same
                        for(i = 0; i < len; i++) {
                                cret = copy_from_user(&ref, (void *) ((long) (to_addr+i)), sizeof(ref));
                                ret = kfifo_out(&sphere->fifo, &c, sizeof(c));
                                if(ret != sizeof(c)) BUG();
                                if(c != ref) {
                                        printk(KERN_CRIT "copy_to_user bug at addr %p %d %d %d %d",
                                               (void *) ((long) (to_addr+i)), i, c, ref, cret);
                                        BUG();
                                }
                        }
                }
                idx += bytesWritten;
                cond_broadcast(&sphere->queue_full_cond);
        }

        sphere->fifo_head_ctu_buf = 0;

}

static int reexecute_syscall(struct pt_regs *regs) {
        // this is for the mmap optimization, for dlls we assume that they exist on the 
        // system that is replaying and that opening an existing file with O_RDONLY will
        // not affect it
        if(regs_syscallno(regs) == __NR_open)
                return ((regs_second(regs) & O_ACCMODE) == O_RDONLY);

        // this is used to detect shared memory threads, something we
        // don't handle yet
        if((regs_syscallno(regs) == __NR_clone) && !sphere_is_chunk_replaying(current->rtcb->sphere))
                BUG_ON((regs_first(regs) & CLONE_VM) == CLONE_VM);

        switch (regs_syscallno(regs)) {

#ifdef CONFIG_X86_64
        case __NR_arch_prctl:
#endif
        case __NR_execve: case __NR_brk:
        case __NR_exit_group: case __NR_munmap: case __NR_mmap: 
        case __NR_mprotect: case __NR_exit: case __NR_mlock:
        case __NR_munlock: case __NR_mlockall: case __NR_munlockall:

        case __NR_clone: case __NR_fork:

        case __NR_rt_sigaction: case __NR_rt_sigprocmask: case __NR_rt_sigreturn:
        case __NR_sigaltstack:
                return 1;

#ifdef CONFIG_X86_64
        case __NR_shmget: case __NR_shmat: case __NR_shmctl:  case __NR_shmdt:
#endif
        case __NR_ptrace: case __NR_modify_ldt: case __NR_reboot: case __NR_iopl:
        case __NR_vfork: case __NR_ioperm: case __NR_setsid:
                // we don't know how to support these yet
                printk(KERN_CRIT "unhandled syscall %lu\n", regs_syscallno(regs));
                BUG();
                return 1;
        }

        return 0;
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
        check_reg("syscallno", regs_syscallno(regs), regs_syscallno(stored_regs));
        check_reg("ip", regs_ip(regs), regs_ip(stored_regs));
        check_reg("sp", regs_sp(regs), regs_sp(stored_regs));
        check_reg("return", regs_return(regs), regs_return(stored_regs));
        check_reg("first", regs_first(regs), regs_first(stored_regs));
        check_reg("second", regs_second(regs), regs_second(stored_regs));
        //check_reg("third", regs_third(regs), regs_third(stored_regs));
        //check_reg("fourth", regs_fourth(regs), regs_fourth(stored_regs));
        //check_reg("fifth", regs_fifth(regs), regs_fifth(stored_regs));
        //check_reg("sixth", regs_sixth(regs), regs_sixth(stored_regs));
}

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
void sphere_set_breakpoint(unsigned long ip) {
        if((ip < 0xffffffffff600000) || (ip >= 0xffffffffff601000))
                BUG_ON(ip >= PAGE_OFFSET);

        // XX FIXME make sure that this debug regiter is not being used and that we aren't
        // trampling someone else's use of the other debug registers


        if(ip == 0) {
                set_debugreg(0, 7);
                set_debugreg(0, 0);
        } else {
                set_debugreg(ip, 0);
                set_debugreg(0x1, 7);                
#ifdef DEBUG_BREAKPOINTS
                {
                        unsigned char inst;
                        int ret;
                        
                        ret = access_process_vm(current, ip, &inst, 1, 0);
                        if(ret == 1) {
                                if(inst != 0xcc)
                                        current->rtcb->saved_inst = inst;
                                inst = 0xcc;
                                ret = access_process_vm(current, ip, &inst, 1, 1);
                                BUG_ON(ret != 1);
                        }
                }
#endif
        }
}
#endif

static void handle_mmap_optimization(struct pt_regs *regs, replay_header_t *header) {
        BUG_ON(header->type != syscall_exit_event);        

        if(regs_syscallno(regs) == __NR_open) {
                // we let an open through, fixup the fd
                if(regs_return(regs) != regs_return(&header->regs)) {
                        if((regs_return(regs) < 0) && (regs_return(&header->regs) >= 0)) {
                                // worked during recording, but not during replay, switch to
                                // replaying this syscall and hope it is not for an mmap
                        } else if((regs_return(regs) >= 0) && (regs_return(&header->regs) < 0)) {
                                // failed during recording, but not now, clean up
                                sys_close(regs_return(regs));
                        } else if(regs_return(regs) != regs_return(&header->regs)) {
                                // opened, but with different fd, fixup needed
                                BUG_ON((regs_return(regs) < 0) || (regs_return(&header->regs) < 0));
                                sys_dup2(regs_return(regs), regs_return(&header->regs));
                                sys_close(regs_return(regs));
                        } else {
                                BUG_ON(regs_return(regs) != regs_return(&header->regs));
                        }
                        set_regs_return(regs, regs_return(&header->regs));
                }
                check_regs(regs, &header->regs);
        } else if(regs_syscallno(&header->regs) == __NR_close) {
                // this is for our mmap optimzation
                sys_close(regs_first(regs));
                *regs = header->regs;
        } else if((regs_syscallno(&header->regs) == __NR_dup) ||
                  (regs_syscallno(&header->regs) == __NR_dup2) ||
                  (regs_syscallno(&header->regs) == __NR_dup3)) {
                // XXX FIXME
                // we need to re-execute these if one of the
                // fds is from our previous open
        }
}

static void replay_handle_event(replay_sphere_t *sphere, replay_event_t event, 
                                struct pt_regs *regs, replay_header_t *header) {

        if(header->type == syscall_enter_event) {
                if(sphere->replay_first_execve)
                        check_regs(regs, &header->regs);
                if(!reexecute_syscall(regs))
                        set_regs_syscallno(regs, __NR_getpid);
        } else if(header->type == syscall_exit_event) {                
                handle_mmap_optimization(regs, header);

                // fixup the return value for clone, fork, and vfork
                if((regs_syscallno(regs) == __NR_clone) ||
                   (regs_syscallno(regs) == __NR_fork) ||
                   (regs_syscallno(regs) == __NR_vfork))
                        set_regs_return(regs, regs_return(&header->regs));

                if(regs_syscallno(regs) == __NR_getpid) {
                        // emulate system call by copying registers
                        *regs = header->regs;
                } else if(sphere->replay_first_execve) {
                        // re-executed syscall, check regs to make sure
                        // everything is on track after first execve
                        check_regs(regs, &header->regs);
                }

        } else if(header->type == instruction_event) {
                // This is only for rdtsc for now, we can probably copy the entire regs struct
                *regs = header->regs;
        }
}

static void replay_event_locked(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                                struct pt_regs *regs) {
        
        replay_header_t *header;
        int exit_loop = 0;

        if(PRINT_DEBUG) {
                printk(KERN_CRIT "thread_id = %u\n", thread_id);
                if((event == syscall_enter_event) || (event == syscall_exit_event)) {
                        printk(KERN_CRIT "syscall event (tid=%u) %u, orig_ax = %lu\n", thread_id, event, regs_syscallno(regs));
                } else {
                        printk(KERN_CRIT "event %u\n", event);
                }
        }

        do {

        #ifdef CONFIG_MRR
                // to avoid a deadlock sitatution between capo log and 
                // chunks log, check the current number of executed 
                // instructions and end the chunk if done
                if ((NULL != sphere) && sphere_is_chunk_replaying(sphere) && (NULL != current->rtcb) && (NULL != current->rtcb->chunk)) {
                        mrr_virtualize_chunk_size(current);
                        if (0 == current->rtcb->chunk->inst_count)
                            sphere_chunk_end_locked(current);
                }
        #endif

                my_magic_message_int("waiting for next log entry", thread_id);
                my_magic_message_int("log entry type is", event);
                if ((NULL != current->rtcb) && (NULL != current->rtcb->chunk))
                    my_magic_message_int("remaining inst_count is", current->rtcb->chunk->inst_count);

                header = replay_wait_for_log(sphere, thread_id);
                my_magic_message_int("got the next log entry", thread_id);
                my_magic_message_int("entry type is", header->type);

                if(header == NULL)
                        BUG();
                
                if(PRINT_DEBUG) printk(KERN_CRIT "thread_id %d got event %d\n", thread_id, header->type);

                // on emulated system calls we will get a number of copy to user
                // log entries between the system call enter and exit events
                // so we loop here on copy to user events until we finally
                // get to the system call exit event
                if(header->type == copy_to_user_event) {
                        exit_loop = 0;
                        // the event==syscall_exit_event condition is to squash copy to user
                        // calls that happen on behalf of a signal (and happen after a syscall exit                        
                        // instead of before like is the case with system calls)
                        //
                        // also, we replay copy to user for clone system calls because we re-execute
                        // them but the kernel pushes some pid information into userspace that will
                        // be different whey replaying
                        replay_copy_to_user(sphere, ((regs_syscallno(regs) == __NR_getpid) || (regs_syscallno(regs) == __NR_clone)) 
                                                    && (event == syscall_exit_event));
                        if (PRINT_DEBUG) printk("done replaying copy_to_user\n");
                } else if(header->type == signal_event) {
                        exit_loop = 0;
                        if (PRINT_DEBUG) printk(KERN_CRIT "sending signal %ld\n", regs_syscallno(&header->regs));
                        current->rtcb->send_sig |= 1<<regs_syscallno(&header->regs);
                        send_sig(regs_syscallno(&header->regs), current, 1);
                } else {
                        exit_loop = 1;
                        if(header->type != event) {
                                printk(KERN_CRIT "header->type = %u, type = %u, header->orig_ax %lu, regs->orig_ax = %lu\n", 
                                       header->type, event, regs_syscallno(&header->regs), regs_syscallno(regs));
                                BUG();
                        }
                }

                replay_handle_event(sphere, event, regs, header);

                kfree(header);
                header = NULL;

                my_magic_message_int("signaling next_record_cond", thread_id);
                cond_broadcast(&sphere->next_record_cond);

        } while(!exit_loop);

        if(PRINT_DEBUG) printk(KERN_CRIT "thread_id %d done with event\n", thread_id);
}


/*
 * Do not put any chunk-counting stuff in this function.
 * It is meant to be used for just grabbing the next chunk from the log and
 * waiting for predecessors.
 */
static void sphere_chunk_begin_locked(replay_sphere_t *sphere, rtcb_t *rtcb) {
        chunk_t *chunk;
        uint32_t idx, i, me;

        BUG_ON(rtcb->chunk != NULL);
        if(PRINT_DEBUG) printk(KERN_CRIT "starting chunk begin tid = %u\n", rtcb->thread_id);

        chunk = demux_chunk_begin(sphere->demux, rtcb->thread_id, &sphere->mutex);
        BUG_ON(chunk->thread_id != rtcb->thread_id);
        
        me = chunk->processor_id;

        if (PRINT_DEBUG) {
                printk(KERN_CRIT "waiting for predecessor chunks to finish tid = %u\n", rtcb->thread_id);
                for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                        printk(KERN_CRIT "proc %u: count = %u sema_count = %u\n",
                               me, chunk->pred_vec[idx], sphere->proc_sem[idx][me].count);
                }
        }

        mutex_unlock(&sphere->mutex);

        my_magic_message_int("before semaphores", rtcb->thread_id);
        // now wait on tokens from predecessor chunks
        for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                for(i = 0; i < chunk->pred_vec[idx]; i++) {
                        down(&(sphere->proc_sem[idx][me]));
                }
        }
        my_magic_message_int("after semaphores", rtcb->thread_id);

        mutex_lock(&sphere->mutex);
        rtcb->chunk = chunk;
        if (PRINT_DEBUG) printk(KERN_CRIT "chunk begin tid = %u ip = 0x%p\n", rtcb->thread_id, (void *) chunk->ip);
}


static void sphere_chunk_end_locked(struct task_struct *tsk) {
        uint32_t idx, i, me;
        rtcb_t *rtcb = tsk->rtcb;
        replay_sphere_t *sphere = rtcb->sphere;
        chunk_t *chunk = rtcb->chunk;

        me = chunk->processor_id;
        demux_chunk_end(sphere->demux, &sphere->mutex, chunk);        

        // signal the successor chunks
        for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                for(i = 0; i < chunk->succ_vec[idx]; i++) {
                        up(&(sphere->proc_sem[me][idx]));
                }
        }

        rtcb->chunk = NULL;
        kfree(chunk);
}

/**********************************************************************************************/


/******************************** Public functions ********************************************/

// this is where all of the locking should take place

replay_sphere_t *sphere_alloc(void) {
        replay_sphere_t *sphere;
        int i, j;
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
        cond_init(&sphere->queue_full_cond);
        cond_init(&sphere->queue_empty_cond);
        cond_init(&sphere->next_record_cond);
        sphere->num_threads = 0;
        atomic_set(&sphere->fd_count, 0);
        sphere->header = NULL;

        // XXX FIXME check allocation errors
        sphere->proc_sem = (struct semaphore **) 
                kmalloc(NUM_CHUNK_PROC*sizeof(struct semaphore *), GFP_KERNEL);
        for(i = 0; i < NUM_CHUNK_PROC; i++) {
                sphere->proc_sem[i] = (struct semaphore *) 
                        kmalloc(NUM_CHUNK_PROC * sizeof(struct semaphore), GFP_KERNEL);
                for(j = 0; j < NUM_CHUNK_PROC; j++) {
                        sema_init(&sphere->proc_sem[i][j], 0);
                }
        }
        sphere->is_chunk_replay = 0;

        sphere->has_fifo_reader = 0;
        sphere->has_fifo_writer = 0;

        sphere->demux = demux_alloc();

        mutex_init(&sphere->mutex);

        return sphere;
}

void sphere_reset(replay_sphere_t *sphere) {
        mutex_lock(&sphere->mutex);

        if(sphere->num_threads > 0)
                BUG();
        atomic_set(&sphere->state, idle);
        sphere->next_thread_id = 1;
        sphere->replay_first_execve = 0;
        if(kfifo_len(&sphere->fifo) > 0)
                printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");        
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        sphere->fifo_head_ctu_buf = 0;
        sphere->is_chunk_replay = 0;

        BUG_ON(sphere->has_fifo_reader);
        sphere->has_fifo_reader = 0;
        BUG_ON(sphere->has_fifo_writer);
        sphere->has_fifo_writer = 0;

        // XXX FIXME we should do something to reset the proc_sem semaphores
        // or throw a bug if there are any threads waiting on them or they
        // have values

        demux_reset(sphere->demux);

        mutex_unlock(&sphere->mutex);
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

int sphere_is_chunk_replaying(replay_sphere_t *sphere) {
        // XXX FIXME we probably need to lock here because we are accessing
        // is_chunk_replay, even though it only gets set at beginning of replay
        BUG_ON(sphere->is_chunk_replay && !sphere_is_replaying(sphere));
        return sphere_is_replaying(sphere) && sphere->is_chunk_replay;
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
        mutex_lock(&sphere->mutex);
        ret = sphere_fifo_from_user_ll(sphere, buf, count, &sphere->fifo, 
                                       &sphere->queue_full_cond, &sphere->next_record_cond,
                                       &sphere->has_fifo_writer);
        mutex_unlock(&sphere->mutex);
        return ret;
}

int sphere_chunk_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count) {
        int ret;
        mutex_lock(&sphere->mutex);
        ret = demux_from_user(sphere->demux, buf, count, &sphere->mutex);
        mutex_unlock(&sphere->mutex);
        return ret;
}

int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count) {
        int ret;

        mutex_lock(&sphere->mutex);
        ret = sphere_fifo_to_user_ll(sphere, buf, count);
        mutex_unlock(&sphere->mutex);

        return ret;
}

int sphere_start_recording(replay_sphere_t *sphere) {
        int ret;

        mutex_lock(&sphere->mutex);
        ret = start_record_replay(sphere, recording);
        mutex_unlock(&sphere->mutex);

        return ret;
}

int sphere_start_replaying(replay_sphere_t *sphere) {
        int ret;

        mutex_lock(&sphere->mutex);
        ret = start_record_replay(sphere, replaying);
        mutex_unlock(&sphere->mutex);

        return ret;
}

int sphere_start_chunking(replay_sphere_t *sphere) {
        int ret = 0;

        mutex_lock(&sphere->mutex);
        BUG_ON(!sphere_is_replaying(sphere));
        sphere->is_chunk_replay = 1;
        mutex_unlock(&sphere->mutex);

        return ret;
}

uint32_t sphere_thread_create(replay_sphere_t *sphere, struct pt_regs *regs) {
        uint32_t thread_id;

        mutex_lock(&sphere->mutex);

        thread_id = sphere_next_thread_id(sphere);
        if(sphere_is_recording(sphere)) {
                record_header_locked(sphere, thread_create_event, thread_id, regs);
        } else {
                replay_event_locked(sphere, thread_create_event, thread_id, regs);
        }
        
        mutex_unlock(&sphere->mutex);

        return thread_id;

}

void sphere_thread_exit(rtcb_t *rtcb, struct pt_regs *regs) {
        replay_sphere_t *sphere = rtcb->sphere;
        uint32_t thread_id = rtcb->thread_id;

        mutex_lock(&sphere->mutex);
        if(sphere_is_recording(sphere)) {
                record_header_locked(sphere, thread_exit_event, thread_id, regs);
        } else {
                replay_event_locked(sphere, thread_exit_event, thread_id, regs);
        }

        sphere->num_threads--;
        BUG_ON(sphere->num_threads < 0);
        
        if(sphere->num_threads == 0)
                atomic_set(&sphere->state, done);

#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
        // XXX FIXME we need some way to associate this with a thread
        perf_counter_term(rtcb->pevent);
        rtcb->pevent = NULL;
#endif

        mutex_unlock(&sphere->mutex);

}


void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs) {
        int ret;

        mutex_lock(&sphere->mutex);

        ret = record_header_locked(sphere, event, thread_id, regs);

#ifdef CONFIG_MRR
        // this should only happen on the exit of the first execve in the first
        // thread that executes execve, gets chunking started
        if(sphere->replay_first_execve == 1) {
                sphere->replay_first_execve = 2;
                mrr_switch_to_record(current);
        } else if(current->rtcb->needs_chunk_start) {
                current->rtcb->needs_chunk_start = 0;
                mrr_switch_to_record(current);
        }
#endif

        mutex_unlock(&sphere->mutex);

        if(ret)
                BUG();
}

void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len) {
        int ret;
        struct task_struct *tsk = current;
        struct pt_regs *regs = task_pt_regs(tsk);

        while(mutex_trylock(&sphere->mutex) == 0) ;

        ret = record_header_locked(sphere, copy_to_user_event,
                                   current->rtcb->thread_id, regs);
        if(ret) {
                mutex_unlock(&sphere->mutex);
                BUG();
                return;
        }
        ret = record_buffer_locked(sphere, to_addr, buf, len);
        mutex_unlock(&sphere->mutex);

        if(ret)
                BUG();
}


void replay_event(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                  struct pt_regs *regs) {

        BUG_ON(sphere != current->rtcb->sphere);

        mutex_lock(&sphere->mutex);

        replay_event_locked(sphere, event, thread_id, regs);
        // this should only happen on the exit of the first execve in the first
        // thread that executes execve, gets chunking started        
        if(sphere_is_chunk_replaying(sphere)) {
                if(sphere->replay_first_execve == 1) {
                        sphere->replay_first_execve = 2;
                #ifdef CONFIG_RR_CHUNKING_PERFCOUNT
                        sphere_chunk_begin_locked(sphere, current->rtcb);
                        sphere_set_breakpoint(current->rtcb->chunk->ip);
                        current->rtcb->pevent = perf_counter_init(current);
                        current->rtcb->perf_count = perf_counter_read(current->rtcb->pevent);
                #endif
                #ifdef CONFIG_MRR
                        mrr_switch_to_replay(current);
                #endif
                } else if(current->rtcb->needs_chunk_start) {
                        current->rtcb->needs_chunk_start = 0;
                #ifdef CONFIG_RR_CHUNKING_PERFCOUNT
                        sphere_chunk_begin_locked(sphere, current->rtcb);
                        current->rtcb->pevent = perf_counter_init(current);
                        sphere_set_breakpoint(current->rtcb->chunk->ip);
                #endif
                #ifdef CONFIG_MRR
                        mrr_switch_to_replay(current);
                #endif
                }
        }

        mutex_unlock(&sphere->mutex);
}

void sphere_chunk_begin(struct task_struct *tsk) {
        replay_sphere_t *sphere = tsk->rtcb->sphere;
        mutex_lock(&sphere->mutex);
        sphere_chunk_begin_locked(sphere, tsk->rtcb);
        mutex_unlock(&sphere->mutex);
}

void sphere_chunk_end(struct task_struct *tsk) {
        replay_sphere_t *sphere = tsk->rtcb->sphere;
        mutex_lock(&sphere->mutex);
        sphere_chunk_end_locked(tsk);
        mutex_unlock(&sphere->mutex);
}

void sphere_check_first_execve(replay_sphere_t *sphere, struct pt_regs *regs) {
        if((regs_syscallno(regs) == __NR_execve) &&
           (sphere->replay_first_execve == 0)) {
                sphere->replay_first_execve = 1;
        }
}

int sphere_has_first_execve(replay_sphere_t *sphere) {
        return sphere->replay_first_execve;
}

/**********************************************************************************************/
