#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <asm/replay.h>
#include "mrr_if.h"

#define MSG_PREFIX "KernelMrr: "

/*
 * For recording mode. this function will have the processor 
 * dump the mrr chunks data to the provided buffer.
 */
void mrr_buffer_full_handler(struct task_struct *tsk, bool complete_flush) {

    if (NULL == tsk->rtcb) {
        printk(KERN_ERR MSG_PREFIX "mrr_buffer_full_handler invoked on invalid RTCB.");
        BUG();
    }

    // this should be during recording
    if (sphere_is_recording(tsk->rtcb->sphere)) {

        // flush the on-processor buffer into the rtcb buffer
        int dump_size;
        void *buf_addr = &tsk->rtcb->chunk_size_buffer;

        if (complete_flush) {
            dump_size = mrr_flush(buf_addr, tsk->rtcb->thread_id);
        } else {
            dump_size = mrr_flush_buffer(buf_addr, tsk->rtcb->thread_id);
        }

        // TODO: complete this
        // copy the rtcb buffer into the rscb buffer
        // ...        
    }
    
}


/*
 * For replaying mode.
 */
void mrr_chunk_done_handler(struct task_struct *tsk) {

    if (NULL == tsk->rtcb) {
        printk(KERN_ERR MSG_PREFIX "mrr_chunk_done_handler invoked on invalid RTCB.");
        BUG();
    }

    // this should be during replay
    if (sphere_is_replaying(tsk->rtcb->sphere)) {
        // for debugging: print a message and break
        my_magic_message("in chunk done handler.");
        my_sim_break();
    }
}


void prepare_mrr(struct task_struct *tsk) {

    // we should only enable mrr chunking after the first execve
    // since we do not want to record/replay the driver program
    // (since it behaves differently in record and replay modes)
    if (tsk->rtcb->sphere->first_execve) {

        // set the mrr hardware into proper mode
        if (sphere_is_recording(tsk->rtcb->sphere)) {
            //my_magic_message("putting the processor in record mode");
            mrr_set_record();
        } else if (sphere_is_replaying(tsk->rtcb->sphere)) {
            //my_magic_message("putting the processor in replay mode");
            mrr_set_replay();
        }
        
        // set the chunking flag for the thread
        //my_magic_message("setting TIF_MRR_CHUNKING");
        set_ti_thread_flag(task_thread_info(tsk), TIF_MRR_CHUNKING);
    }
}

static int __init replay_mrr_if_init(void) {
    set_mrr_buffer_full_handler_cb(&mrr_buffer_full_handler);
    printk(KERN_INFO "set the mrr_buffer_full_handler call back");
    set_mrr_chunk_done_handler_cb(&mrr_chunk_done_handler);
    printk(KERN_INFO "set the mrr_chunk_done_handler call back");
	return 0;
}

module_init(replay_mrr_if_init);
