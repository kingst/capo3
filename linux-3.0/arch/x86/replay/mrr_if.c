#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <asm/replay.h>
#include <asm/mrr/simics_if.h>
#include "mrr_if.h"

#define MSG_PREFIX "KernelMrr: "


static void prepare_mrr(struct task_struct *tsk) {

    rtcb_t *rtcb = tsk->rtcb;
    replay_sphere_t *sphere = rtcb->sphere;

    // we should only enable mrr chunking after the first execve
    // since we do not want to record/replay the driver program
    // (since it behaves differently in record and replay modes)
    if (sphere_is_recording_replaying(sphere) && sphere->replay_first_execve) {

        // set the chunking flag for the thread
        // FIXME
        //if (sphere_is_chunking(rtcb->sphere))
        set_ti_thread_flag(task_thread_info(tsk), TIF_MRR_CHUNKING);

        // set the mrr hardware into proper mode
        if (sphere_is_recording(sphere)) {
            mrr_set_record();
        }
        else if (sphere_is_chunk_replaying(sphere)) {

            // set the mode
            mrr_set_replay();

            // get the next chunk from the log, if necessary, and set the target chunk size
            // care must be taken here since there might be a race between
            // this invocation of sphere_chunk_begin() and a previous call
            // to the same function that caused a context switch and is still
            // in progress.
            if (NULL == rtcb->chunk /* && !rtcb->is_in_chunk_begin */) {
                sphere_chunk_begin(tsk);
                BUG_ON(NULL == rtcb->chunk);
            }

            if (NULL != rtcb->chunk) {
                BUG_ON(0 == rtcb->chunk->inst_count);
                mrr_set_target_chunk_size(rtcb->chunk->inst_count);
            }
        }
    }
}


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

    rtcb_t *rtcb = tsk->rtcb;
    if (NULL == rtcb) {
        printk(KERN_ERR MSG_PREFIX "mrr_chunk_done_handler invoked on invalid RTCB.");
        BUG();
    }

    // this should be during replay
    if (sphere_is_replaying(tsk->rtcb->sphere)) {

        // reset the mrr chunk inst count
        mrr_get_chunk_size(1);

        // for debugging: print a message and break
        my_magic_message("in chunk done handler.");
        //my_sim_break();

        // signal the end of the current chunk
        if (NULL != rtcb->chunk) {
            my_magic_message("calling sphere_chunk_end");
            sphere_chunk_end(current, 0);
        }

        // we might sleep, so enable irqs
		local_irq_enable();

        // set the next target chunk size
        my_magic_message("calling sphere_chunk_begin");        
        sphere_chunk_begin(current);
        BUG_ON(NULL == rtcb->chunk);

        BUG_ON(0 == rtcb->chunk->inst_count);
        mrr_set_target_chunk_size(rtcb->chunk->inst_count);
        my_magic_message("just set mrr chunk size");        
        //my_sim_break();
    }
}


/*
 * handles switching from a recoded thread
 * PRECOND: tsk should not be holding sphere->mutex.
 */
void mrr_switch_from(struct task_struct *tsk) {

    rtcb_t *rtcb = tsk->rtcb;

    // recording mode: flush the mrr buffer
    if (sphere_is_recording(rtcb->sphere) && test_tsk_thread_flag(tsk, TIF_MRR_CHUNKING)) {
        mrr_buffer_full_handler(tsk, true);
    }

    // replay mode: save the remaining inst count
    if (sphere_is_replaying(rtcb->sphere) && test_tsk_thread_flag(tsk, TIF_MRR_CHUNKING)) {
        if (rtcb->chunk != NULL) {
            uint32_t cur_inst_count = mrr_get_chunk_size(1);
            my_magic_message_int("just read mrr chunk size", rtcb->thread_id);
            my_magic_message_int("read mrr chunk size is", cur_inst_count);
            //my_sim_break();

            // update the remaining inst count
            BUG_ON(rtcb->chunk->inst_count < cur_inst_count);
            rtcb->chunk->inst_count -= cur_inst_count;

            // if the chunk has been exhausted (but not ended), 
            // end it now
            if (0 == rtcb->chunk->inst_count) {
                my_magic_message("calling sphere_chunk_end");
                sphere_chunk_end(tsk, 0);
            }
        }
    }

    my_magic_app_out();
}


/*
 * handles switching to a recoded thread
 * PRECOND: tsk should not be holding sphere->mutex.
 */
void mrr_switch_to(struct task_struct *tsk) {
    my_magic_app_in();
    prepare_mrr(tsk);
}


static int __init replay_mrr_if_init(void) {
    set_mrr_buffer_full_handler_cb(&mrr_buffer_full_handler);
    printk(KERN_INFO "set the mrr_buffer_full_handler call back");
    set_mrr_chunk_done_handler_cb(&mrr_chunk_done_handler);
    printk(KERN_INFO "set the mrr_chunk_done_handler call back");
	return 0;
}


module_init(replay_mrr_if_init);
