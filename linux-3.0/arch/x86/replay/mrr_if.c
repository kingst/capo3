#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <asm/replay.h>
#include <asm/mrr/simics_if.h>
#include "mrr_if.h"

#define MSG_PREFIX "KernelMrr: "


void mrr_virtualize_chunk_size(struct task_struct *tsk) {

    rtcb_t *rtcb = tsk->rtcb;

    // save the remaining inst count
    if (sphere_is_chunk_replaying(rtcb->sphere) && test_tsk_thread_flag(tsk, TIF_MRR_CHUNKING) && (rtcb->chunk != NULL)) {
        uint32_t cur_inst_count = mrr_get_chunk_size(1);

        // update the remaining inst count
        BUG_ON(rtcb->chunk->inst_count < cur_inst_count);
        rtcb->chunk->inst_count -= cur_inst_count;

        // set the new target size in the processor
        mrr_set_target_chunk_size(rtcb->chunk->inst_count);            
    }
}


/*
 * this function does not sleep.
 */
static void prepare_mrr_record(struct task_struct *tsk) {

    rtcb_t *rtcb = tsk->rtcb;
    replay_sphere_t *sphere = rtcb->sphere;

    // FIXME: add sphere_is_chunk_recording()
    if (sphere_is_recording(sphere) /*sphere_is_chunk_recording(sphere)*/ && sphere_has_first_execve(sphere)) {
        set_ti_thread_flag(task_thread_info(tsk), TIF_MRR_CHUNKING);
        mrr_set_record();
    }
}


static void prepare_mrr_replay(struct task_struct *tsk) {
    rtcb_t *rtcb = tsk->rtcb;
    replay_sphere_t *sphere = rtcb->sphere;

    if (sphere_is_chunk_replaying(sphere) && sphere_has_first_execve(sphere)) {

        set_ti_thread_flag(task_thread_info(tsk), TIF_MRR_CHUNKING);
        mrr_set_replay();

        // if we already have a chunk, set its chunk size in the processor.
        if (NULL != rtcb->chunk) {
            mrr_set_target_chunk_size(rtcb->chunk->inst_count);
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

        // signal the end of the current chunk
        if (NULL != rtcb->chunk) {
            sphere_chunk_end(current);
        }

        // we might sleep, so enable irqs
		local_irq_enable();

        // set the next target chunk size
        sphere_chunk_begin(current);
        BUG_ON(NULL == rtcb->chunk);
        BUG_ON(0 == rtcb->chunk->inst_count);
        mrr_set_target_chunk_size(rtcb->chunk->inst_count);
    }
}


/*
 * handles switching from a recoded thread
 * This function does not sleep.
 */
void mrr_switch_from_record(struct task_struct *tsk) {

    rtcb_t *rtcb = tsk->rtcb;

    // flush the mrr buffer
    if (sphere_is_recording(rtcb->sphere) && test_tsk_thread_flag(tsk, TIF_MRR_CHUNKING)) {
        mrr_buffer_full_handler(tsk, true);
    }

    my_magic_app_out();
}


/*
 * handles switching from a recoded thread
 * This function does not sleep.
 */
void mrr_switch_from_replay(struct task_struct *tsk) {

    // save the remaining inst count
    mrr_virtualize_chunk_size(tsk);

    my_magic_app_out();
}


/*
 * handles switching to a recoded thread
 */
void mrr_switch_to_record(struct task_struct *tsk) {
    my_magic_app_in();
    prepare_mrr_record(tsk);
}


/*
 * handles switching to a replayed thread
 * PRECOND: tsk should not be holding sphere->mutex since 
 * this function may sleep.
 */
void mrr_switch_to_replay(struct task_struct *tsk) {
    my_magic_app_in();
    prepare_mrr_replay(tsk);
}

