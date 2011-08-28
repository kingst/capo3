/*
 * Memory Race Recorder (MRR) exception handler
 * author: Nima Honarmand
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <asm/traps.h>
#include <asm/io.h>
#include <asm/mrr/mrrhw_if.h>
#include <asm/mrr/mrrhwsw_if.h>

#define MSG_PREFIX "KernelMrr: "

/**
 * The call back that is used to handle MRR exceptions
 */
static mrr_buffer_full_handler_sig mrr_buffer_full_handler_cb = NULL;
static mrr_chunk_done_handler_sig mrr_chunk_done_handler_cb = NULL;
void set_mrr_buffer_full_handler_cb(mrr_buffer_full_handler_sig cb) {
    mrr_buffer_full_handler_cb = cb;
}
void set_mrr_chunk_done_handler_cb(mrr_chunk_done_handler_sig cb) {
    mrr_chunk_done_handler_cb = cb;
}
EXPORT_SYMBOL(set_mrr_buffer_full_handler_cb);
EXPORT_SYMBOL(set_mrr_chunk_done_handler_cb);

/**
 * Handler for the Mrr Buffer Full exception.
 */
dotraplinkage void do_mrr_full(void) {
    // call back to flush the buffer
    if (mrr_buffer_full_handler_cb != NULL) {
        mrr_buffer_full_handler_cb(current, false);
    }
}


/**
 * Handler for the Mrr Chunk Done exception.
 */
dotraplinkage void do_mrr_chunk_done(void) {

    // call back to set a new target chunk size
    if (mrr_chunk_done_handler_cb != NULL) {
        mrr_chunk_done_handler_cb(current);
    }        
}

