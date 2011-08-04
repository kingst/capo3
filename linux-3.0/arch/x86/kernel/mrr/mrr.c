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
#include <asm/mrr/mrrhwsw_if.h>

#define MSG_PREFIX "KernelMrr: "

/**
 * The call back that is used to handle MRR-full exceptions
 */
static mrr_full_handler_sig mrr_full_handler_cb = NULL;
void set_mrr_full_handler_cb(mrr_full_handler_sig cb) {
    mrr_full_handler_cb = cb;
}
EXPORT_SYMBOL(set_mrr_full_handler_cb);

/**
 * Handler for the Mrr Buffer Full exception.
 */
dotraplinkage void do_mrr_full(void) {

    // flush the buffer
    if (mrr_full_handler_cb != NULL) {
        mrr_full_handler_cb(current, false);
    }
}


