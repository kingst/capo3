#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <asm/replay.h>
#include <asm/mrr/mrrhwsw_if.h>
#include <asm/mrr/simics_if.h>

#define MSG_PREFIX "KernelMrr: "

/*
 * this function will have the processor dump the mrr chunks data
 * to the provided buffer
 */
void mrr_full_handler(struct task_struct *tsk, bool complete_flush) {

    if (NULL == tsk->rtcb) {
        printk(KERN_ERR MSG_PREFIX "mrr_full_handler invoked on invalid RTCB.");
        BUG();
    }

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


static int __init replay_mrr_if_init(void) {
    set_mrr_full_handler_cb(&mrr_full_handler);
    printk(KERN_INFO "set the mrr_full_handler call back");
	return 0;
}

module_init(replay_mrr_if_init);
