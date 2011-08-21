#ifndef _ASM_X86_MRRHWSW_IF_H
#define _ASM_X86_MRRHWSW_IF_H

#ifdef CONFIG_MRR

// this include files is copied from the Simics module
// and defines markers and instructions
#include "mrrhw_if.h"

#define mrr_disable_chunking()  asm volatile ( __MRR_INST_DISABLE_CHUNKING )
#define mrr_enable_chunking()   asm volatile ( __MRR_INST_ENABLE_CHUNKING )
#define mrr_terminate_chunk()   asm volatile ( __MRR_INST_TERMINATE_CHUNK )
#define mrr_set_record()        asm volatile ( __MRR_INST_RECORD )
#define mrr_set_replay()        asm volatile ( __MRR_INST_REPLAY )

static inline int mrr_flush_buffer(void *paddr, int actor_id) {

    int ret;

    asm volatile (
        __MRR_INST_FLUSH_BUFFER
        : "=a" (ret)
        : "a" (paddr), "c" (actor_id)
    );

    return ret;
}

static inline int mrr_flush(void *paddr, int actor_id) {

    int ret;

    asm volatile (
        __MRR_INST_FLUSH_MRR
        : "=a" (ret)
        : "a" (paddr), "c" (actor_id)
    );

    return ret;
}

/**
 * call-backs called to handle MRR exceptions.
 */
struct task_struct;
typedef void (*mrr_buffer_full_handler_sig)(struct task_struct *tsk, bool complete_flush);
void set_mrr_buffer_full_handler_cb(mrr_buffer_full_handler_sig cb);
typedef void (*mrr_chunk_done_handler_sig)(struct task_struct *tsk);
void set_mrr_chunk_done_handler_cb(mrr_chunk_done_handler_sig cb);

#else

#define mrr_disable_chunking()          ((void) 0)
#define mrr_enable_chunking()           ((void) 0)
#define mrr_terminate_chunk()           ((void) 0)
#define mrr_set_record()                ((void) 0)
#define mrr_set_replay()                ((void) 0)
#define mrr_flush_buffer(nthg,nthg1)    ((void) 0)
#define mrr_flush(nthg,nthg1)           ((void) 0)

#endif // CONFIG_MRR

#endif /* _ASM_X86_MRRHWSW_IF_H */


