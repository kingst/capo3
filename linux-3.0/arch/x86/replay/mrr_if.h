#ifndef _ASM_X86_REPLAY_MRR_IF_H
#define _ASM_X86_REPLAY_MRR_IF_H

#include <asm/mrr/mrrhwsw_if.h>
#include <asm/mrr/mrrhw_if.h>

void mrr_buffer_full_handler(struct task_struct *tsk, bool complete_flush);
void prepare_mrr(struct task_struct *tsk);

#endif /* _ASM_X86_REPLAY_MRR_IF_H */


