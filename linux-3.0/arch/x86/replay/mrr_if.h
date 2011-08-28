#ifndef _ASM_X86_REPLAY_MRR_IF_H
#define _ASM_X86_REPLAY_MRR_IF_H

#include <asm/mrr/mrrhw_if.h>
#include <asm/mrr/mrrhwsw_if.h>

void mrr_buffer_full_handler(struct task_struct *tsk, bool complete_flush);
void mrr_switch_from(struct task_struct *tsk);
void mrr_switch_to(struct task_struct *tsk);

#endif /* _ASM_X86_REPLAY_MRR_IF_H */


