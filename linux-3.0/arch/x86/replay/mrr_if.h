#ifndef _ASM_X86_REPLAY_MRR_IF_H
#define _ASM_X86_REPLAY_MRR_IF_H

#include <asm/mrr/mrrhw_if.h>
#include <asm/mrr/mrrhwsw_if.h>

void mrr_virtualize_chunk_size(struct task_struct *tsk);

void mrr_buffer_full_handler(struct task_struct *tsk, bool complete_flush);
void mrr_chunk_done_handler(struct task_struct *tsk);

void mrr_switch_from_record(struct task_struct *tsk);
void mrr_switch_from_replay(struct task_struct *tsk);
void mrr_switch_to_record(struct task_struct *tsk);
void mrr_switch_to_replay(struct task_struct *tsk);

#endif /* _ASM_X86_REPLAY_MRR_IF_H */


