#ifndef _ASM_X86_REPLAY_MRR_IF_H
#define _ASM_X86_REPLAY_MRR_IF_H

struct task_struct;
void mrr_full_handler(struct task_struct *tsk, bool complete_flush);

#endif /* _ASM_X86_REPLAY_MRR_IF_H */


