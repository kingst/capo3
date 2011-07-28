#ifndef __REPLAY_H__
#define __REPLAY_H__

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING _IO(REPLAY_IOC_MAGIC, 1)
#define REPLAY_IOC_RESET_SPHERE    _IO(REPLAY_IOC_MAGIC, 2)

typedef enum {invalid_event=0, execve_event, syscall_enter_event, 
              syscall_exit_event, thread_create_event, thread_exit_event,
              instruction_event, copy_to_user_event} replay_event_t;

struct replay_sphere;

#endif
