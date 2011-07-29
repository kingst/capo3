#ifndef __REPLAY_H__
#define __REPLAY_H__

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING _IO(REPLAY_IOC_MAGIC, 1)
#define REPLAY_IOC_RESET_SPHERE    _IO(REPLAY_IOC_MAGIC, 2)

typedef enum {invalid_event=0, execve_event, syscall_enter_event, 
              syscall_exit_event, thread_create_event, thread_exit_event,
              instruction_event, copy_to_user_event, signal_event} replay_event_t;

#include <linux/kfifo.h>

typedef enum {idle, recording, replaying, done} replay_state_t;

typedef struct replay_sphere {
        replay_state_t state;
        unsigned char *fifo_buffer;
        spinlock_t lock;
        struct kfifo fifo;
        wait_queue_head_t usermode_wait;
        uint32_t next_thread_id;
        atomic_t fd_count;
        int num_threads;
        atomic_t num_readers;
        atomic_t num_writers;
} replay_sphere_t;


typedef struct replay_thread_control_block {
        struct replay_sphere *sphere;
        uint32_t thread_id;
} rtcb_t;

typedef struct replay_header {
    uint32_t type;
    uint32_t thread_id;
    struct pt_regs regs;
} replay_header_t;

void rr_syscall_enter(struct pt_regs *regs);
void rr_syscall_exit(struct pt_regs *regs);
void rr_thread_create(struct task_struct *tsk, replay_sphere_t *sphere);
void rr_thread_exit(struct pt_regs *regs);
void rr_switch_to(struct task_struct *prev_p, struct task_struct *next_p);
int rr_general_protection(struct pt_regs *regs);
void rr_copy_to_user(unsigned long to_addr, void *buf, int len);
void rr_send_signal(struct pt_regs *regs);

replay_sphere_t *sphere_alloc(void);
void sphere_reset(replay_sphere_t *sphere);
int sphere_is_recording_replaying(replay_sphere_t *sphere);
void sphere_inc_fd(replay_sphere_t *sphere);
void sphere_dec_fd(replay_sphere_t *sphere);
int sphere_is_done_recording(replay_sphere_t *sphere);
int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count);
int sphere_wait_usermode(replay_sphere_t *sphere);
int sphere_start_recording(replay_sphere_t *sphere);
uint32_t sphere_next_thread_id(replay_sphere_t *sphere);
void sphere_thread_exit(replay_sphere_t *sphere);

void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs);
void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len);

#endif
