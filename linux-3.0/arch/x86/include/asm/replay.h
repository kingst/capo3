#ifndef __REPLAY_H__
#define __REPLAY_H__

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING _IO(REPLAY_IOC_MAGIC, 1)
#define REPLAY_IOC_RESET_SPHERE    _IO(REPLAY_IOC_MAGIC, 2)

typedef enum {invalid_event=0, execve_event, syscall_enter_event, 
              syscall_exit_event, thread_create_event, thread_exit_event,
              instruction_event, copy_to_user_event, signal_event} replay_event_t;

typedef struct replay_header {
        uint32_t type;
        uint32_t thread_id;
        struct pt_regs regs;
} replay_header_t;

#ifdef __KERNEL__

#include <linux/kfifo.h>
#include <linux/cond.h>

typedef enum {idle, recording, replaying, done} replay_state_t;

typedef struct replay_sphere {
        unsigned char *fifo_buffer;

        // these variables can be touched by both usermode and rr threads
        // so they need to be protected from each other
        atomic_t state;
        struct kfifo fifo;
        cond_t queue_full_cond;
        cond_t queue_empty_cond;
        cond_t next_record_cond;

        // these variables are only accessed by usermode
        struct mutex mutex;
        atomic_t fd_count;

        // these variables are only accessed by rr threads
        int fifo_head_ctu_buf;
        uint32_t next_thread_id;
        int num_threads;
        replay_header_t *header;
        int replay_first_execve;
} replay_sphere_t;


typedef struct replay_thread_control_block {
        struct replay_sphere *sphere;
        uint32_t thread_id;
        uint64_t def_sig;
        uint64_t send_sig;

#ifdef CONFIG_MRR
        // TODO: change this later
        char chunk_size_buffer[1024];
#endif
} rtcb_t;

void rr_syscall_enter(struct pt_regs *regs);
void rr_syscall_exit(struct pt_regs *regs);
void rr_thread_create(struct task_struct *tsk, replay_sphere_t *sphere);
void rr_thread_exit(struct pt_regs *regs);
void rr_switch_to(struct task_struct *prev_p, struct task_struct *next_p);
int rr_general_protection(struct pt_regs *regs);
void rr_copy_to_user(unsigned long to_addr, void *buf, int len);
void rr_send_signal(int signo);
int rr_deliver_signal(int signr, struct pt_regs *regs);

// from usermode calls
// for the two fifo calls as long as we have mutual exclution wrt
// other reads/writes then we don't need any spinlocks
replay_sphere_t *sphere_alloc(void);
void sphere_reset(replay_sphere_t *sphere);
void sphere_inc_fd(replay_sphere_t *sphere);
void sphere_dec_fd(replay_sphere_t *sphere);
int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count);
int sphere_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count);

// The first thread to record/replay calls these on itself
// holds the rr_thread_wait.lock
int sphere_start_recording(replay_sphere_t *sphere);
int sphere_start_replaying(replay_sphere_t *sphere);

// called from record/replay threads when allocated
// might be called from context of a different thread
// holds the rr_thread_wait.lock
void sphere_thread_exit(replay_sphere_t *sphere, uint32_t thread_id, struct pt_regs *regs);
uint32_t sphere_thread_create(replay_sphere_t *sphere, struct pt_regs *regs);

// simple status calls
int sphere_is_recording_replaying(replay_sphere_t *sphere);
int sphere_is_recording(replay_sphere_t *sphere);
int sphere_is_replaying(replay_sphere_t *sphere);

// calls from threads that are being recorded/replayed
// holds the rr_thread_wait.lock
void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs);
void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len);
void replay_event(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                  struct pt_regs *regs);


#endif

#endif
