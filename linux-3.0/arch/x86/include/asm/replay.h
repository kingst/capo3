#ifndef __REPLAY_H__
#define __REPLAY_H__

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING   _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING   _IO(REPLAY_IOC_MAGIC, 1)
#define REPLAY_IOC_RESET_SPHERE      _IO(REPLAY_IOC_MAGIC, 2)
#define REPLAY_IOC_START_CHUNKING    _IO(REPLAY_IOC_MAGIC, 3)
#define REPLAY_IOC_SET_CHUNK_LOG_FD  _IO(REPLAY_IOC_MAGIC, 4)

typedef enum {invalid_event=0, execve_event, syscall_enter_event, 
              syscall_exit_event, thread_create_event, thread_exit_event,
              instruction_event, copy_to_user_event, signal_event} replay_event_t;

typedef struct replay_header {
        uint32_t type;
        uint32_t thread_id;
        struct pt_regs regs;
} replay_header_t;

#define NUM_CHUNK_PROC 8

typedef struct chunk_struct {
        uint32_t processor_id;
        uint32_t thread_id;
        uint32_t inst_count;
        uint32_t succ_vec[NUM_CHUNK_PROC];
        uint32_t pred_vec[NUM_CHUNK_PROC];
        unsigned long ip;
} chunk_t;

#ifdef __KERNEL__

#ifdef CONFIG_X86_64

static inline unsigned long regs_return(struct pt_regs *regs) {return regs->ax;}
static inline void set_regs_return(struct pt_regs *regs, unsigned long val) {regs->ax = val;}
static inline unsigned long regs_syscallno(struct pt_regs *regs) {return regs->orig_ax;}
static inline void set_regs_syscallno(struct pt_regs *regs, unsigned long val) {regs->orig_ax = val;}
static inline unsigned long regs_first(struct pt_regs *regs) {return regs->di;}
static inline unsigned long regs_second(struct pt_regs *regs) {return regs->si;}
static inline unsigned long regs_third(struct pt_regs *regs) {return regs->dx;}
static inline unsigned long regs_fourth(struct pt_regs *regs) {return regs->r10;}
static inline unsigned long regs_fifth(struct pt_regs *regs) {return regs->r8;}
static inline unsigned long regs_sixth(struct pt_regs *regs) {return regs->r9;}
static inline unsigned long regs_ip(struct pt_regs *regs) {return regs->ip;}
static inline unsigned long regs_sp(struct pt_regs *regs) {return regs->sp;}

//#elif CONFIG_X86_32
#elif 0

#error "support for 32 bit not working yet"

static inline unsigned long regs_return(struct pt_regs *regs) {return regs->ax;}
static inline void set_regs_return(struct pt_regs *regs, unsigned long val) {regs->ax = val;}
static inline unsigned long regs_syscallno(struct pt_regs *regs) {return regs->orig_ax;}
static inline void set_regs_syscallno(struct pt_regs *regs, unsigned long val) {regs->orig_ax = val;}
static inline unsigned long regs_first(struct pt_regs *regs) {return regs->bx;}
static inline unsigned long regs_second(struct pt_regs *regs) {return regs->cx;}
static inline unsigned long regs_third(struct pt_regs *regs) {return regs->dx;}
static inline unsigned long regs_fourth(struct pt_regs *regs) {return regs->si;}
static inline unsigned long regs_fifth(struct pt_regs *regs) {return regs->di;}
static inline unsigned long regs_sixth(struct pt_regs *regs) {return regs->bp;}
static inline unsigned long regs_ip(struct pt_regs *regs) {return regs->ip;}
static inline unsigned long regs_sp(struct pt_regs *regs) {return regs->sp;}

#else

#error "unsupported architecture"

#endif

#include <linux/kfifo.h>
#include <linux/cond.h>
#include <linux/semaphore.h>

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
        int has_fifo_reader;
        int has_fifo_writer;
        int has_chunk_fifo_writer;

        // these variables are only accessed by rr threads
        int fifo_head_ctu_buf;
        uint32_t next_thread_id;
        int num_threads;
        replay_header_t *header;
        int replay_first_execve;

        // for chunk replay
        struct semaphore **proc_sem;
        unsigned char *chunk_buffer;
        struct kfifo chunk_fifo;
        cond_t chunk_queue_full_cond;
        cond_t chunk_next_record_cond;
        struct chunk_struct *next_chunk;
        int is_chunk_replay;
        int *next_tickets;
        atomic_t *cur_tickets;
        wait_queue_head_t tickets_wait_queue;
        cond_t cur_tickets_updated;
} replay_sphere_t;

struct perf_event;

typedef struct replay_thread_control_block {
        struct replay_sphere *sphere;
        uint32_t thread_id;
        uint64_t def_sig;
        uint64_t send_sig;
        struct chunk_struct *chunk;
        uint32_t my_ticket;
        int needs_chunk_start;
        uint64_t perf_count;
        struct perf_event *pevent;
#ifdef CONFIG_MRR
        // TODO: change this later
        char chunk_size_buffer[1024];
#endif
} rtcb_t;

// kernel callback function types
typedef void (*rr_syscall_enter_cb_t)(struct pt_regs *regs);
typedef void (*rr_syscall_exit_cb_t)(struct pt_regs *regs);
typedef void (*rr_thread_create_cb_t)(struct task_struct *tsk, replay_sphere_t *sphere);
typedef void (*rr_thread_exit_cb_t)(struct pt_regs *regs);
typedef void (*rr_switch_from_cb_t)(struct task_struct *prev_p);
typedef void (*rr_switch_to_cb_t)(struct task_struct *next_p);
typedef int (*rr_general_protection_cb_t)(struct pt_regs *regs);
typedef void (*rr_copy_to_user_cb_t)(unsigned long to_addr, void *buf, int len);
typedef int (*rr_deliver_signal_cb_t)(int signr, struct pt_regs *regs);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
typedef int (*rr_do_debug_cb_t)(struct pt_regs *regs, long error_code);
#endif


// from usermode calls
// for the two fifo calls as long as we have mutual exclution wrt
// other reads/writes then we don't need any spinlocks
replay_sphere_t *sphere_alloc(void);
void sphere_reset(replay_sphere_t *sphere);
void sphere_inc_fd(replay_sphere_t *sphere);
void sphere_dec_fd(replay_sphere_t *sphere);
int sphere_fifo_to_user(replay_sphere_t *sphere, char __user *buf, size_t count);
int sphere_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count);
int sphere_chunk_fifo_from_user(replay_sphere_t *sphere, const char __user *buf, size_t count);

// The first thread to record/replay calls these on itself
int sphere_start_recording(replay_sphere_t *sphere);
int sphere_start_replaying(replay_sphere_t *sphere);
int sphere_start_chunking(replay_sphere_t *sphere, rtcb_t *rtcb);

// called from record/replay threads when allocated
// might be called from context of a different thread
void sphere_thread_exit(rtcb_t *rtcb, struct pt_regs *regs);
uint32_t sphere_thread_create(replay_sphere_t *sphere, struct pt_regs *regs);

// simple status calls
int sphere_is_recording_replaying(replay_sphere_t *sphere);
int sphere_is_recording(replay_sphere_t *sphere);
int sphere_is_replaying(replay_sphere_t *sphere);
int sphere_is_chunk_replaying(replay_sphere_t *sphere);

// calls from threads that are being recorded/replayed
void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                   struct pt_regs *regs);
void record_copy_to_user(replay_sphere_t *sphere, unsigned long to_addr, void *buf, int32_t len);
void replay_event(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                  struct pt_regs *regs);

int sphere_has_first_execve(replay_sphere_t *sphere);
void sphere_check_first_execve(replay_sphere_t *sphere, struct pt_regs *regs);

// for chunk replay
void sphere_chunk_begin(struct task_struct *tsk);
void sphere_chunk_end(struct task_struct *tsk);
#ifdef CONFIG_RR_CHUNKING_PERFCOUNT
void sphere_set_breakpoint(unsigned long ip);
#endif

#endif

#endif
