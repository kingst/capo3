#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/kfifo.h>
#include <linux/file.h>

#include <trace/syscall.h>
#include <trace/events/syscalls.h>

#include <asm/replay.h>

void replay_thread_create(struct pt_regs *regs);

#define LOG_BUFFER_SIZE (8*1024*1024)
#define NUM_REPLAY_MINOR 4

typedef enum {idle, recording, replaying, done} replay_state_t;

typedef struct replay_sphere {
        replay_state_t state;
        unsigned char *fifo_buffer;
        spinlock_t lock;
        struct kfifo fifo;
        wait_queue_head_t wait;
        atomic_t fd_count;
        atomic_t num_threads;
        atomic_t num_readers;
        atomic_t num_writers;
} replay_sphere_t;

static struct class *replay_class = NULL;
static struct file_operations replay_fops;
static int replay_major = 0;

#define REPLAY_VERSION	"0.3"

static int replay_open(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere;

        if(inode->i_private == NULL) {
                sphere = kmalloc(sizeof(replay_sphere_t), GFP_KERNEL);
                if(sphere == NULL) {
                        BUG();
                        return -ENOMEM;
                }

                sphere->state = done;
                sphere->fifo_buffer = vmalloc(LOG_BUFFER_SIZE);
                if(sphere->fifo_buffer == NULL) {
                        kfree(sphere);
                        BUG();
                        return -ENOMEM;
                }

                spin_lock_init(&sphere->lock);
                kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
                init_waitqueue_head(&sphere->wait);
                atomic_set(&sphere->fd_count, 0);
                atomic_set(&sphere->num_threads, 0);
                atomic_set(&sphere->num_readers, 0);
                atomic_set(&sphere->num_writers, 0);
                inode->i_private = sphere;
        } else {
                sphere = (replay_sphere_t *) inode->i_private;
        }

        atomic_inc(&sphere->fd_count);
        file->private_data = sphere;

	return 0;
}

static int replay_release(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere = file->private_data;

        if(inode->i_private != file->private_data)
                BUG();

        spin_lock(&sphere->lock);
        if(atomic_dec_return(&sphere->fd_count) < 0)
                BUG();
        if(kfifo_len(&sphere->fifo) > 0)
                printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        spin_unlock(&sphere->lock);

	return 0;
}

static int kfifo_has_data(replay_sphere_t *sphere) {
        int len, ret;
        len = kfifo_len(&sphere->fifo);

        spin_lock(&sphere->lock);
        ret = (len > 0) || (sphere->state == done);
        spin_unlock(&sphere->lock);

        return ret;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        int ret = 0;
        replay_sphere_t *sphere;
        int flen, bytesRead=0;

        sphere = (replay_sphere_t *) file->private_data;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }

        spin_lock(&sphere->lock);
        if(sphere->state == done) {
                spin_unlock(&sphere->lock);
                return 0;
        }
        spin_unlock(&sphere->lock);

        if(atomic_inc_return(&sphere->num_readers) > 1)
                return -EINVAL;

        // We enforce mutual exclusion on all threads that are being
        // recorded when they access the kfifo that is in the sphere.
        // So as long as there is only one reader we can access kfifo
        // data without holding any locks
        ret = wait_event_interruptible(sphere->wait, kfifo_has_data(sphere));

        if(ret == -ERESTARTSYS) {
                atomic_dec(&sphere->num_readers);
                return ret;
        }

        flen = kfifo_len(&sphere->fifo);
        if(flen < count)
                count = flen;

        if(flen <= 0)
                BUG();

        ret = kfifo_to_user(&sphere->fifo, buf, count, &bytesRead);
        
        atomic_dec(&sphere->num_readers);

        if(ret)
                return ret;

        return bytesRead;
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
        replay_sphere_t *sphere;
        rtcb_t *rtcb;

        if(file->private_data == NULL)
                BUG();

        if(current->rtcb != NULL)
                BUG();

        sphere = (replay_sphere_t *) file->private_data;

        if(cmd == REPLAY_IOC_START_RECORDING) {
                // the process will call this on itself before
                // calling exec.  From this point on the process is being
                // traced
                if(atomic_read(&sphere->num_threads) > 0)
                        BUG();
                printk(KERN_CRIT "starting recording on process %d\n", current->pid);
                set_thread_flag(TIF_RECORD_REPLAY);
                rtcb = kmalloc(sizeof(rtcb_t), GFP_KERNEL);
                rtcb->sphere = sphere;
                rtcb->thread_id = 1;
                current->rtcb = rtcb;
                replay_thread_create(task_pt_regs(current));
        } else if(cmd == REPLAY_IOC_RESET_SPHERE) {
                spin_lock(&sphere->lock);
                sphere->state = idle;
                spin_unlock(&sphere->lock);
        } else {
                BUG();
                return -EINVAL;
        }

        return 0;
}

static int __init replay_init(void) {
        int idx;
        struct device *dev;

        memset(&replay_fops, 0, sizeof(replay_fops));
        replay_fops.read = replay_read;
        replay_fops.open = replay_open;
        replay_fops.unlocked_ioctl = replay_ioctl;
        replay_fops.release = replay_release;
        replay_major = register_chrdev(0, "replay", &replay_fops);
        if(replay_major < 0) {
                printk("could not register replay char device\n");
                BUG();
        }

        replay_class = class_create(THIS_MODULE, "replay");
        if(IS_ERR(replay_class)) {
                printk(KERN_ERR "could not create replay class.\n");
                BUG();
        } else {
                printk(KERN_INFO "************* replay: version %s, Sam King, replay_major = %d\n", 
                       REPLAY_VERSION, replay_major);
                for(idx = 0; idx < NUM_REPLAY_MINOR; idx++) {
                        dev = device_create(replay_class, NULL, MKDEV(replay_major, idx), 
                                            NULL, "replay%d", idx);
                        if(IS_ERR(dev)) {
                                printk(KERN_CRIT "************* replay module could not create device\n");
                        } else {
                                printk(KERN_INFO "created replay driver replay%d\n", idx);
                        }
                }
        }

	return 0;
}

static void __exit replay_exit(void) {
        int idx;
        printk(KERN_INFO "exiting replay module\n");

        if(!IS_ERR(replay_class)) {
                for(idx = 0; idx < NUM_REPLAY_MINOR; idx++)
                        device_destroy(replay_class, MKDEV(replay_major, idx));
                class_destroy(replay_class);
        }

        if(replay_major >= 0) {
                unregister_chrdev(replay_major, "replay");
        }

        printk(KERN_INFO "done exiting replay module\n");
}

module_init(replay_init);
module_exit(replay_exit);

MODULE_AUTHOR("Sam King");
MODULE_DESCRIPTION("Provides control of replay hardware.");
MODULE_LICENSE("BSD");
MODULE_VERSION(REPLAY_VERSION);

/*********************************** Helpers for logging **************************************/

static int record_header_locked(replay_sphere_t *sphere, replay_event_t event, 
                                uint32_t thread_id, struct pt_regs *regs) {
        int ret;
        uint32_t type = (uint32_t) event;

        ret = kfifo_in(&sphere->fifo, &type, sizeof(type));
        if(ret != sizeof(type)) return -1;
        ret = kfifo_in(&sphere->fifo, &thread_id, sizeof(thread_id));
        if(ret != sizeof(thread_id)) return -1;
        ret = kfifo_in(&sphere->fifo, regs, sizeof(*regs));
        if(ret != sizeof(*regs)) return -1;

        return 0;
}


static void record_header(replay_sphere_t *sphere, replay_event_t event, uint32_t thread_id,
                          struct pt_regs *regs) {
        int ret;

        spin_lock(&sphere->lock);
        ret = record_header_locked(sphere, event, thread_id, regs);
        spin_unlock(&sphere->lock);

        // we should be able to avoid these if there is no one 
        // waiting, but I am assuming that the wake up
        // handler handles this reasonable efficiently
        wake_up_interruptible(&sphere->wait);

        if(ret)
                BUG();
}

/**********************************************************************************************/

/*********************************** Callbacks from kernel ************************************/
void replay_syscall_enter(struct pt_regs *regs) {        
        if(current->rtcb == NULL)
                BUG();

        record_header(current->rtcb->sphere, syscall_enter_event, 
                      current->rtcb->thread_id, regs);
}

void replay_syscall_exit(struct pt_regs *regs) {
        if(current->rtcb == NULL)
                BUG();

        record_header(current->rtcb->sphere, syscall_exit_event, 
                      current->rtcb->thread_id, regs);
}

void replay_thread_create(struct pt_regs *regs) {
        if(current->rtcb == NULL)
                BUG();

        atomic_inc(&current->rtcb->sphere->num_threads);

        record_header(current->rtcb->sphere, thread_create_event, 
                      current->rtcb->thread_id, regs);
}

void replay_thread_exit(struct pt_regs *regs) {
        rtcb_t *rtcb = current->rtcb;
        if(rtcb == NULL)
                BUG();

        if(atomic_dec_return(&rtcb->sphere->num_threads) < 0)
                BUG();

        record_header(rtcb->sphere, thread_exit_event, 
                      rtcb->thread_id, regs);
        

        current->rtcb = NULL;
        clear_thread_flag(TIF_RECORD_REPLAY);

        spin_lock(&rtcb->sphere->lock);
        rtcb->sphere->state = done;
        spin_unlock(&rtcb->sphere->lock);
        wake_up_interruptible(&rtcb->sphere->wait);

        kfree(rtcb);
}

/**********************************************************************************************/
