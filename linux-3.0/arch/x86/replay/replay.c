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

#define LOG_BUFFER_SIZE (8*1024*1024)

typedef enum {none, recording, replaying} replay_state_t;

typedef struct replay_sphere {
        replay_state_t state;
        unsigned char *fifo_buffer;
        spinlock_t lock;
        struct kfifo fifo;
        wait_queue_head_t wait;
        atomic_t count;
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

                sphere->state = none;
                sphere->fifo_buffer = vmalloc(LOG_BUFFER_SIZE);
                if(sphere->fifo_buffer == NULL) {
                        kfree(sphere);
                        BUG();
                        return -ENOMEM;
                }

                spin_lock_init(&sphere->lock);
                kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
                init_waitqueue_head(&sphere->wait);
                atomic_set(&sphere->count, 0);
                inode->i_private = sphere;
        } else {
                sphere = (replay_sphere_t *) inode->i_private;
        }

        atomic_inc(&sphere->count);
        file->private_data = sphere;

	return 0;
}

static int replay_release(struct inode *inode, struct file *file) {
        replay_sphere_t *sphere = file->private_data;

        if(inode->i_private != file->private_data)
                BUG();

        spin_lock(&sphere->lock);
        sphere->state = none;
        if(atomic_dec_return(&sphere->count) < 0)
                BUG();
        if(kfifo_len(&sphere->fifo) > 0)
                printk(KERN_CRIT "Warning, replay sphere fifo still has data....\n");
        kfifo_init(&sphere->fifo, sphere->fifo_buffer, LOG_BUFFER_SIZE);
        spin_unlock(&sphere->lock);

	return 0;
}

static int kfifo_has_data(replay_sphere_t *sphere) {
        int len;

        spin_lock(&sphere->lock);
        len = kfifo_len(&sphere->fifo);
        spin_unlock(&sphere->lock);

        return len > 0;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        int ret = 0;
        replay_sphere_t *sphere;

        sphere = (replay_sphere_t *) file->private_data;
        if(sphere == NULL) {
                BUG();
                return -EINVAL;
        }

        ret = wait_event_interruptible(sphere->wait, kfifo_has_data(sphere));

        if(ret == -ERESTARTSYS)
                return ret;

        return 0;
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
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
                for(idx = 0; idx < 4; idx++) {
                        dev = device_create(replay_class, NULL, MKDEV(replay_major, idx), NULL, "replay%d", idx);
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
        printk(KERN_INFO "exiting replay module\n");

        if(!IS_ERR(replay_class)) {
                device_destroy(replay_class, MKDEV(replay_major, 0));
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

/*********************************** Callbacks from kernel ************************************/
void replay_syscall_enter(struct pt_regs *regs) {
        static int count=0;

        if(count<100) {
                count++;
                printk(KERN_CRIT "syscall enter\n");
        }
}

void replay_syscall_exit(struct pt_regs *regs) {
        static int count=0;
        if(count<100) {
                count++;
                printk(KERN_CRIT "syscall exit\n");
        }
}

/**********************************************************************************************/
