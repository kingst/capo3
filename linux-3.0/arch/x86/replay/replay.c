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

static void replay_syscall_enter(void *ignore, struct pt_regs *regs, long id);
static void replay_syscall_exit(void *ignore, struct pt_regs *regs, long ret);

static struct class *replay_class = NULL;
static struct file_operations replay_fops;
static int replay_major = 0;

#define REPLAY_VERSION	"0.3"

static int replay_open(struct inode *inode, struct file *file) {
        int ret = 0;
	return ret;
}

static int replay_release(struct inode *inode, struct file *file) {
	return 0;
}

static ssize_t replay_read(struct file *file, char __user *buf, size_t count,
                             loff_t *f_pos) {
        return 0;
}

static long replay_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
        return 0;
}

static int __init replay_init(void) {
        int ret;

        memset(&replay_fops, 0, sizeof(replay_fops));
        replay_fops.read = replay_read;
        replay_fops.open = replay_open;
        replay_fops.unlocked_ioctl = replay_ioctl;
        replay_fops.release = replay_release;
        replay_major = register_chrdev(0, "replay", &replay_fops);
        if(replay_major < 0)
                printk("could not register replay char device\n");

        replay_class = class_create(THIS_MODULE, "replay");
        if(IS_ERR(replay_class)) {
                printk(KERN_ERR "could not create replay class.\n");
        } else {
                device_create(replay_class, NULL, MKDEV(replay_major, 0), NULL, "replay");
                printk(KERN_INFO "replay: version %s, Sam King\n", REPLAY_VERSION);
        }

        ret = register_trace_sys_enter(replay_syscall_enter, NULL);
        if(ret) BUG();
        ret = register_trace_sys_exit(replay_syscall_exit, NULL);
        if(ret) BUG();

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

        unregister_trace_sys_enter(replay_syscall_enter, NULL);
        unregister_trace_sys_exit(replay_syscall_exit, NULL);

        printk(KERN_INFO "done exiting replay module\n");
}

module_init(replay_init);
module_exit(replay_exit);

MODULE_AUTHOR("Sam King");
MODULE_DESCRIPTION("Provides control of replay hardware.");
MODULE_LICENSE("BSD");
MODULE_VERSION(REPLAY_VERSION);

/*********************************** Callbacks from kernel ************************************/
static void replay_syscall_enter(void *ignore, struct pt_regs *regs, long id) {
        static int count=0;

        if(count<100) {
                count++;
                printk(KERN_CRIT "syscall enter\n");
        }
}

static void replay_syscall_exit(void *ignore, struct pt_regs *regs, long ret) {
        static int count=0;
        if(count<100) {
                count++;
                printk(KERN_CRIT "syscall exit\n");
        }
}

/**********************************************************************************************/
