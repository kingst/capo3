/*
   hostfs for Linux
   Copyright 2001 - 2006 Virtutech AB
   Copyright 2001 SuSE

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
   NON INFRINGEMENT.  See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   $Id: hostfs_host.c,v 1.8 2006/03/31 14:56:52 ekloef Exp $
*/


#include "hostfs_linux.h"

#if !defined(__sparc_v9__)
static volatile void *hostfs_dev_data;
#endif

static void
write_value(uint value)
{
#if defined(__sparc_v9__)
        asm volatile ("wr %0, 0, %%asr31" :: "r"(value));
#else
        writel(value, hostfs_dev_data);
#endif
}

static uint
read_value(void)
{
        uint value;
#if defined(__sparc_v9__)
        asm volatile ("rd %%asr31, %0" : "=r" (value));
#else
        value = readl(hostfs_dev_data);
#endif
        return value;
}

static void
data_to_host(uint *data, int len)
{
        int i;

        for (i = 0; i < len; i++)
                write_value(data[i]);
}

static void
data_from_host(uint *data, int len)
{
        int i;

        for (i = 0; i < len; i++) 
                data[i] = read_value();
}

spinlock_t get_host_data_lock;
spinlock_t hostfs_position_lock;


int
get_host_data(host_func_t func, host_node_t hnode, void *in_buf, void *out_buf)
{
        uint data;

        if (func != host_funcs[func].func)
                printk(DEVICE_NAME " INTERNAL ERROR: host_funcs_t != func\n");

        spin_lock(&get_host_data_lock);

        data = func;
        data_to_host(&data, 1);
        data_to_host(&hnode, 1);
        data_to_host(in_buf, host_funcs[func].out);
        data_from_host(out_buf, host_funcs[func].in);

        spin_unlock(&get_host_data_lock);

        return 0;
}


/* internal function */
int
hf_do_seek(ino_t inode, loff_t off)
{
        struct hf_seek_data odata;
        struct hf_common_data idata;

        SET_HI_LO(odata.off, off);
        get_host_data(hf_Seek, inode, &odata, &idata);
        return idata.sys_error;
}


/*
 * Dynamic configuration support.
 * You can specify simicsfs.phys_addr=0xff00ff00 on the kernel command line, or
 * insmod simicsfs phys_addr=0xff00ff00
 */

#ifdef KERNEL_2_6
# include <linux/moduleparam.h>

#ifdef CONFIG_SIMICSFS_ADDRESS
static char *phys_addr = CONFIG_SIMICSFS_ADDRESS;
#else
static char *phys_addr;
#endif

module_param(phys_addr, charp, 0);
MODULE_PARM_DESC(phys_addr, "Physical address where simicsfs is mapped.");

#endif

int init_host_fs(void) {

    unsigned long long hostfs_dev = HOSTFS_DEV;

    spin_lock_init(&get_host_data_lock);
    spin_lock_init(&hostfs_position_lock);

#ifdef KERNEL_2_6
    if (phys_addr && strcmp(phys_addr, "") != 0)
            hostfs_dev = simple_strtoull(phys_addr, NULL, 0);
#endif

#if defined(__alpha)
    hostfs_dev_data = (void *)phys_to_virt(hostfs_dev);
#elif defined(__i386) || defined(__x86_64__) || defined(__ia64) \
        || defined(__powerpc__) || defined(__arm__) || defined(__mips__) \
        || defined(__m68k__)
# ifdef CONFIG_440
	hostfs_dev_data = (void *)ioremap64(hostfs_dev, 16);
# else
	hostfs_dev_data = (void *)ioremap(hostfs_dev, 16);
# endif
	if (!hostfs_dev_data) {
		printk("hostfs: cannot map 0x%08llx\n", hostfs_dev);
		return -EIO;
	}
	printk(KERN_INFO "Mapping hostfs from p:%08llx to %p\n",
               hostfs_dev, hostfs_dev_data);
#elif defined(__sparc_v9__)
#else
#error "No device mapping for this architecture"
#endif
	return 0;
}
