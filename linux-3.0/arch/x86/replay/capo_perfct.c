/*======================================================== 
** University of Illinois/NCSA 
** Open Source License 
**
** Copyright (C) 2011,The Board of Trustees of the University of 
** Illinois. All rights reserved. 
**
** Developed by: 
**
**    Research Group of Professor Sam King in the Department of Computer 
**    Science The University of Illinois at Urbana-Champaign 
**    http://www.cs.uiuc.edu/homes/kingst/Research.html 
**
** Copyright (C) Nathan Dautenhahn
**
** Permission is hereby granted, free of charge, to any person obtaining a 
** copy of this software and associated documentation files (the 
** Software), to deal with the Software without restriction, including 
** without limitation the rights to use, copy, modify, merge, publish, 
** distribute, sublicense, and/or sell copies of the Software, and to 
** permit persons to whom the Software is furnished to do so, subject to 
** the following conditions: 
**
** Redistributions of source code must retain the above copyright notice, 
** this list of conditions and the following disclaimers. 
**
** Redistributions in binary form must reproduce the above copyright 
** notice, this list of conditions and the following disclaimers in the 
** documentation and/or other materials provided with the distribution. 
** Neither the names of Sam King or the University of Illinois, 
** nor the names of its contributors may be used to endorse or promote 
** products derived from this Software without specific prior written 
** permission. 
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
** IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR 
** ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
** SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE. 
**========================================================== 
*/

#include <linux/errno.h>    
#include <linux/types.h>   
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>     
#include <linux/perf_event.h>

#include "asm/capo_perfct.h"

struct perf_event *pevent;

static struct perf_event_attr *attr = NULL;

/*
 * This function sets up the performance counter registers to record. 
 */
int perf_counter_init(void){
        int cpu;
        struct task_struct *tsk = current;
        long raw = 0;

        if(attr == NULL) {
                attr = kmalloc(sizeof(*attr), GFP_KERNEL);
                memset(attr,0,sizeof(*attr));
                attr->type = PERF_TYPE_HARDWARE;
                //attr->type = PERF_TYPE_RAW;
                attr->config = PERF_COUNT_HW_INSTRUCTIONS;
                attr->size = sizeof(*attr);
                attr->sample_period = 0;
                attr->disabled = 0;
                attr->inherit = 0;
                attr->pinned = 1;     //TODO Not sure if we want this set or not yet
                //attr->exclusive = 1;
                attr->freq = 0;
                attr->exclude_user = 0; 
                attr->exclude_kernel = 1;        
                attr->exclude_hv = 1;         
                attr->exclude_idle = 1;      
                attr->inherit_stat = 1;
                //attr->precise_ip = 3;       
                //attr->wakeup_events = 10000;	  // wakeup every n events
        }

        cpu = -1;       // count events for this thread on all cpus

        pevent = perf_event_create_kernel_counter(attr, cpu, tsk, 
                        (perf_overflow_handler_t) capo_overflow_handler);

        if (IS_ERR(pevent)){
                return PTR_ERR(pevent);
        }

        if (pevent->state != PERF_EVENT_STATE_ACTIVE) {
                printk(KERN_CRIT "Failed to enable kernel counter");
                kfree(attr);
                attr=NULL;
                perf_event_release_kernel(pevent);
                return -EBUSY;
        }

        return 0;
}

u64 perf_counter_read(void){
        u64 enabled = 0; u64  running = 0;
        return perf_event_read_value(pevent, &enabled, &running); 
}

void perf_counter_term(void){
        if(attr != NULL) {
                kfree(attr);
                attr=NULL;
                //release the pevent//
                perf_event_release_kernel(pevent);
        }
}

void capo_perf_event_disable(void){
        if(pevent != NULL)
                perf_event_disable(pevent);
}

void capo_perf_event_enable(void){
        if(pevent != NULL) 
                perf_event_enable(pevent);
}
