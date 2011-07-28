#ifndef __UTIL_H__
#define __UTIL_H__

#include <unistd.h>
#include <sys/ioctl.h>

#include <stdint.h>

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    /* arguments: non interrupts/non tracing syscalls only save upto here*/
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    /* end of arguments */
    /* cpu exception frame or undefined */
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
    /* top of stack page */
};



#include <asm/replay.h>

pid_t startChild(int replayFd, char *argv[], char *envp[]);

#endif
