#ifndef __UTIL_H__
#define __UTIL_H__

#include <unistd.h>
#include <sys/ioctl.h>

#include <stdint.h>

#ifdef __x86_64__
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

static inline unsigned long regs_syscallno(struct pt_regs *regs) {return regs->orig_rax;}
static inline unsigned long regs_return(struct pt_regs *regs) {return regs->rax;}
static inline unsigned long regs_first(struct pt_regs *regs) {return regs->rdi;}
static inline unsigned long regs_ip(struct pt_regs *regs) {return regs->rip;}

#elif __i386__

struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

static inline unsigned long regs_syscallno(struct pt_regs *regs) {return regs->orig_eax;}
static inline unsigned long regs_return(struct pt_regs *regs) {return regs->eax;}
static inline unsigned long regs_first(struct pt_regs *regs) {return regs->ebx;}
static inline unsigned long regs_ip(struct pt_regs *regs) {return regs->eip;}

#else

#error "architecture not supported"

#endif


#include "../linux-3.0/arch/x86/include/asm/replay.h"

typedef enum {START_REPLAY, START_RECORD, START_CHUNKED_REPLAY} start_t;
pid_t startChild(int replayFd, char *argv[], char *envp[], start_t type);

struct execve_data {
    char *fileName;
    int32_t argc;
    int32_t envc;
    char **argv;
    char **envp;
};

struct execve_data *readExecveData(void);
char *readBuffer(void);
int read_chunk(int chunkFd, chunk_t *chunk);
void write_bytes(int fd, void *tbuf, int len);

#endif
