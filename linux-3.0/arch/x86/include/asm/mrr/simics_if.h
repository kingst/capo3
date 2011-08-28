#ifndef _ASM_X86_SIMICS_IF_H
#define _ASM_X86_SIMICS_IF_H

#include "mrrhw_if.h"

////////////////////////////////////////////////////////////////////////////////
// magic call stubs
////////////////////////////////////////////////////////////////////////////////

#ifdef CONFIG_SIMICS

/*
 * Simics magic instruction
 */
#define __MAGIC "xchg %%bx, %%bx ;"

/*
 * Magic function with one argument
 * Pass the magic function argument in 'reax'
 * Return value (if any) in '%rax'
 */
inline static void *my_magic_1(void *a) {

    void *ret;

    asm volatile (
        __MAGIC
        : "=a"(ret)     // output
        : "a"(a)        // input
    );

    return ret;
}

/*
 * Magic function with two arguments
 * Pass the magic function argument in '%rax' and '%rcx'
 * Return value (if any) in '%rax'
 */
inline static void *my_magic_2(void *a, void *c) {

    void *ret;

    asm volatile (
        __MAGIC
        : "=a"(ret)             // output
        : "a"(a), "c"(c)        // input
    );

    return ret;
}

/*
 * Magic function with three arguments
 * Pass the magic function argument in '%rax', '%rcx', and '%rdx'
 * Return value (if any) in '%rax'
 */
inline static void *my_magic_3(void *a, void *c, void *d) {

    void *ret;

    asm volatile (
        __MAGIC
        : "=a"(ret)                 // output
        : "a"(a), "c"(c), "d"(d)    // input
    );

    return ret;
}
#else

#define my_magic_1(nthg)                ((void) 0)
#define my_magic_2(nthg,nthg1)          ((void) 0)
#define my_magic_3(nthg,nthg1,nthg2)    ((void) 0)

#endif // CONFIG_SIMICS

#define my_magic(n)                     my_magic_1(n)
#define my_sim_break()                  my_magic((void*)(unsigned long)MRR_MARKER_BREAK_SIM)
#define my_magic_message(msg)           my_magic_2((void*)(unsigned long)MRR_MARKER_MESSAGE,(void*)(msg))
#define my_magic_message_int(msg,arg)   my_magic_3((void*)(unsigned long)MRR_MARKER_MESSAGE_INT,(void*)(msg),(void*)(unsigned long)(arg))
#define my_magic_app_in()               my_magic((void*)(unsigned long)MRR_MARKER_APP_IN)
#define my_magic_app_out()              my_magic((void*)(unsigned long)MRR_MARKER_APP_OUT)
#define my_magic_stats_reset()          my_magic((void*)(unsigned long)MRR_MARKER_STATS_RESET)

#endif /* _ASM_X86_SIMICS_IF_H */
