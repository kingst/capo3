#ifndef _ASM_X86_SIMICS_IF_H
#define _ASM_X86_SIMICS_IF_H

////////////////////////////////////////////////////////////////////////////////
// Markers used for magic calls
////////////////////////////////////////////////////////////////////////////////

#define MRR_MARKERS_BEGIN 			0xB5000000

#define MRR_MARKER_BREAK_SIM 		(MRR_MARKERS_BEGIN + 0x1)
#define	MRR_MARKER_MESSAGE 			(MRR_MARKERS_BEGIN + 0x2)
#define MRR_MARKER_MESSAGE_INT		(MRR_MARKERS_BEGIN + 0x3)

#define MRR_SYS_MARKERS_BEGIN 		(MRR_MARKERS_BEGIN + 0x800000)
#define MRR_MARKERS_END 			(MRR_MARKERS_BEGIN + 0xFFFFFF)

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

#define my_magic(n) my_magic_1(n)
#define my_sim_break()                  my_magic((void*)MRR_MARKER_BREAK_SIM)
#define my_magic_message(msg)           my_magic_2((void*)MRR_MARKER_MESSAGE,msg)
#define my_magic_message_int(msg,arg)   my_magic_3((void*)MRR_MARKER_MESSAGE_INT,msg,arg)

#endif /* _ASM_X86_SIMICS_IF_H */
