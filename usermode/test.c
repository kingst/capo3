#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

#include <signal.h>

void handler(int signo) {
        printf("signo = %d\n", signo);
}

int main(void) {
        int status;
        long low, high;
        __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
        printf("rdtsc = %ld %ld\n", high, low);

        //signal(SIGCHLD, handler);

        printf("parent pid = %d\n", getpid());
        if(fork() == 0) {
                printf("child pid = %d\n", getpid());
                execl("/bin/busybox","tar", "-xvf", "tmp.tar", NULL);
                assert(0);
        }
        
        int ret = wait(&status);
        printf("wait ret = %d\n", ret);

        return 0;
}
