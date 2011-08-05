#include <iostream>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

#include <signal.h>

using namespace std;

void handler(int signo) {
        cout << "signo = " << signo << endl;
}

int main(void) {
        int status;
        long low, high;
        __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
        cout << "rdtsc = " << high << " " << low << endl;
        cout << "Hello world!" << endl;

        signal(SIGCHLD, handler);

        if(fork() == 0) {
                execl("/bin/busybox","tar", "-xvf", "tmp.tar", NULL);
                assert(false);
        }
        
        int ret = wait(&status);
        cout << "wait ret = " << ret << endl;

        return 0;
}
