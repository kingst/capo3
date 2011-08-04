#include <iostream>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

using namespace std;

int main(void) {
        int status;
        long low, high;
        __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high));
        cout << "rdtsc = " << high << " " << low << endl;
        cout << "Hello world!" << endl;
        
        if(fork() == 0) {
                execl("/bin/busybox","tar", "-xvf", "tmp.tar", NULL);
                assert(false);
        }
        
        wait(&status);
        
        return 0;
}
