#include "util.h"

#include <assert.h>

void startRecording(int replayFd) {
    int ret = ioctl(replayFd, REPLAY_IOC_START_RECORDING, 0);
}

pid_t startChild(int replayFd, char *argv[], char *envp[]) {
    pid_t pid;

    pid = fork();
    if(pid == 0) {
        dup2(STDERR_FILENO, STDOUT_FILENO);
        startRecording(replayFd);        
        execve(argv[0], argv, envp);
        assert(false);
    }

    return pid;
}
