#include <iostream>

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "util.h"

using namespace std;

int main(int argc, char *argv[], char *envp[]) {
    unsigned char buf[4096];
    int replayFd, ret, bytesWritten;

    if(argc < 2) {
        cerr << "Usage " << argv[0] << ": exe_path [arguments] > replay.log" << endl;
        return 1;
    }

    replayFd = open("/dev/replay0", O_RDONLY | O_CLOEXEC);
    if(replayFd < 0) {
        cerr << "could not open /dev/replay device" << endl;
        return 1;
    }

    startChild(replayFd, argv+1, envp);

    while((ret = read(replayFd, buf, sizeof(buf))) > 0) {
        bytesWritten = write(STDOUT_FILENO, buf, ret);
        assert(bytesWritten == ret);
    }

    assert(ret == 0);

    return 0;
}
