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
** Copyright (C) Sam King
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

#include "util.h"

#include <assert.h>

void startRecording(int replayFd) {
    int ret = ioctl(replayFd, REPLAY_IOC_START_RECORDING, 0);
    assert(ret == 0);
}

void startReplaying(int replayFd) {
    int ret = ioctl(replayFd, REPLAY_IOC_START_REPLAYING, 0);
    assert(ret == 0);
}

pid_t startChild(int replayFd, char *argv[], char *envp[], int rec) {
    pid_t pid;

    pid = fork();
    if(pid == 0) {
        dup2(STDERR_FILENO, STDOUT_FILENO);
        if(rec) {
            startRecording(replayFd);        
        } else {
            startReplaying(replayFd);
        }
        execve(argv[0], argv, envp);
        assert(false);
    }

    return pid;
}

char *readString(void) {
    char *str;
    int32_t len;
    int ret;

    ret = read(STDIN_FILENO, &len, sizeof(len));
    assert(ret == sizeof(len));

    str = new char[len+1];
    str[len] = '\0';

    ret = read(STDIN_FILENO, str, len);
    assert(ret == len);

    return str;
}

uint64_t readUInt64() {
    int ret;
    uint64_t u;;

    ret = read(STDIN_FILENO, &u, sizeof(u));
    assert(ret == sizeof(u));

    return u;
}

// just throw away these results
char *readBuffer(void) {
    char *str;
    uint64_t to_addr;

    to_addr = readUInt64();
    str = readString();
    delete [] str;
    
    return NULL;
}

int32_t readInt32() {
    int ret;
    int32_t i;

    ret = read(STDIN_FILENO, &i, sizeof(i));
    assert(ret == sizeof(i));

    return i;
}

struct execve_data *readExecveData(void) {
    int32_t idx;
    struct execve_data *e = new struct execve_data;

    e->fileName = readString();
    
    e->argc = readInt32();
    e->argv = new char *[e->argc+1];
    e->argv[e->argc] = NULL;
    for(idx = 0; idx < e->argc; idx++) {
        e->argv[idx] = readString();
    }

    e->envc = readInt32();
    e->envp = new char *[e->envc+1];
    e->envp[e->envc] = NULL;
    for(idx = 0; idx < e->envc; idx++) {
        e->envp[idx] = readString();
    }

    return e;
}
