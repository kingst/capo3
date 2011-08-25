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

#include <stdio.h>
#include <stdlib.h>

#define __USE_GNU

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>

#include "util.h"

unsigned char readUChar(int fd) {
        unsigned char c;
        int ret;

        ret = read(fd, &c, sizeof(c));
        assert(ret == sizeof(c));

        return c;
}

uint32_t readUInt(int fd) {
        uint32_t c;
        int ret;

        ret = read(fd, &c, sizeof(c));
        assert(ret == sizeof(c));

        return c;
}

unsigned long readULong(int fd) {
        unsigned long c;
        int ret;

        ret = read(fd, &c, sizeof(c));
        assert(ret == sizeof(c));

        return c;
}

void fillSuccPred(chunk_t *chunk, unsigned char succ, unsigned char pred) {
        int idx;
        for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                if(succ & (1<<idx)) {
                        chunk->succ_vec[idx]++;
                }
                if(pred & (1<<idx)) {
                        chunk->pred_vec[idx]++;
                }
        }
}


void handle_chunk_log(int chunkFd) {
        int replayFd;
        unsigned char c, succ, pred;
        chunk_t chunk;
        unsigned char *buf;
        unsigned int bytesWritten;
        int ret;

        replayFd = open("/dev/replay0", O_WRONLY | O_CLOEXEC);
        if(replayFd < 0) {
                fprintf(stderr,"could not open /dev/replay device\n");
                exit(0);
        }
        ret = ioctl(replayFd, REPLAY_IOC_SET_CHUNK_LOG_FD, 0);
        assert(ret == 0);

        memset(&chunk, 0, sizeof(chunk));
        while((ret = read(chunkFd, &c, sizeof(c))) == 1) {
                if(c == 0xff) {
                        succ = readUChar(chunkFd);
                        pred = readUChar(chunkFd);
                        fillSuccPred(&chunk, succ, pred);
                } else {
                        chunk.processor_id = c;
                        chunk.thread_id = readUChar(chunkFd);
                        chunk.inst_count = readUInt(chunkFd);
                        chunk.ip = readULong(chunkFd);
                        succ = readUChar(chunkFd);
                        pred = readUChar(chunkFd);
                        fillSuccPred(&chunk, succ, pred);

                        bytesWritten = 0;
                        buf = (unsigned char *) &chunk;
                        while(bytesWritten < sizeof(chunk)) {
                                ret = write(replayFd, buf+bytesWritten, sizeof(chunk)-bytesWritten);
                                bytesWritten += ret;
                        }
                        memset(&chunk, 0, sizeof(chunk));
                }
        }

}

int main(int argc, char *argv[]) {
        unsigned char buf[4096];
        int replayFd, ret, bytesWritten, status, len;
        replay_header_t header;
        struct execve_data *e;
        int chunkFd = -1;

        if(argc > 2) {
                fprintf(stderr, "Usage %s: [chunk_log] < replay_log\n", argv[0]);
                return 0;
        }

        replayFd = open("/dev/replay0", O_WRONLY | O_CLOEXEC);
        if(replayFd < 0) {
                fprintf(stderr,"could not open /dev/replay device\n");
                return 0;
        }
        ret = ioctl(replayFd, REPLAY_IOC_RESET_SPHERE, 0);
        assert(ret == 0);

        if(argc == 2) {
                chunkFd = open(argv[1], O_RDONLY);
                if(chunkFd < 0) {
                        fprintf(stderr, "Usage %s: [chunk_log] < replay_log\n", argv[0]);
                        return 0;
                }
                if(fork() == 0) {
                        handle_chunk_log(chunkFd);
                        exit(0);
                }
        }

        ret = read(STDIN_FILENO, &header, sizeof(header));
        assert(ret == sizeof(header));
    
        e = readExecveData();
        if(chunkFd < 0) {
                startChild(replayFd, e->argv, e->envp, START_REPLAY);
        } else {
                close(chunkFd);
                chunkFd = -1;
                startChild(replayFd, e->argv, e->envp, START_CHUNKED_REPLAY);
        }

        while((ret = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
                bytesWritten = 0;
                len = ret;
                while(bytesWritten < len) {
                        ret = write(replayFd, buf+bytesWritten, len-bytesWritten);
                        assert(ret > 0);
                        bytesWritten += ret;
                }
        }

        while(wait(&status) != -1)
                ;

        return 1;
}
