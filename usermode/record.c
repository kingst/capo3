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

void recordString(char *s) {
        int ret;
        int32_t len;

        len = strlen(s);
        ret = write(STDOUT_FILENO, &len, sizeof(len));
        assert(ret == sizeof(len));

        ret = write(STDOUT_FILENO, s, len);
        assert(ret == len);
}

void recordStringArray(char *array[]) {
        int32_t idx, count = 0;

        while(array[count] != NULL)
                count++;

        int ret = write(STDOUT_FILENO, &count, sizeof(count));
        assert(ret == sizeof(count));
        for(idx = 0; idx < count; idx++) {
                recordString(array[idx]);
        }

}

void recordExecve(char *fileName, char *argv[], char *envp[]) {
        replay_header_t header;

        memset(&header, 0, sizeof(header));

        header.type = execve_event;
        int ret = write(STDOUT_FILENO, &header, sizeof(header));
        assert(ret == sizeof(header));

        recordString(fileName);
        recordStringArray(argv);
        recordStringArray(envp);
}

int main(int argc, char *argv[], char *envp[]) {
        unsigned char buf[4096];
        int replayFd, ret, bytesWritten, status;

        if(argc < 2) {
                fprintf(stderr, "Usage %s: exe_path [arguments] > replay.log\n", argv[0]);
                return 1;
        }

        replayFd = open("/dev/replay0", O_RDONLY | O_CLOEXEC);
        if(replayFd < 0) {
                fprintf(stderr, "could not open /dev/replay device\n");
                return 1;
        }
        ret = ioctl(replayFd, REPLAY_IOC_RESET_SPHERE, 0);
        assert(ret == 0);

        argv++;
        recordExecve(argv[0], argv, envp);
        startChild(replayFd, argv, envp, 1);

        while((ret = read(replayFd, buf, sizeof(buf))) > 0) {
                bytesWritten = write(STDOUT_FILENO, buf, ret);
                assert(bytesWritten == ret);
        }

        assert(ret == 0);

        while(wait(&status) != -1)
                ;

        return 0;
}
