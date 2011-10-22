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
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>

#include "util.h"

int main(int argc, char *argv[]) {
        replay_header_t header;
        int ret;
        struct execve_data *e;

        if(argc >= 3) {
                fprintf(stderr, "Usage %s: [replay.log]\n", argv[0]);
                return 0;
        }

        if(argc == 2) {
                ret = open(argv[1], O_RDONLY);
                if(ret < 0) {
                        fprintf(stderr, "could not open file %s\n", argv[1]);
                        return 0;
                }
                dup2(ret, STDIN_FILENO);
        }
        
        while((ret = read(STDIN_FILENO, &header, sizeof(header))) > 0) {
                assert(ret == sizeof(header));
                printf("%u ", header.thread_id);
                if(header.type == syscall_enter_event) {
                        printf("syscall_enter_event, syscall = %ld arg1 = 0x%08lx ip = 0x%08lx\n",
                               regs_syscallno(&header.regs), 
                               regs_first(&header.regs), 
                               regs_ip(&header.regs));
                } else if(header.type == syscall_exit_event) {
                        printf("syscall_exit_event, syscall = %ld ret = %ld\n",
                               regs_syscallno(&header.regs), regs_return(&header.regs));
                } else if(header.type == thread_create_event) {
                        printf("thread_create_event\n");
                } else if(header.type == thread_exit_event) {
                        printf("thread_exit_event\n");
                } else if(header.type == instruction_event) {
                        printf("instruction_event ip = 0x%08lx\n", regs_ip(&header.regs));
                } else if(header.type == execve_event) {
                        printf("execve_event\n");
                        e = readExecveData();
                } else if(header.type == copy_to_user_event) {
                        printf("copy_to_user\n");
                        readBuffer();
                } else if(header.type == signal_event) {
                        printf("signal\n");
                } else {
                        assert(0);
                }
                
        }
        
        assert(ret == 0);
        
        return 0;
}
