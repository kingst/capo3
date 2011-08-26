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
        chunk_t chunk;
        int ret, idx;

        if(argc >= 3) {
                fprintf(stderr, "Usage %s: [chunk.log]\n", argv[0]);
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

        while(read_chunk(STDIN_FILENO, &chunk)) {
                printf("processor id = %u\n", chunk.processor_id);
                printf("thread id    = %u\n", chunk.thread_id);
                printf("inst count   = %u\n", chunk.inst_count);
                printf("succ vec     =");
                for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                        printf(" 0x%02x", chunk.succ_vec[idx]);
                }
                printf("\n");

                printf("pred vec     =");
                for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                        printf(" 0x%02x", chunk.pred_vec[idx]);
                }
                printf("\n");

                printf("ip           = 0x%p\n", (void *) chunk.ip);
        }
        
        return 0;
}
