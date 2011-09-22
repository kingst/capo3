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

#include <map>
#include <list>

extern "C" {
#include "util.h"
}

using namespace std;


int main(int argc, char *argv[]) {
        chunk_t *chunk;
        int idx;
        int fd;
        list<chunk_t *> chunk_list;

        if(argc != 2) {
                fprintf(stderr, "Usage %s: chunk_log_output < chunk.log\n", argv[0]);
                return 0;
        }

        fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0600);
        if(fd < 0) {
                fprintf(stderr, "could not open file %s\n", argv[1]);
                return 0;
        }

        // read number of processors
        int num_procs = read_num_procs(STDIN_FILENO);
        if (num_procs > NUM_CHUNK_PROC) {
                fprintf(stderr, "chunks log contains more than %d processors\n", NUM_CHUNK_PROC);
                return 0;
        }

        // read chunks
        chunk = new chunk_t;
        while(read_chunk(STDIN_FILENO, chunk, num_procs)) {
                fprintf(stderr,"processor id = %u\n", chunk->processor_id);
                fprintf(stderr,"thread id    = %u\n", chunk->thread_id);
                fprintf(stderr,"inst count   = %u\n", chunk->inst_count);
                fprintf(stderr,"succ vec     =");
                for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                        fprintf(stderr," 0x%02x", chunk->succ_vec[idx]);
                }
                fprintf(stderr,"\n");

                fprintf(stderr,"pred vec     =");
                for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
                        fprintf(stderr," 0x%02x", chunk->pred_vec[idx]);
                }
                fprintf(stderr,"\n");

                fprintf(stderr,"ip           = 0x%p\n", (void *) chunk->ip);

                chunk_list.insert(chunk_list.end(), chunk);
                chunk = new chunk_t;
        }
        
        list<chunk_t *>::iterator list_iter;
        map<uint32_t, chunk_t *> last_chunk;

        // first fill in any zero ip values with the proper IP
        for(list_iter = chunk_list.begin(); list_iter != chunk_list.end(); list_iter++) {
                chunk = *list_iter;
                if(last_chunk.find(chunk->thread_id) != last_chunk.end()) {
                        //assert(chunk->ip != 0);
                        //assert(chunk->inst_count != 0);
                        assert(last_chunk[chunk->thread_id]->ip == 0);
                        assert(last_chunk[chunk->thread_id]->inst_count == 0);
                                
                        last_chunk[chunk->thread_id]->ip = chunk->ip;
                        last_chunk.erase(chunk->thread_id);
                } else if(chunk->ip == 0) {
                        assert(chunk->inst_count == 0);

                        last_chunk[chunk->thread_id] = chunk;
                }
        }

        last_chunk.clear();
        assert(last_chunk.size() == 0);

        // push the beginning ip for a chunk back to the previous chunk
        for(list_iter = chunk_list.begin(); list_iter != chunk_list.end(); list_iter++) {
                chunk = *list_iter;

                if(last_chunk.find(chunk->thread_id) != last_chunk.end()) {
                        last_chunk[chunk->thread_id]->ip = chunk->ip;
                }
                last_chunk[chunk->thread_id] = chunk;
        }

        map<uint32_t, chunk_t *>::iterator iter;
        // set the ip to 1 for the last chunk in each thread
        for(iter = last_chunk.begin(); iter != last_chunk.end(); iter++) {
                iter->second->ip = 1;
        }

        // write it out
        for(list_iter = chunk_list.begin(); list_iter != chunk_list.end(); list_iter++) {
                chunk = *list_iter;
                write_bytes(fd, chunk, sizeof(*chunk));
        }


        return 0;
}
