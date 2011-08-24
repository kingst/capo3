#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#define __USE_GNU
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

void print_chunk(chunk_t *chunk) {

    int idx;
    int is_main_entry = (chunk->processor_id != 0xFF);

    if (is_main_entry)
        printf("main entry: ");
    else
        printf("dumm entry: ");

    printf("pred={");    
    for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
        printf("%d, ", chunk->pred_vec[idx]);    
    }
    printf("}");    

    printf("     ");

    printf("succ={");    
    for(idx = 0; idx < NUM_CHUNK_PROC; idx++) {
        printf("%d, ", chunk->succ_vec[idx]);    
    }
    printf("}");    

    if (is_main_entry) {
        printf("     ");    
        printf("cpu=%5d, actor=%5d, inst_count=%6d, ip=%lx", chunk->processor_id, chunk->thread_id, chunk->inst_count, chunk->ip);
    }

    printf("\n");        
}


void handle_chunk_log() {
    unsigned char c, succ, pred;
    chunk_t chunk;

    memset(&chunk, 0, sizeof(chunk));
    while((read(STDIN_FILENO, &c, sizeof(c))) == 1) {
        if(c == 0xff) {
            chunk.processor_id = c;
            succ = readUChar(STDIN_FILENO);
            pred = readUChar(STDIN_FILENO);
            fillSuccPred(&chunk, succ, pred);
        } else {
            chunk.processor_id = c;
            chunk.thread_id = readUChar(STDIN_FILENO);
            chunk.inst_count = readUInt(STDIN_FILENO);
            chunk.ip = readULong(STDIN_FILENO);
            succ = readUChar(STDIN_FILENO);
            pred = readUChar(STDIN_FILENO);
            fillSuccPred(&chunk, succ, pred);
        }        
        print_chunk(&chunk);
        memset(&chunk, 0, sizeof(chunk));
    }

}


int main() {

    // read and print chunk log
    handle_chunk_log();
    return 0;
}


