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

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "util.h"

using namespace std;

int main(void) {
    replay_header_t header;
    int ret;
    struct execve_data *e;

    while((ret = read(STDIN_FILENO, &header, sizeof(header))) > 0) {
        assert(ret == sizeof(header));

        if(header.type == syscall_enter_event) {
            cout << "syscall_enter_event, syscall = " << header.regs.orig_rax << " arg1 = " << header.regs.rdi << endl;
        } else if(header.type == syscall_exit_event) {
            cout << "syscall_exit_event, ret = " << header.regs.rax << endl;
        } else if(header.type == thread_create_event) {
            cout << "thread_create_event" << endl;
        } else if(header.type == thread_exit_event) {
            cout << "thread_exit_event" << endl;
        } else if(header.type == instruction_event) {
            cout << "instruction_event" << endl;
        } else if(header.type == execve_event) {
            cout << "execve_event" << endl;            
            e = readExecveData();
        } else if(header.type == copy_to_user_event) {
            cout << "copy to user" << endl;
            readBuffer();
        } else {
            assert(false);
        }

    }

    assert(ret == 0);
    
    return 0;
}
