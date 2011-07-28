#ifndef __UTIL_H__
#define __UTIL_H__

#include <unistd.h>
#include <sys/ioctl.h>

#include <asm/replay.h>

pid_t startChild(int replayFd, char *argv[], char *envp[]);

#endif
