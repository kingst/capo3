#ifndef __UTIL_H__
#define __UTIL_H__

#include <unistd.h>
#include <sys/ioctl.h>

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING _IO(REPLAY_IOC_MAGIC, 1)

pid_t startChild(int replayFd, char *argv[], char *envp[]);

#endif
