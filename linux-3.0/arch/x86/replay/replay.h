#ifndef __REPLAY_H__
#define __REPLAY_H__

#define REPLAY_IOC_MAGIC 0xf1

#define REPLAY_IOC_START_RECORDING _IO(REPLAY_IOC_MAGIC, 0)
#define REPLAY_IOC_START_REPLAYING _IO(REPLAY_IOC_MAGIC, 1)

#endif