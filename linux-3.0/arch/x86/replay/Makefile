ifdef CONFIG_RECORD_REPLAY_STATIC
obj-y   :=  rr.o
else
obj-m   :=  rr.o
endif

ifdef CONFIG_RECORD_REPLAY
rr-objs	+=  replay.o sphere.o demux.o
endif

ifdef CONFIG_RR_CHUNKING_PERFCOUNT
rr-objs += capo_perfct.o
endif

ifdef CONFIG_MRR
rr-objs += mrr_if.o
endif
