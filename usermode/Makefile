EXE = record replay test scan_log scan_chunk_log fixup_chunk_log

all: $(EXE)

CC = gcc
CPLUSPLUS = g++
CFLAGS = -g -W -Wall
LDFLAGS = -static

SHARED_OBJS = util.o
LOBJS = record.o $(SHARED_OBJS)
ROBJS = replay.o $(SHARED_OBJS)
TOBJS = test.o
SOBJS = scan_log.o $(SHARED_OBJS)
COBJS = scan_chunk_log.o $(SHARED_OBJS)
FOBJS = fixup_chunk_log.o $(SHARED_OBJS)

OBJS = $(ROBJS) $(LOBJS) $(TOBJS) $(SOBJS) $(COBJS) $(FOBJS)

-include $(OBJS:.o=.d)

test: $(TOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(TOBJS)

scan_log: $(SOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(SOBJS)

scan_chunk_log: $(COBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(COBJS)

fixup_chunk_log: $(FOBJS)
	$(CPLUSPLUS) -o $@ $(LDFLAGS) $(CFLAGS) $(FOBJS)

replay: $(ROBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(ROBJS)

record: $(LOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(LOBJS)

%.d: %.c
	@set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; 
	@[ -s $@ ] || rm -f $@

%.d: %.cpp
	@set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; 
	@[ -s $@ ] || rm -f $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CPLUSPLUS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXE) *.o *~ core.* *.d core
