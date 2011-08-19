EXE = record replay test scan_log

all: $(EXE)

CC = gcc
CFLAGS = -g -W -Wall
LDFLAGS = -static

SHARED_OBJS = util.o
LOBJS = record.o $(SHARED_OBJS)
ROBJS = replay.o $(SHARED_OBJS)
TOBJS = test.o
SOBJS = scan_log.o $(SHARED_OBJS)

OBJS = $(ROBJS) $(LOBJS) $(TOBJS) $(SOBJS)

-include $(OBJS:.o=.d)

test: $(TOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(TOBJS)

scan_log: $(SOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(SOBJS)

replay: $(ROBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(ROBJS)

record: $(LOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(LOBJS)

%.d: %.c
	@echo "Calculating dependencies of $<..."
	@set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; 
	@[ -s $@ ] || rm -f $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXE) *.o *~ core.* *.d core
