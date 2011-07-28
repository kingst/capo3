EXE = record replay test

all: $(EXE)

CC = g++
CFLAGS = -g -W -Wall -I ../linux-3.0/arch/x86/include
LDFLAGS = -static

SHARED_OBJS = util.o
LOBJS = record.o $(SHARED_OBJS)
ROBJS = replay.o $(SHARED_OBJS)
TOBJS = test.o

OBJS = $(ROBJS) $(LOBJS) $(TOBJS)

-include $(OBJS:.o=.d)

test: $(TOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(TOBJS)

replay: $(ROBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(ROBJS)

record: $(LOBJS)
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(LOBJS)

%.d: %.cpp
	@echo "Calculating dependencies of $<..."
	@set -e; $(CC) -MM $(CFLAGS) $< \
		| sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; 
	@[ -s $@ ] || rm -f $@

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXE) *.o *~ core.* *.d core
