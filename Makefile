OBJS = src/router/main.o src/router/ctx.o src/router/log.o src/router/pox.o src/router/router.o \
       src/router/arp.o src/router/pcap.o src/router/utils.o src/router/simclist.o
DEPS = $(OBJS:.o=.d)
CC = gcc
CFLAGS = -g3 -Wall -fpic -std=gnu99 -MMD -MP
BIN = ./chirouter
LDLIBS = -lm -pthread

.PHONY: all clean tests grade

all: $(BIN)
	
$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o$(BIN) $(LDLIBS)
	
%.d: %.c

clean:
	-rm -f $(OBJS) $(BIN) src/*.d
