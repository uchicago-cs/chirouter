OBJS = src/c/main.o src/c/server.o src/c/ctx.o src/c/log.o src/c/router.o \
       src/c/arp.o src/c/utils.o src/c/pcap.o
DEPS = $(OBJS:.o=.d)
CC = gcc
CFLAGS = -g3 -Wall -fpic -std=gnu99 -MMD -MP
BIN = ./chirouter
LDLIBS = -lm -pthread

.PHONY: all clean

all: $(BIN)
	
$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o$(BIN) $(LDLIBS)
	
clean:
	-rm -f $(OBJS) $(BIN) $(DEPS)

-include $(DEPS)