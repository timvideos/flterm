TARGETS=flterm byteswap
CC=gcc
RM ?= rm -f
PREFIX ?= /usr/local
DESTDIR ?=

all: $(TARGETS)

%: %.c
	$(CC) -O2 -Wall -I. -s -o $@ $<

install: flterm
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 -t $(DESTDIR)$(PREFIX)/bin $^

.PHONY: all clean install

clean:
	$(RM) $(TARGETS)
