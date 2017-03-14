TARGETS=flterm byteswap
CC=gcc
RM ?= rm -f
PREFIX ?= /usr/local
DESTDIR ?=

all: $(TARGETS)

GIT_VERSION=$(shell git describe)

%: %.c
	$(CC) -O2 -Wall -DGIT_VERSION='"$(GIT_VERSION)"' -I. -s -o $@ $<

install: flterm
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 -t $(DESTDIR)$(PREFIX)/bin $^

.PHONY: all clean install

clean:
	$(RM) $(TARGETS)
