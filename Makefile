# z-fileinfo Makefile

CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2

PREFIX  ?= /usr/local/bin

.PHONY: all clean install

all: z-fileinfo z-fileinfo-mcp

z-fileinfo: z-fileinfo.c
	$(CC) $(CFLAGS) -o $@ $<

# MCP binary is the same source compiled with a different argv[0] identity;
# a symlink is sufficient but a hard copy works on all filesystems.
z-fileinfo-mcp: z-fileinfo
	cp -f z-fileinfo z-fileinfo-mcp

install: all
	install -d $(PREFIX)
	install -m 755 z-fileinfo $(PREFIX)/z-fileinfo
	install -m 755 z-fileinfo-mcp $(PREFIX)/z-fileinfo-mcp

clean:
	rm -f z-fileinfo z-fileinfo-mcp
