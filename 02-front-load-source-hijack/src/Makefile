CC      ?= gcc
HARDEN   = -no-pie -fno-stack-protector -fcf-protection=none -Wl,-z,relro,-z,lazy
CFLAGS  ?= -O0 -g -w

all: vuln_client2

vuln_client2: vuln_client2.c
	$(CC) $(CFLAGS) $(HARDEN) -o $@ $<

clean:
	rm -f vuln_client2 core core.*

.PHONY: all clean
