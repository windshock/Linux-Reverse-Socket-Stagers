CC      ?= gcc
HARDEN   = -no-pie -fno-stack-protector -fcf-protection=none -Wl,-z,relro,-z,lazy
CFLAGS  ?= -O0 -g -w

all: vuln_client3

vuln_client3: vuln_client3.c
	$(CC) $(CFLAGS) $(HARDEN) -o $@ $<

clean:
	rm -f vuln_client3 core core.*

.PHONY: all clean
