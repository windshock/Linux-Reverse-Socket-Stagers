# Build the SYNTHETIC demo target as a legacy, hardening-free binary:
#   No PIE / No stack canary / NX on / Partial RELRO (lazy binding)
# so the single-socket reverse-staging technique can be studied end-to-end.
CC      ?= gcc
# -no-pie                 -> fixed code/PLT/GOT/gadget addresses
# -fno-stack-protector    -> no canary (overflow reaches the return address)
# -fcf-protection=none    -> no Intel CET (endbr64/shadow stack) — legacy binary
# -z relro -z lazy        -> Partial RELRO, lazy binding (GOT resolves on call)
HARDEN   = -no-pie -fno-stack-protector -fcf-protection=none -Wl,-z,relro,-z,lazy
CFLAGS  ?= -O0 -g -w

all: vuln_client

vuln_client: vuln_client.c
	$(CC) $(CFLAGS) $(HARDEN) -o $@ $<
	@echo "---- checksec ----"
	@command -v checksec >/dev/null 2>&1 && checksec --file=$@ || \
	  echo "(install 'checksec' to verify: expect No PIE / No canary / NX / Partial RELRO)"

clean:
	rm -f vuln_client core core.*

.PHONY: all clean
