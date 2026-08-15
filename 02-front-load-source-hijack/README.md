# 02 — Front-Load Source-Hijack

**When you can't put the chain at the return offset: place it at payload offset 0.**

Sometimes the classic "chain right after the overflow offset" placement doesn't
survive. In real targets the vulnerable routine's *output path* runs one or more
`memcpy`s **after** the overflow, and those copies clobber the stack right past
the saved return address — leaving only a handful of usable slots (or none).

The trick — **front-load** — flips it: if one of those output copies takes its
**source from the front of the response you sent**, then whatever you put at
response offset 0 lands on the saved RIP. So you place the ROP chain at
**payload offset 0**, and the target's own copy installs it for you.

> Original, vendor-neutral demo. Same planted gadgets as [01](../01-single-socket-reverse-stager/).

## The mechanism here

`read_server_blob()` in `src/vuln_client2.c`:

```c
recv_all(fd, buf, len);                    // len kept short: buf never reaches RIP
void *rbp = __builtin_frame_address(0);
memcpy((char*)rbp + 8, buf, front * 8);    // [rbp+8] = saved RIP  <-- source = buf[0..]
```

The **only** thing that controls RIP is `buf[0..]` (the response front). A chain
placed at the classic return offset never runs — the formatter overwrites RIP
with your padding. A chain placed at **offset 0** runs. There is nothing to
"find": no return offset, just a front-loaded chain.

## Exploit

`exploit/evil_server2.py` sends the **same single-socket staged chain as 01**
(socket leak → `recv` stage-2 → pivot → `system`), but at payload offset 0, and
tells the formatter how many slots to hijack:

```
header = [4B body length][4B front = slot count]
body   = <ROP chain>          # at offset 0 — front-loaded
```

Everything downstream is identical to 01. Verified end-to-end (`uid=0` under
full ASLR), both a marker payload and a real `/bin/sh` over the reused socket.

## Run

```bash
# Apple Silicon: colima start --arch x86_64
./run.sh
```

```
[srv] socket leak -> libc base=0x...
MODE=marker → uid=0(root) ...
MODE=shell  → uid=0(root) ... SHELL_OK
[*] both modes passed.
```

## How this maps to a real target

Here the source-hijack is a single explicit `memcpy` for clarity. In the wild it
is usually incidental: an output/formatting routine that copies a
server-controlled-length region whose source happens to be (part of) the
response you control. The tell is a crash where **RIP equals your payload's first
bytes** rather than the bytes at the return offset — that's the cue to
front-load. See [`../references.md`](../references.md).
