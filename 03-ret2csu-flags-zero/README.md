# 03 — ret2csu + flags=0

**Calling `send`/`recv` by ROP when you have no `pop rdx` and no `pop rcx`.**

`send()`/`recv()` are 4-argument: `send(fd, buf, len, flags)` → `rdi, rsi, rdx,
rcx`. Two things bite you when you drive them from a ROP chain on a sparse
gadget set:

1. **flags (`%rcx`)** — a stray value (e.g. `MSG_DONTWAIT`) makes the call fail
   with `EAGAIN`. There's often no clean `pop rcx`.
2. **len (`%rdx`)** — there's often no `pop rdx` either.

This lab recovers both the way real exploits do:

- **flags = 0** comes from a real wrapper. `net_send()`/`net_recv()` just call
  `send(fd,buf,n,0)` / `recv(fd,buf,n,0)`; the `0` is baked into a proper
  function frame. We reach them through a fixed function-pointer table `fnptr[]`
  — exactly how `__libc_csu_init` calls `init_array` entries.
- **len (`%rdx`)** comes from **ret2csu**. `__libc_csu_init` contains:

  ```
  mov r14, rdx ; mov r13, rsi ; mov r12d, edi ; call [r15+rbx*8]
  ...
  add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
  ```

  so `r12=fd(edi)`, `r13=buf(rsi)`, `r14=len(rdx)`, `r15=&fnptr`, `rbx=index`.

> ### Why Ubuntu 20.04
> `__libc_csu_init` was **removed in glibc 2.34** (Ubuntu 22.04+). This lab builds
> on **Ubuntu 20.04 (glibc 2.31)**, which still ships it — otherwise ret2csu has
> no gadget. That version dependency is itself the lesson: on a modern target you
> would hunt for a different `mov ?, rdx ; call` gadget instead.

## The chain

```
ret2csu:  net_send(3, send@got, 8)   -> socket leak of libc 'send'   (rdx=8 via r14)
ret2csu:  net_recv(3, STAGE2, 0x100)  -> pull stage-2 over same socket (rdx=0x100)
pop rsp ; STAGE2                       -> pivot
STAGE2:   pop rdi ; &cmd ; system      -> ret2libc
```

Each `ret2csu` step jumps to the csu POP gadget (loads `rbx,rbp,r12..r15`),
returns into the csu MOV/CALL gadget (loads `rdi/rsi/rdx`, calls
`fnptr[rbx]`), then the loop exits and the `add rsp,8 ; pop x6 ; ret` epilogue
consumes 7 slots before returning to the next step. The `pop rdi` / `pop rsp` /
`ret` used for the final stage-2 are planted (as in 01/02) to keep the focus on
ret2csu + the flags=0 path.

The single-socket leak→stage-2→pivot→`system` structure is identical to
[01](../01-single-socket-reverse-stager/). Verified end-to-end (`uid=0` under
full ASLR), both a marker payload and a real `/bin/sh` over the reused socket.

## Run

```bash
# Apple Silicon: colima start --arch x86_64
./run.sh
```

```
[srv] socket leak (ret2csu send) -> libc base=0x...
MODE=marker → uid=0(root) ...
MODE=shell  → uid=0(root) ... SHELL_OK
[*] both modes passed.
```

See [`../references.md`](../references.md) for ret2csu background (ROP Emporium
has a dedicated `ret2csu` challenge).
