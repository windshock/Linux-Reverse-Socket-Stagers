# Retrospective: reverse socket staging

The three labs share one constraint: the victim is a client that dials out,
trusts a server response, and must be exploited through that same connection.
The successful pattern is a leak, a blocking stage-2 receive, and a pivot into
writable BSS memory. Full ASLR remains enabled; the binaries are non-PIE,
NX-enabled, partial-RELRO, and built without canaries.

## Lab differences

| Lab | Bug | Main technique | Extra constraint |
|---|---|---|---|
| 01 | unchecked response length into a stack buffer | single-socket leak/recv/pivot | saved RIP offset and stack-space margin |
| 02 | unchecked receive followed by `memcpy(rbp+8, buf, front*8)` | front-load source hijack | chain must start at `buf[0]`; copy must stay short |
| 03 | unchecked response length with sparse gadgets | ret2csu + flags-zero wrappers | glibc 2.31 `__libc_csu_init` and `fnptr[]` |

## What required the most debugging

The socket descriptor is not always 3 under Rosetta or a pty. Scanning
`/proc/<pid>/fd` and retaining an explicit `FD=` override fixed the failure.
The offset probe also cannot rely on an x86 core's `rsp` field under Rosetta;
the checked-in O0 build therefore uses `0x7f8` as a validated fallback.

The first stage must remain small enough for the available stack. Stage 2 is
received into a high offset in `stage2_land`, then `pop rsp` pivots there. A
larger lab2 front copy overwrites the caller's environment and breaks `PATH`,
so the copy is kept to the chain-sized front region.

The shell command uses `sh <&fd >&fd 2>&fd`. This keeps the outer shell's
standard input separate and attaches only the inner shell to the reused socket,
which avoids losing the first command byte.

## Verified facts

- ASLR remains `2` during the marker and shell runs.
- lab1 and lab2 can use ordinary pop-register chains, but their flags-zero
  wrappers are custom jumps and must be selected explicitly.
- lab3's ret2csu call loads `r12d`, `r13`, and `r14` into `edi`, `rsi`, and
  `rdx`, then calls `[r15+rbx*8]`; `rbp=rbx+1` makes the loop execute once.
- `ropbot`/angrop can find ordinary gadgets and build register setup for labs 1
  and 2, but cannot infer the socket protocol, delayed BSS contents, or lab3's
  custom indirect table dispatch.

## Operational checklist

- discover or override the client socket fd;
- keep leak and stage-2 delivery on the same connection;
- use a writable BSS landing area above the RELRO boundary;
- preserve the lab2 caller frame by limiting the front copy;
- verify marker and real-shell modes with ASLR still enabled;
- repeat runs across the target architecture/emulation layer.

The companion comparison is in
[`COMPARISON-with-server-connect-sdk.md`](COMPARISON-with-server-connect-sdk.md),
and the ropbot-specific experiment is in [`ROPBOT-LAB3.md`](ROPBOT-LAB3.md).
