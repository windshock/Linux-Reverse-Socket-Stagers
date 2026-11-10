# Comparison with `server-connect-sdk`

The companion `server-connect-sdk` project contains the same three reverse
socket staging techniques in a form that is easier to run under Rosetta and
pty based containers. The underlying exploitation ideas are identical:

- single-socket libc leak, stage-2 `recv`, and BSS stack pivot;
- lab 2 front-load source hijacking through the controlled `memcpy`;
- lab 3 ret2csu dispatch with flags forced to zero by the wrapper table.

## What this repository provides

This repository has the more self-contained workflow: each lab owns its
Dockerfile, `run.sh`, offset probe, marker mode, shell mode, and end-to-end
verification. The lab3 image deliberately uses Ubuntu 20.04/glibc 2.31 because
the intended `__libc_csu_init` dispatcher is absent from later glibc releases.

## What the companion project adds

The companion project records the debugging details that matter on Apple
Silicon and other emulation layers. In particular, it detects the client socket
through `/proc/<pid>/fd`, documents why fd 3 is not reliable under Rosetta,
keeps the stage-2 copy short enough to preserve `PATH`, and uses
`sh <&fd >&fd 2>&fd` for the reused socket shell. Its comparison also records
the Rosetta corefile limitation and the static `0x7f8` offset fallback.

## Reconciliation

The current tree now includes those portability fixes: all three exploit
servers support `FD=` overrides and automatic socket-fd discovery, and the
offset probes fall back to `0x7f8` when the runtime cannot expose x86 `rsp`.
The companion project's ropbot experiment is documented separately in
[`ROPBOT-LAB3.md`](ROPBOT-LAB3.md); it automates ordinary gadget discovery and
register setup but leaves protocol sequencing and custom ret2csu dispatch to
the exploit.
