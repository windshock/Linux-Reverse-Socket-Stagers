# Ropbot applicability to the three labs

Upstream reference: [`angr/angrop`](https://github.com/angr/angrop). The
ret2csu helper used here is proposed in
[`angr/angrop#160`](https://github.com/angr/angrop/pull/160), with the earlier
prototype tracked in [`sefcom/ropbot#1`](https://github.com/sefcom/ropbot/pull/1).

The exploit chains were tested against the built x86_64 binaries with the
angrop implementation from the upstream development branch plus the local
`ret2csu()` patch. The lab3 exploit now
accepts `ROPBOT=1` and routes both ret2csu calls through `rop.ret2csu()`.

For labs 1 and 2, gadget discovery found the planted pop gadgets and
`rop.set_regs(rdi=..., rsi=..., rdx=...)` generated the ordinary register setup
chain. The custom `g_send0` and `g_recv0` wrappers were not recognized as
ordinary ROP gadgets because they jump directly to the PLT and do not end in
`ret`; they still need explicit selection.

The BSS pivot could not be verified automatically because the destination is
populated later by a socket `recv`, so symbolic execution sees unconstrained
memory. Lab 3 found its gadgets but could not synthesize the requested
`rdi/rsi/rdx` setup: the useful call is an indirect ret2csu dispatch through the
custom `fnptr[]` table, outside the normal direct `func_call()` model. The new
explicit `ret2csu()` helper handles that dispatch. With the PR branch installed
in an x86 analysis environment, the helper-backed exploit passed both marker
mode (`uid=0`) and shell mode (`SHELL_OK`) under ASLR=2. The repository-level
command `ROPBOT=1 ./run.sh` now reproduces that test by selecting
`Dockerfile.ropbot`, which builds the target under Ubuntu 20.04/glibc 2.31 and
installs the pre-merge helper branch in a Python 3.10 runtime. The same helper
was then re-tested with angr/angrop development HEADs under Python 3.12.

The practical integration boundary is gadget discovery and ordinary register
setup. Protocol sequencing, leak arithmetic, fd selection, stage-2 delivery,
front-load limits remain exploit-specific. Run with `ROPBOT=1 ./run.sh` to select
the helper-backed container; the default `ROPBOT=0` path retains the manual chain for environments
where angr is not installed.

## Runtime staging adapter

The repository now keeps the runtime half separate in
`03-ret2csu-flags-zero/exploit/staged_rop.py`. `StagedRopSession` receives the
stage-1 leak, resolves the libc base, and delivers stage 2 over the existing
socket. angrop remains responsible only for constructing and validating the ROP
bytes; the adapter owns the network/session boundary. This is the reusable
multi-stage application layer, rather than functionality that belongs inside
angrop itself.
