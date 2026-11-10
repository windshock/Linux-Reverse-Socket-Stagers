# Ropbot applicability to the three labs

The exploit chains were tested against the built x86_64 binaries with the
angrop implementation used by the `ropbot` PR branch. The lab3 exploit now
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
mode (`uid=0`) and shell mode (`SHELL_OK`) under ASLR=2.

The practical integration boundary is gadget discovery and ordinary register
setup. Protocol sequencing, leak arithmetic, fd selection, stage-2 delivery,
front-load limits remain exploit-specific. Run with `ROPBOT=1` to select the
helper; the default `ROPBOT=0` path retains the manual chain for environments
where angr is not installed.
