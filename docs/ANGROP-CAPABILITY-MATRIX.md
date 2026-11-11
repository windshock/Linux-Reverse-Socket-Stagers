# angrop capability matrix

The repository separates ROP-byte construction from runtime staging. The
runtime adapter (`exploit/staged_rop.py`) handles leak reception, libc-base
resolution, and stage-2 delivery. angrop handles only chain construction and
validation.

## Interface-level result

| Lab | Interface | angrop support | Harness handling |
|---|---|---|---|
| Lab 1 | Gadget discovery / binary analysis | Invoked by `ANGROP=1` via `find_gadgets_single_threaded()` | Harness supplies the binary and protocol context |
| Lab 1 | Register setup / ordinary calls | Chain bytes are serialized through `RopChain`; gadget analysis is performed by angrop. The planted `send0/recv0` jump sites are lab-specific and remain explicit | Harness supplies fd, GOT address, stage buffer, and call order |
| Lab 1 | Stack pivot | Gadget analysis runs, but generic `pivot()` is not used; the synthetic `pop rsp` landing is explicit | Harness supplies the pivot destination and embeds it in the staged protocol |
| Lab 1 | Leak, libc calculation, stage-2 transport | Outside angrop's chain-builder scope | `StagedRopSession` receives the leak, rebases libc, builds runtime stage 2, and sends it |
| Lab 2 | Gadget discovery / binary analysis | Invoked by `ANGROP=1` via `find_gadgets_single_threaded()` | Harness supplies the binary and front-load protocol |
| Lab 2 | Ordinary ROP chain generation | Gadget analysis is performed by angrop and bytes are emitted through `RopChain`; front-load formatting and the planted jump sites remain explicit | Harness places the generated chain at response offset 0 |
| Lab 2 | Front-load RIP / formatter semantics | Outside angrop's chain-builder scope; not a lack of ordinary ROP APIs | Harness places chain at response offset 0 and sets the formatter slot count |
| Lab 2 | Leak and stage-2 runtime | Outside angrop's chain-builder scope | `StagedRopSession` handles leak, libc rebase, and same-socket delivery |
| Lab 3 | Ordinary `func_call()` for CSU indirect call | Insufficient for this lab's indirect CSU layout | Harness selects the CSU/table addresses |
| Lab 3 | Explicit `ret2csu()` helper | Supported by the proposed upstream PR #160; integration verified | Harness passes the CSU parameters and appends the staged runtime flow |
| Lab 3 | Leak, libc calculation, stage-2 transport | Outside angrop's chain-builder scope | `StagedRopSession` handles the runtime boundary |

In all three labs the harness owns socket lifecycle, protocol headers, leak
parsing, libc rebasing, stage-2 transport, shell/marker verification, and
retry/timeout behavior. These are not “unsupported angrop features”; they are
runtime protocol orchestration outside a ROP chain builder's responsibility.
angrop owns ROP gadget analysis and chain bytes only.

Run `scripts/angrop_capabilities.py` inside an angr/angrop environment to
report the installed API surface and whether each lab binary is present:

```bash
python3 scripts/angrop_capabilities.py
```

The report is an availability probe, not a guarantee that a chain can be
synthesized for every binary. Actual gadget constraints and lab-specific
placement rules still require an integration run.

## Builder APIs not used by the current three harnesses

The installed angrop builder exposes more APIs than these labs need:

| API | Current status | Reason |
|---|---|---|
| `set_regs()` / `move_regs()` | Not used in the final payload path | The labs use planted call sites and an explicit stack layout; automatic register setters would change the layout that the demonstrations are testing |
| `func_call()` | Not used for `send0`/`recv0` | Those symbols are `xor ecx; jmp *_plt` sites, not normal returning function bodies; the generic call model does not produce a valid chain for them |
| `pivot()` | Not used for the final pivot | The received `.bss` landing layout is a protocol-specific synthetic target; the explicit `pop rsp; ret` is retained and the end-to-end exploit verifies it |
| `write_to_mem()`, `do_syscall()`, `sigreturn()` | Not required by Labs 1–3 | No lab's objective requires a memory-write, syscall-only, or SROP chain |

These are “available but not applicable to the current interface,” not missing
angrop support. A future lab that removes the planted call sites or requires a
write/syscall/SROP primitive should add a separate integration path and test
that API directly.

The three `staged_rop.py` files remain colocated with their standalone lab
entry points on purpose: each lab can be copied and run independently. Their
`StagedRopSession` interfaces are kept identical, and the rebasing regression
check covers repeated leak resolution without relying on a shared import path.

The integration runs are selected with `ANGROP=1 ./run.sh` for Labs 1 and 2,
and `ROPBOT=1 ./run.sh` for Lab 3. Each path prints its active chain builder
and verifies both marker and shell modes.
