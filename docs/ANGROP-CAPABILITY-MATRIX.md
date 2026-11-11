# angrop capability matrix

The repository separates ROP-byte construction from runtime staging. The
runtime adapter (`exploit/staged_rop.py`) handles leak reception, libc-base
resolution, and stage-2 delivery. angrop handles only chain construction and
validation.

| Lab interface | angrop can help with | Harness responsibility | Result |
|---|---|---|---|
| Lab 1 single-socket | register setup, calls, pivot, memory operations | `StagedRopSession` reads the 8-byte `send` leak, computes `libc_base = leak - libc.send`, builds the runtime `system` stage, and sends it over the same socket | runtime adapter applied; chain remains manual |
| Lab 2 front-load | ordinary chain construction and gadget analysis | harness places the chain at response offset 0, sets the formatter's front-slot count, then reuses the same leak/base/stage-2 flow | front-load semantics remain harness-specific |
| Lab 3 ret2csu | explicit `ret2csu()` helper plus ordinary chain APIs | harness selects CSU/table addresses, invokes `ret2csu()`, receives the leak, resolves libc, and delivers stage 2 through `StagedRopSession` | helper and runtime adapter both integrated |

In all three labs the harness owns socket lifecycle, protocol headers, leak
parsing, libc rebasing, stage-2 transport, shell/marker verification, and
retry/timeout behavior. angrop owns ROP gadget analysis and chain bytes only.

Run `scripts/angrop_capabilities.py` inside an angr/angrop environment to
report the installed API surface and whether each lab binary is present:

```bash
python3 scripts/angrop_capabilities.py
```

The report is an availability probe, not a guarantee that a chain can be
synthesized for every binary. Actual gadget constraints and lab-specific
placement rules still require an integration run.
