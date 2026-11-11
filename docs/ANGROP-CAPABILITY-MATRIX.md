# angrop capability matrix

The repository separates ROP-byte construction from runtime staging. The
runtime adapter (`exploit/staged_rop.py`) handles leak reception, libc-base
resolution, and stage-2 delivery. angrop handles only chain construction and
validation.

## Interface-level result

| Lab | Interface | angrop support | Harness handling |
|---|---|---|---|
| Lab 1 | Gadget discovery | Available; the `ANGROP=1` path loads the binary with angr/angrop | Harness supplies the lab's planted gadget addresses and protocol context |
| Lab 1 | Register setup / ordinary calls | Available through `RopChain`/builder APIs; concrete chain generation verified | Harness supplies fd, GOT address, stage buffer, and call order |
| Lab 1 | Stack pivot | Available as an angrop builder capability | Harness supplies the pivot destination and embeds it in the staged protocol |
| Lab 1 | Leak, libc calculation, stage-2 transport | Outside angrop's chain-builder scope | `StagedRopSession` receives the leak, rebases libc, builds runtime stage 2, and sends it |
| Lab 2 | Ordinary ROP chain generation | Available; concrete chain generation verified with `ANGROP=1` | Harness supplies the front-loaded chain values |
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

The integration runs are selected with `ANGROP=1 ./run.sh` for Labs 1 and 2,
and `ROPBOT=1 ./run.sh` for Lab 3. Each path prints its active chain builder
and verifies both marker and shell modes.
