# angrop capability matrix

The repository separates ROP-byte construction from runtime staging. The
runtime adapter (`exploit/staged_rop.py`) handles leak reception, libc-base
resolution, and stage-2 delivery. angrop handles only chain construction and
validation.

| Lab interface | angrop can help with | External logic still required |
|---|---|---|
| Lab 1 single-socket | register setup, calls, pivot, memory operations | socket protocol, leak/base calculation, stage-2 transport |
| Lab 2 front-load | ordinary chain construction and gadget analysis | front-loaded RIP placement and formatter semantics, socket staging |
| Lab 3 ret2csu | explicit `ret2csu()` helper plus ordinary chain APIs | CSU addresses/table selection, socket staging, leak/base calculation |

Run `scripts/angrop_capabilities.py` inside an angr/angrop environment to
report the installed API surface and whether each lab binary is present:

```bash
python3 scripts/angrop_capabilities.py
```

The report is an availability probe, not a guarantee that a chain can be
synthesized for every binary. Actual gadget constraints and lab-specific
placement rules still require an integration run.
