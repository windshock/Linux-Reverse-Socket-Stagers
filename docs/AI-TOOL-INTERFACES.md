# AI-facing tool interfaces

The repository keeps the tool boundary small so an agent can request a
structured result instead of reproducing long analysis code in every run.

## Binary analysis and stage-1 chain construction

Labs 1 and 2 expose the same two functions from their local
`exploit/angrop_chain.py` module:

```python
analysis = analyze_binary(binary, gadget_addresses=(...))
payload = build_rop_chain(binary, values, gadget_addresses=(...), analysis=analysis)
```

`analyze_binary()` runs angrop's gadget discovery and returns the loaded angr
project, the ROP analysis, the discovered gadget count, and the addresses that
were verified. `build_rop_chain()` uses that analysis to emit concrete payload
bytes through `RopChain`.

The current interface intentionally accepts explicit chain values. It does not
claim target-goal-to-chain synthesis: the Lab harness still supplies the
protocol-specific call sites, arguments, and stack layout.

## Runtime staging

All three labs expose the same `StagedRopSession` shape:

- `receive_leak(symbol)` receives a complete machine-word leak and rebases the
  libc object using the original symbol offset;
- `deliver_stage2(payload)` sends the runtime-generated second stage over the
  existing connection.

This keeps socket I/O, libc rebasing, and stage transitions out of angrop. The
runtime tests in `tests/test_staged_rop.py` exercise fragmentation, repeated
rebasing, short leaks, and byte-exact stage delivery.

Lab 3 additionally uses the explicit `ret2csu()` helper from the ropbot/upstream
angrop prototype because its indirect-call frame is specific to that target.
