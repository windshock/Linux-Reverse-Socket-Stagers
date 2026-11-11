# AI-facing tool interfaces

The repository keeps the tool boundary small so an agent can request a
structured result instead of reproducing long analysis code in every run.

## Binary analysis and stage-1 chain construction

Labs 1 and 2 expose the same two functions from their local
`exploit/angrop_chain.py` module:

```python
analysis = analyze_binary(binary, gadget_addresses=(...))
summary = analysis_summary(analysis)
payload = build_rop_chain(binary, values, gadget_addresses=(...), analysis=analysis)
payload_summary = build_rop_chain_summary(binary, values, analysis=analysis)
```

`analyze_binary()` runs angrop's gadget discovery and returns the loaded angr
project, the ROP analysis, the discovered gadget count, and the addresses that
were verified. `analysis_summary()` converts that internal result to a JSON-safe
summary. `build_rop_chain()` uses that analysis to emit concrete payload bytes
through `RopChain`; `build_rop_chain_summary()` exposes only its length and
hex-encoded bytes for an external caller.

The current interface intentionally accepts explicit chain values. It does not
claim target-goal-to-chain synthesis: the Lab harness still supplies the
protocol-specific call sites, arguments, and stack layout.

## Runtime staging

All three labs expose the same `StagedRopSession` shape:

- `receive_leak(symbol)` receives a complete machine-word leak and rebases the
  libc object using the original symbol offset;
- `receive_leak_summary(symbol)` returns a JSON-safe success/error object;
- `deliver_stage2(payload)` sends the runtime-generated second stage over the
  existing connection and returns `{ok, bytes_sent}`.

`scripts/ai_tool_api.py` provides `verify_execution(output, mode)`, which turns
the marker/shell oracle into a compact result. It does not infer success from a
partial log.

This keeps socket I/O, libc rebasing, and stage transitions out of angrop. The
runtime tests in `tests/test_staged_rop.py` exercise fragmentation, repeated
rebasing, short leaks, timeout propagation, JSON-safe summaries, and
byte-exact stage delivery.

Lab 3 additionally uses the explicit `ret2csu()` helper from the ropbot/upstream
angrop prototype because its indirect-call frame is specific to that target.

## A/B measurement harness

`python3 scripts/ab_experiment.py --input runs.jsonl` aggregates recorded
direct-analysis and tool-assisted runs. Each JSONL record must include:

```json
{"condition":"tool","run_id":1,"input_tokens":0,"output_tokens":0,
 "tool_calls":0,"tool_time_seconds":0,"total_time_seconds":0,
 "success":false,"retries":0}
```

The script reports per-condition means and success rate. It prints
`NOT_TESTED` when no records are supplied; it never fabricates token, cost, or
success values. Model/API execution and trace capture remain external so the
same model, binary, environment, oracle, and budget can be held constant.

## Observed Hinoki account baseline

The supplied Hinoki dashboard snapshot records the following account-level
baseline (UTC):

| Period | Product | Usage | Credit spend |
|---|---|---:|---:|
| Last 30 days | Inference | 61M tokens | $7.04 |
| Last 30 days | Hinoki Cloud Agent | 0 tokens | — |
| Last 30 days | Agentic scans | 0 tokens | — |

This implies an observed aggregate rate of approximately `$0.115/M tokens`,
but it is **not** a per-task measurement for these Labs. It may include other
work performed during the same period and does not separate input from output
tokens. The A/B harness therefore leaves this value as contextual baseline
metadata; task-level conclusions require per-run traces with the same scope.
