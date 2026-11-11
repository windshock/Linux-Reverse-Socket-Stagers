# Hinoki A/B experiment

This note records the observed comparison for writing the synthetic Lab 1, Lab
2, and Lab 3 remote-command execution demonstrations.

| Condition | Description | Hinoki inference | Credit spend |
|---|---|---:|---:|
| **A — direct** | The model writes the exploit and supporting code directly. | **61M tokens** | **$7.04** |
| **B — tool-assisted** | The model uses the repository interfaces backed by `angrop`, `ropbot`, `pwntools`, and `StagedRopSession`, then runs the Docker-backed validations. | **15.3M tokens** | **$2.21** |

## Observed difference

- Token usage: `61 / 15.3 = 3.99`, approximately **4.0x lower** for B.
- Token reduction: approximately **74.9%**.
- Credit spend: `7.04 / 2.21 = 3.19`, approximately **3.2x lower** for B.
- Credit reduction: approximately **68.6%**.

The B condition included two sessions on the same day: verification of the
existing tool path, followed by actual implementation and integration from the
pre-integration Lab baseline. The implementation run passed:

- Lab 1: `ANGROP=1`, marker and shell modes;
- Lab 2: `ANGROP=1`, marker and shell modes;
- Lab 3: `ROPBOT=1`, marker and shell modes;
- ASLR-enabled Docker execution for all three Labs;
- unit and integration test suites.

The figures are Hinoki dashboard aggregates for the two comparison periods.
They are not per-request telemetry and should not be read as a universal
per-exploit saving. For repeatable research measurements, provide per-run
JSONL traces to [`scripts/ab_experiment.py`](../scripts/ab_experiment.py),
which intentionally reports `NOT_TESTED` when such records are absent.
