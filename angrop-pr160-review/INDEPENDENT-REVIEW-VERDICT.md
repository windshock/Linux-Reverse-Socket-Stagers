# Independent adversarial review — verdict

Reviewer environment (rebuilt from scratch, macOS arm64, Python 3.12.16):
angr 10.0.7 (claripy vendored inside angr — see R1), z3-solver 5.3.3.0,
angrop @ 7976832 (editable), patch `returning-ret2csu.diff` applied cleanly (+163/−13).
All probes: `probes/` (reviewer-written: `my_oracle.py`, `fp_scan.py`, `mkelf.py`+`synth_probe.py`,
`sem_change.py`, `scale_libc.py`). Vendored `bins/unexploitable` sha256-matches
angr/binaries upstream.

## R1. setup.sh is broken as shipped (reproducibility) — BROKEN, science survives

`./setup.sh` aborts at its first pip step:

```
ERROR: Cannot install angr==10.0.7, claripy==9.3.7 and z3-solver==5.3.3.0
ERROR: ResolutionImpossible
```

Root cause (deterministic, not a PyPI flake): **claripy 9.3.7 pins `z3-solver==4.13.0.0`**
while **angr 10.0.7 pins `z3-solver==5.3.3.0`** — the two pins can never co-resolve.
Moreover angr 10.0.7 no longer depends on external claripy at all (vendored as
`angr.rustylib.claripy`; there is deliberately no top-level `claripy` module), so the
stated env in FINDINGS.md ("angr 10.0.7 … claripy 9.3.7") cannot be the product of
setup.sh on any date. With `set -euo pipefail` the script dies before cloning angrop.

Rebuild that worked (minimal deviation, recorded): drop the claripy/z3 pins,
`pip install angr==10.0.7 pytest setuptools keystone-engine`, then the rest of
setup.sh unchanged. **Every claim below reproduces in the rebuilt env**, so the
conclusions stand — but setup.sh must be fixed before anyone else can reproduce.

## Claims, attacked

### C1 — pristine angrop cannot auto-assemble a returning ret2csu — SURVIVES (real effort)

- Enumerated the entire public builder API at 7976832 (`grep -rn "def "` across
  `angrop/chain_builder/`): no `ret2csu`, no `mem_func_call`; `func_call` is the only
  generic call entry (do_syscall/execve/sigreturn are unrelated).
- Baseline on `bins/vuln_client3` (197 gadgets): `net_send/send/net_recv ×
  needs_return=True` all RAISE; default (None) RAISES; `net_send + net_recv` RAISES.
  Same on `unexploitable` full set (`flip.py BEFORE`: A seeded=PASS, B default=FAIL).
- The seeded-DB scenario (A) builds only a TERMINAL chain; even there
  `needs_return=True` raises and `chain+chain` raises (`open3.py`).
- Low-level path (`set_regs` + manual frame) does work (`lowlevel.py`: RETURN-OK,
  re-verified) — i.e. the gap is automation, exactly as claimed.

### C2/C3 — patched chain executes, returns, and chains — SURVIVES my stronger oracle

I did not trust `validate.py` (its capture records only the last call; "pc is
symbolic" alone doesn't prove the right path). `probes/my_oracle.py`:

- Two chained calls with DISTINCT args (`c1 + c2`): both captured **in order** with
  exactly (edi,rsi,rdx) = args1 then args2 — proves c1 returned and control flowed
  through c2.
- Final pc constrained to a reviewer-chosen sentinel (0x401544): **satisfiable** —
  `next_pc_idx()=15` is a genuinely controllable slot, not a fixed/garbage value.
- Executed-block trace: `0x40152a(loader) → 0x401510(dispatch) → 0x4011c6(net_send) →
  0x40151d(post-call loop check) → 0x401526(epilogue add-rsp/pops/ret) → next loader
  → …` — the loader→dispatch→callee→**csu epilogue**→ret path, not an accident.
- Layout re-derivation: produced words are exactly `[loader][rbx=0][rbp=1]
  [r12=fd][r13=buf][r14=len][r15=0x403e10][dispatch][fill×7][next_pc]` — reduces to
  the `lowlevel.py` hand frame byte-for-byte.

Oracle-validity question (§2 of the brief): the hook is fair for the *mechanism*
(register setup + epilogue return are callee-independent given a callee that returns
with balanced stack), and its blind spot (noreturn / stack-switching callees) is
shared with pristine `func_call`'s own assumptions — not patch-specific. The
symbolic-pc assertion alone would be weak; trace + sentinel-pin close it.

### C4 — discovery, not hardcoded — SURVIVES, strengthened beyond the author's evidence

- `grep` of the diff: no literal `7`, no glibc register constants in the discovery path.
- 5 distinct entry points into vuln_client3's dispatch all yield
  `{cleanup_slots:7, pins:{rbx:0, rbp:1}}` dynamically (`discover_test.py`, re-run).
- **New adaptivity proof** (`probes/mkelf.py` + `synth_probe.py`): reviewer-built
  synthetic ELF whose "csu" has a CUSTOM epilogue `add rsp,8; pop rbx; pop rbp; ret`
  (3 slots, and rbp NOT pinned). Discovery returns `{'cleanup_slots': 3,
  'pins': {'rbx': 0}}` — it adapts to a layout where the true answer ≠ 7. End-to-end
  `func_call(needs_return=True)` on that binary builds and executes to a pinned
  sentinel with exact args.

### C5 — 53/53 + full test dir — SURVIVES (with a control experiment)

- `tests/test_chainbuilder.py` with patch: **53 passed** in 28s (pip keystone wheel;
  no DYLD needed).
- Full `tests/`: 126 passed, 9 failed — all 9 ("Not a valid binary": mips/cgc/
  ropblock corpus) fail **identically on pristine angrop** (stash-control re-run:
  same 9). They are sparse-checkout/environment artifacts, not patch effects.
  Patch-caused failures outside chainbuilder: **0**.

### C6 — side effects — partially closed; two NEW findings

1. **Guard relaxation (Blocker A).** No wrong-gadget or blowup found: glibc-2.19
   full cache (4654 gadgets) → self-contained path wins first, func_jmp pool is empty
   in that cache, timings 0.01–0.03s; `unexploitable` full set → relaxation admits a
   csu-family alt-entry (0x4005ca) and the terminal chain executes with rdx
   controlled (`flip.py AFTER B` PASS). NOTE: `flip.py`'s `uses_csu` flag only tests
   0x4005D0, so its `uses_csu=False` is misleading — 0x4005ca IS the same call site.
2. **Iteration-order nondeterminism (new, minor).** On `unexploitable`, the first
   pool gadget (0x4005ca, whose pc_target is bare `sreg_r12` → unparseable) succeeds
   terminally and preempts the "prefer returning" policy — patched default there is
   still a 9-word terminal chain. Correct, but "None prefers returning" is
   set-iteration-order dependent, not guaranteed.
3. **needs_return=None semantics — CONFIRMED REAL CHANGE** (blindspot #2), seeded
   scenario, same call: pristine default = 9-word terminal chain; patched default =
   17-word returning chain (both execute, rdx controlled). The old "function won't
   return!" warning no longer fires when the returning variant succeeds. Needs
   maintainer sign-off, as the author already flagged.
4. **Discovery false-positive shape — REAL but currently benign** (blindspot #4a).
   A pure non-csu `jmp [r15+rbx*8]` thunk parses and discovery reports
   `cleanup_slots=0` "returning" (synthetic, measured). The chain it produces is
   still semantically correct for any callee that returns with a balanced stack —
   verified end-to-end unhooked with a plain-`ret` callee (args exact, sentinel
   satisfiable). Residual hazard: a noreturn callee now gets a chain that *claims*
   to return through more gadget shapes than before (pristine makes the same
   assumption for its FunctionGadget path). Worth a doc note, not a blocker.
5. **Cross-arch: the blindspot doc's "safe fallback" claim is WRONG in practice
   (new).** Real ARM glibc 2.31 (tests_data cache) contains **4 csu-parseable
   jmp_mem gadgets** (0x4b985f, 0x4b9861, 0x4b9863, 0x44361f) — the parser fires
   off x86-64. Running `_discover_csu_epilogue` on them is pathologically slow:
   >11 minutes of CPU on the first of the 4 gadgets without completing (killed) on this machine (vs 0.09s per gadget on x86-64);
   i386 and aarch64 caches show 0 matches, and the suite's ARM tests never reach
   these gadgets (suite green in 28s) — so tests cannot see this. If a user's
   `func_call` on ARM degrades to the func_jmp loop on such a gadget, they eat a
   multi-minute silent stall per gadget per call (no caching). **Recommend gating
   discovery to amd64 (or a step/time budget + per-gadget cache) before sharing.**
6. **copy.copy side effects (blindspot #3)** — no leak found: synthesized
   `stack_change`/`pc_offset` are consumed only by `_func_call`'s layout loop;
   `next_pc_idx()` is `_values`-driven; the copy never enters gadget pools/caches;
   IBT checks read only `transit_type`/`has_endbr`; a chain containing the copy
   pickles fine (exec-after-unpickle fails for ALL chains — angrop's own
   `__getstate__` drops `_blank_state`; pre-existing).
7. **Cost on the happy path**: returning `func_call` on vuln_client3 ≈ 0.10s/call
   (discovery re-paid per call, uncached — blindspot #4b confirmed, cheap here);
   `needs_return=False` = 0.01s (discovery fully skipped, verified).

## Harness-bias notes (§4)

- `flip.py` `uses_csu` checks a single address → mislabels csu alt-entries as
  non-csu. Didn't invert any conclusion, but fix before citing.
- `validate.py`'s single-capture + symbolic-pc assertions are weak for the reasons
  above; my oracle supersedes them (same verdict).
- `harness.py`'s "=== BASELINE ===" label is wrong — it prints whatever code is
  applied; per ADVERSARIAL-REVIEW.md you apply the patch BEFORE running it, so its
  "baseline" section is actually the patched behavior. Cosmetic but confusing.

## Verdict

- Claims C1–C5: **survived genuine falsification attempts** (rebuilt env, own oracle,
  own synthetic binaries, control experiment for the suite).
- C6: not provable "no side effects", but concretely narrowed: relaxation showed no
  mis-selection in anything I could run; two NEW items for the maintainer — the ARM
  parser over-reach + cost stall (5), and iteration-order nondeterminism of the
  "prefer returning" policy (2) — plus the confirmed needs_return=None change (3).
- **Draft-PR verdict: yes, shareable as a prototype** with the author's five
  blindspots PLUS the ARM gate/caching requirement called out up front. Not
  merge-ready: gate discovery to amd64 (or budget+cache it), decide the None-semantics
  question with the maintainer, and note the ordering caveat.
- Approach opinion (not inheriting the framing): the mechanism — discovery-driven,
  expressed as stack_change/pc_offset on a copied gadget — is sound and the smallest
  blast radius for a first PR; the proper long-term home is classification-time
  `call_mem` (as DESIGN §6 already says). I do NOT think a separate hardcoded
  `ret2csu()` API is the right shape; discovery-based is right.

## Repro index (reviewer's own commands)

```
./setup.sh                                   # fails (R1); rebuild per R1 note
./venv/bin/python scripts/lowlevel.py        # RETURN-OK (pristine)
./venv/bin/python scripts/lab3_targetproof.py  # pristine: all RAISE / patched: all BUILT
./venv/bin/python scripts/flip.py BEFORE|AFTER
./venv/bin/python scripts/validate.py        # PASS (patched)
./venv/bin/python probes/my_oracle.py        # dual-call + trace + sentinel: PASS
./venv/bin/python probes/fp_scan.py          # csu-parseable census + timing
./venv/bin/python probes/mkelf.py && ./venv/bin/python probes/synth_probe.py  # adaptivity(3≠7) + jmp-thunk
./venv/bin/python probes/sem_change.py patched|pristine  # 9→17 words (stash for pristine)
./venv/bin/python probes/scale_libc.py       # glibc full set: no regression
( cd angrop-src && ../venv/bin/python -m pytest tests/test_chainbuilder.py -q )  # 53/53
( cd angrop-src && ../venv/bin/python -m pytest tests/ -q )  # 9 env-failures, identical on pristine
```
