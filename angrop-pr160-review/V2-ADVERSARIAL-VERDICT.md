# V2 adversarial review — the post-fix diff (gate + cache), independently re-derived

Reviewer: fresh agent, no trust in `INDEPENDENT-REVIEW-VERDICT.md`, `evidence/`, `probes/`,
or the `REVIEW-BLINDSPOTS.md` "Update 2026-11-18" addendum (all read only to learn what was
claimed; every number below re-derived with my own scripts in `probes2/`). Environment:
macOS arm64, python 3.12.16, angr 10.0.7 (claripy vendored), z3 5.3.3, angrop@7976832
editable, v2 diff applied (+182/−13, `git diff --stat` verified, left applied).

Two things I verified about the environment that the implementer's docs get wrong or
gloss: angr's `state.memory.load(addr, n)` defaults to **big-endian** in this build
(any hand-rolled oracle that forgets `endness=` sees byte-swapped "wrong args" that are
its own bug, not the chain's); and the i386 cache pairs with
`binaries/tests/i386/i386_glibc_2.35`, not `libc.so.6` (mismatching the pair makes
`load_gadgets(optimize=True)` crash inside pristine `reg_mover` code — my first census
run's artifact, not a patch bug).

## Claims, attacked

### C1 — patched func_call auto-assembles a returning, chainable ret2csu on AMD64 — SURVIVED (own dual oracle, strongest evidence in the file)

`probes2/c1_exec_oracle.py` + `probes2/c1b_hooked.py` (written from scratch; not
`scripts/validate.py`, not `probes/my_oracle.py`).

- Chain layout (16 words, my own resolver): `[0x40152a loader][rbx=0][rbp=1][fd][buf][len]
  [table 0x403e10][dispatch 0x401510][fill×7][next_pc]`; `next_pc_idx=15`.
- **Real-code callee, not a hook**: I assembled a synthetic x86-64 callee into scratch
  memory (records rdi/rsi/rdx, clobbers flags + caller-saved regs, push/pop stack use),
  pointed the table slot at it, and concrete-executed the payload. Callee recorded
  `rdi=0x41414141 rsi=0x42424242 rdx=0xc0de` — exact. Instruction trace:
  `0x40152a…34 (loader pops) → 0x401510/0x401519 (dispatch, call [r15+rbx*8]) → callee →
  0x40151d (add rbx,1) → 0x401524 (jne not taken) → 0x401526 (add rsp,8+pops) → ret →
  MY sentinel 0x50000100`, whose code wrote `0xdeadbeef` — the next_pc slot is genuinely
  controllable, and the path is the real csu epilogue, not an accident.
- **Dual call** `c1+c2` (31 words, different args): callee entered twice in trace, args
  0x41414141… then 0xaaaa0001… in order, sentinel reached after both. Chainable.
- **Unmodified-binary variant**: binary's own `[0x403e10]=0x4011c6` (claim's table/fnptr
  addresses verified); with `net_send` hooked, the recorder captured exactly the requested
  args and the sentinel magic was written. (A hooked address never appears in an
  instruction trace — the recorder capture is the proof, my first verdict logic there was
  wrong, not the chain.)

### C2 — 53/53 chainbuilder; full tests/ has zero patch-caused failures — SURVIVED (with pristine control)

- `( cd angrop-src && ../venv/bin/python -m pytest tests/test_chainbuilder.py -q )` →
  **53 passed** in 24.1s.
- Full `tests/` patched: **126 passed, 9 failed**; pristine (stash control, run before the
  restore): **126 passed, 9 failed** — the failure sets are **identical** (9×
  "Not a valid binary file": mipsel/btrfs, i386-cgc, ropblock corpus — sparse-checkout
  artifacts). Patch-caused failures: 0.

### F1a — gate gives non-AMD64 an instant, zero-side-effect fallback — SURVIVED

`probes2/f1a_arm_census.py` (with my own re-implementation of the pc_target parse, not the
patch's method):

- armel glibc 2.31: 225 jmp_mem gadgets, **4 csu-parseable**, set **exactly**
  `{0x44361f, 0x4b985f, 0x4b9861, 0x4b9863}` (claimed addrs match, no extras/missing).
- `_discover_csu_epilogue` on each → `None` in **0.0000s**; `project.is_hooked(0x43430000)`
  stays **False** (hook never installed); `_csu_epilogue_cache` stays **empty** — the gate
  sits *before* the cache, so non-AMD64 doesn't even populate it (stronger than claimed).
- `_try_csu_return` → None; repeated calls still cost 0.0000s.
- i386 (cache `i386_glibc_2.35` ↔ `binaries/tests/i386/i386_glibc_2.35`) and aarch64
  (`aarch64_glibc_2.19` ↔ `tests/aarch64/libc.so.6`, fast_mode=True): **0** jmp_mem
  gadgets in the func_jmp pool even after explicit `bootstrap()` → 0 parseable. Claim holds.

### F1b — the `arch.name == "AMD64"` predicate — SURVIVED (no reachable hole found)

- Grepped all callers (`grep -rn "_parse_csu_dispatch|_discover_csu_epilogue|_try_csu_return"`):
  the only entry into discovery/hook/synthesis is `_try_csu_return`, called only from
  `func_call` line 415. On non-AMD64: parse (pure AST, no project mutation) → gate → None
  → terminal fallback. Nothing else reaches the hook, the sim exec, or `copy.copy`.
- archinfo: x86-64 is exactly `'AMD64'`; no other arch shares the name; AArch64 is
  `'AARCH64'`, ARM is `'ARMEL'/'ARMHF'` — no spelling trap.
- Too-broad check: the gate is arch-only, not simos-gated, so an AMD64 non-Linux project
  (e.g. a Windows PE) still pays ~0.09s discovery per parseable gadget and inherits the
  same inherent false-positive surface as Linux AMD64 (cost, not correctness — the
  mechanism is simos-independent ROP). No misfire found; noted as residual surface.
- Behavior note (pre-existing to the v1 patch, not F1): with `needs_return=True` pristine
  raises immediately without trying jmp gadgets; patched tries csu on each candidate and
  raises a *different message* (`fail to invoke function: …`) if all fail. Same exception
  type, superset semantics.

### F1c — the gate changes nothing on AMD64 — SURVIVED (as far as observable)

- The v1→v2 delta is *only* the early `return None` — on AMD64 the condition is false and
  every patched probe ran the full discovery/cache path (e.g. cache
  `{'0x401510': {'cleanup_slots': 7, 'pins': {'rbx':0,'rbp':1}}}`), i.e. the gate branch is
  dead code on AMD64.
- `needs_return=False`: `probes2/f2d_costs.py` — 0.0163s, **0 discovery calls, 0 cache
  entries**, terminal chain built (on vuln_client3 this *succeeds* where pristine *raises*,
  but that difference comes from the original Blocker-A relaxation, not the gate; same
  9-word terminal shape/gadgets as pristine on the seeded scenario, see below).
- Seeded-DB scenario (`probes2/pristine_control.py`, stash control): pristine nrFalse = 9-word
  terminal `[0x4005e6,…,0x4005d0]`, patched nrFalse = 9-word terminal, same gadgets (fill /
  ptr-slot values differ — solver choice; both satisfy the pc_target constraint; the suite's
  own `test_unexploitable` executes this shape). Self-contained path untouched.

### F2a — cache correct across call contexts — SURVIVED

- Code: `base_reg` excluded from pins; `extra[base_reg] = ptr_to_func` set per call —
  discovery is ptr-independent by construction.
- Execution: one FuncCaller, `func_call(net_send,[1,2,3],needs_return=True)` then
  `func_call(net_recv,[4,5,6],needs_return=True)` (ptr 0x403e10 vs 0x404018) — **both
  build returning chains (next_pc_idx=15) from the same cached entry; cache stays size 1**.
  Dual-call execution with distinct args proven in the C1 oracle.

### F2b — staleness / aliasing / negative caching — SURVIVED on all reachable paths (mechanism caveats documented)

`probes2/f2b_cache_integrity.py`:

- Aliasing: cached dict deep-equal before/after more chains; pins not mutated; `extra` is a
  copy; `g2` fields set only on the copy.
- `rop.optimize()`: the csu gadget object is **unchanged in place** (same id, same moves,
  stack_change −8), cache stays valid, post-optimize returning func_call still builds.
  No reachable path found where a live FuncCaller's gadget content changes under a cached
  addr.
- Keying is addr-only: a *different* gadget object at the same addr gets the cached entry
  (mechanism demo). Negative caching is sticky: after a simulated discovery failure, the
  cached `None` persists even "after fixing" — end-to-end on this binary the impact was
  masked by the self-contained fallback building a chain, but the csu path itself was
  silently downgraded (and with `needs_return=True` a poisoned None → hard RopException,
  see F2e).

### F2c — hook hygiene — **BROKEN in one respect** (pre-existing hook destroyed)

`probes2/f2c_hook_hygiene.py`:

- A pre-existing **user hook at 0x43430000 is silently destroyed**: before discovery
  `hooked_by=UserHook`; after one returning `func_call` `is_hooked(FAKE)=False`. `hook(
  FAKE, …, replace=True)` overwrites it and `finally: unhook(FAKE)` removes it entirely.
  Loss happens on the single discovery call; F2's cache makes it once-per-gadget (better
  than per-call, still real). Any angr-managed SimProcedure parked at that exact address
  would suffer the same.
- No corruption of project memory at TABLE/STACK/FAKE for the lab binary (addresses
  unmapped there; discovery writes are state-local). A non-PIE binary actually mapped in
  the 0x41410000/0x42420000/0x43430000 range colliding with a gadget that *reads* those
  addresses → silently tainted discovery result: plausible by construction, **out of
  scope** here (needs a synthetic ELF; not attempted after one pass).

### F2d — costs — SURVIVED, numbers reproduce

`probes2/f2d_costs.py`:

- First returning call 0.1068s, of which discovery **0.0912s**; cached repeat mean over 20
  **0.0148s** (claimed 0.106→0.015 ✓). Discovery-only: 0.0863s fresh vs 0.000001s cached.
- `needs_return=False` 0.0163s with discovery fully skipped (0 calls, 0 cache entries) ✓.
- Single-entry explanation confirmed: of the 19-gadget func_jmp pool (5 parseable:
  0x401510/11/13/14/16 — same dispatch at different entries), only **0x401510** reaches
  `_try_csu_return` (guard/move-processing order) and it succeeds, so later candidates are
  never probed. The cache is NOT only for repeats: the net_recv chain reused it (F2a);
  it would also amortize retries over failed candidates (up to 4 more parseable gadgets
  would each populate an entry before a success).

### F2e — thread/re-entrancy — SURVIVED live, but the model race shows a NEW permanent-poison hazard

`probes2/f2e_race.py`:

- Live 4-thread race on a shared project/ROP: all 4 calls `ok:15`, cache correct — no
  corruption reproduced (GIL + narrow window).
- Deterministic interleaving model (another discovery's `finally` unhooks FAKE between
  hook and step): discovery returns **None, which gets CACHED**, and every subsequent
  `needs_return=True` call **raises permanently** (with `None` it would silently fall back
  to a terminal chain). Pre-F2 the same race gave a transient wrong answer that the next
  call recomputed; F2's negative caching converts it into a **sticky wrong answer**. New
  hazard class enabled by F2; severity low–medium (angrop makes no thread-safety promises,
  but the cache changes the failure mode from transient to permanent).

### A1 — diff applies cleanly and reproduces byte-for-byte — SURVIVED

Fresh `/tmp` repo at 7976832, `git apply --check` + `git apply` of
`returning-ret2csu.diff`, `diff` vs working tree file: **byte-identical**; `git diff --stat`
= +182/−13 on `angrop/chain_builder/func_caller.py` only.

### A2 — addendum assertions — MOSTLY TRUE; one is FALSE

- True, re-derived: 4 ARM addrs exact; gate 0.0000s; 0.106→0.015; 53/53; seeded
  pristine 9-word terminal vs patched 17-word returning (`probes2/pristine_control.py`:
  patched S5_nrNone = 17 words with next_pc); #4b cost was real and is now cached.
- **FALSE: "#3 (no copy.copy leak found)"** — there is one; see NF1.
- "lab3 BUILT / oracle PASS": consistent with my re-derivation (I did not rerun their
  harness; my own oracle supersedes it — see harness-bias notes).

## New findings (not mentioned anywhere in the package before this review)

**NF1 (medium — fix before sharing): `copy.copy(g)` yields a project-less gadget copy.**
`RopGadget.__getstate__` nulls `project` for pickling, and stdlib `copy.copy` honors
`__getstate__/__setstate__`, so the synthesized `g2` has `project=None`
(`probes2/find_copy_project_leak.py`: copy.project=None while `g.copy()` keeps it). Blast
radius on every returning-csu chain: `chain.payload_code()`, `chain.dstr()`, `str(chain)`
raise `AttributeError: 'NoneType' object has no attribute 'factory'`, and `RopChain.exec()`'s
failure path (`payload_code`) would raise AttributeError instead of the intended
RopException, masking real execution errors. `payload_str()`/`exec()` success paths are
unaffected (why the suite and the implementer's oracle never saw it). One-line fix exists
(`g.copy()`), which I did not apply — reviewer, not implementer.

**NF2 (low–medium): discovery destroys a pre-existing hook at 0x43430000** (F2c above).

**NF3 (low–medium): F2's negative caching turns the hook race into a permanent poison**
(F2e above: model-demonstrated; live race not reproduced).

**NF4 (note, unprobed): `extra.update(epi['pins'])` runs *after* arg registers are placed,
so on an exotic gadget whose epilogue pins a register that also carries an argument, the
pin silently overwrites the requested argument.** Construction-level observation only; no
repro attempted (glibc csu pins are rbx/rbp, never arg regs).

## Harness-bias notes

- The implementer's oracle hooks the callee with a trivial SimProcedure — it cannot see
  callee effects (flags/stack/caller-saved clobbers). My real-code-callee variant closes
  that hole and still passes; the mechanism is callee-independent as claimed *for a
  well-behaved (ABI-respecting) callee* — an ABI-violating callee would break the loop
  exit for any ret2csu, not specifically this patch (not separately reproduced).
- The implementer's smoke tests only ever called `payload_str()`/build paths — exactly the
  surface NF1 leaves intact, which is why "+182/−13 all green" could not catch it. Any
  future check must include `payload_code()`/`dstr()` on produced chains.
- The addendum's numbers were all reproducible; the one qualitative claim (#3 "no leak")
  failed — a reminder that "no leak found" from the author's own probes is weak evidence.

## Overall verdict

- C1, C2, F1a, F1b, F1c, F2a, F2b, F2d, A1: **survived genuine falsification attempts**,
  evidence regenerated independently.
- F2c: **broken** (user-hook destruction — small, concrete, reproducible).
- F2e: survived live, with a model-demonstrated new permanent-poison hazard from negative
  caching.
- **Safe to share as a DRAFT PR? Yes, as a prototype — but fix NF1 first** (it is a
  one-line change and it breaks documented public API on every produced chain); disclose
  NF2/NF3 in the PR text (both acceptable for a prototype: an address-collision caveat and
  a "not thread-safe, and a failed discovery is cached" note). The gate + cache themselves
  do exactly what the addendum claims with no regression found on AMD64 or non-AMD64.

## Reviewer limitations

Fresh context but same model family as the implementer (systematic, not statistical,
independence); single environment (macOS arm64, one angr build); the live thread race was
not reproduced (only modeled); the mapped-segment collision (F2c) and the pin-arg clobber
(NF4) were argued but not constructed; pristine control was via `git stash` (identical
failure set, but only one run each). Probes in `probes2/`, none of the package's own
scripts reused; angrop-src left with the v2 patch applied (`git diff --stat` verified;
returning chains build in the final state).

## Repro index

```
./venv/bin/python -I probes2/c1_exec_oracle.py        # C1 real-callee exec oracle (dual call, trace, sentinel)
./venv/bin/python -I probes2/c1b_hooked.py            # C1 unmodified-binary variant (args + sentinel)
./venv/bin/python -I probes2/find_copy_project_leak.py# NF1 project=None leak + blast radius
( cd angrop-src && ../venv/bin/python -m pytest tests/test_chainbuilder.py -q )   # 53/53
( cd angrop-src && ../venv/bin/python -m pytest tests/ -q )                       # 126/9, == pristine set
./venv/bin/python -I probes2/f1a_arm_census.py        # F1a census + instant None + no hook/cache
./venv/bin/python -I probes2/pristine_control.py      # F1c/A2 pristine-vs-patched scenarios (stash control)
./venv/bin/python -I probes2/f2b_cache_integrity.py   # F2b aliasing/staleness/negative cache
./venv/bin/python -I probes2/f2c_hook_hygiene.py      # NF2 user-hook destruction
./venv/bin/python -I probes2/f2d_costs.py             # F2d 0.1068→0.0148, nrFalse skip, candidate order
./venv/bin/python -I probes2/f2e_race.py              # NF3 poison model + live 4-thread race
# A1 (no stash needed):
git -C angrop-src show 7976832:angrop/chain_builder/func_caller.py > /tmp/a1rt/angrop/chain_builder/func_caller.py
# then git apply returning-ret2csu.diff in /tmp/a1rt and diff against the working tree -> identical
```
