# Adversarial review brief — try to BREAK this patch

You are an independent reviewer. Your job is **not** to confirm the author's claims — it is
to **falsify** them. Assume the author (another LLM) is biased toward its own conclusion and
may have built a harness that only proves what it wanted. Regenerate the evidence yourself;
do not trust the files in `evidence/`. If you cannot break a claim after genuinely trying,
only then report it as surviving.

The change adds **returning / chainable ret2csu** auto-assembly to angrop's `func_call`.
Patch: `returning-ret2csu.diff` (one file, `angrop/chain_builder/func_caller.py`). Design:
`DESIGN-returning-ret2csu.md`. Known unknowns (author's own): `REVIEW-BLINDSPOTS.md`.

---

## 0. Reproduce from scratch (do not trust prebuilt state)

```bash
cd angrop-pr160-review
./setup.sh                          # venv + angr 10.0.7 + angrop@7976832 + bins/ (vendored)
# baseline (PRISTINE angrop): confirm the failure the patch claims to fix
./venv/bin/python scripts/lab3_targetproof.py   # expect: every call form RAISES
# apply the patch
( cd angrop-src && git apply ../returning-ret2csu.diff )
# after: build the gadget cache once, then run the checks
( cd ..; )   # scripts read ./bins/* and write ./gadgets.cache in the cwd you run them from
./venv/bin/python scripts/harness.py        # builds gadgets.cache; shows chains now BUILD
./venv/bin/python scripts/validate.py       # the oracle (see §2) — must independently pass
./venv/bin/python scripts/discover_test.py  # B1 discovery output
./venv/bin/python scripts/lab3_targetproof.py   # expect: every call form now BUILDS
# regression (keystone needed; on macOS: brew install keystone + DYLD_LIBRARY_PATH)
( cd angrop-src && DYLD_LIBRARY_PATH=/opt/homebrew/lib \
    ../venv/bin/python -m pytest tests/test_chainbuilder.py -q )
```
Note: `validate.py` / `discover_test.py` load `gadgets.cache`, so run `harness.py` first.
If HEAD has moved, the diff may need a rebase — report if it doesn't apply cleanly.

---

## 1. The claims, with the author's stated strength — attack each

| # | Claim | Author strength | Try to break it by… |
|---|---|---|---|
| C1 | Pristine angrop cannot auto-assemble a returning ret2csu (`func_call`) | target-proven | find ANY existing API/flag on pristine angrop that produces a returning, chainable ret2csu for `bins/vuln_client3` without the patch |
| C2 | Patched `func_call(...,needs_return=True)` builds a chain that executes correctly | target-proven | see §2 — attack the oracle |
| C3 | The chain returns & chains (`chain+chain`) | target-proven | check `next_pc_idx()` is genuinely a controllable slot, not a fixed/garbage value; verify `chain+chain` actually executes, not just constructs |
| C4 | B1 discovers `cleanup_slots`/pins (not hardcoded) | lab-proven | grep the diff for a literal `7` or `rbp`/`rbx` constant in the discovery path; feed a gadget where the real answer ≠ 7 and see if it adapts |
| C5 | 53/53 chainbuilder tests pass | lab-proven | re-run yourself; also run the FULL test dir, not just chainbuilder |
| C6 | No harmful side effects | **hypothesis-only** | this is the open one — see §3 and `REVIEW-BLINDSPOTS.md` |

---

## 2. Attack the oracle (`scripts/validate.py`) — the most important target

The oracle hooks `net_send` with a SimProcedure that **just records edi/rsi/rdx and
returns 0**. Question its validity hard:
- Does hooking the function to a trivial return **hide** any failure that the real function
  (with real stack/socket effects) would cause? Argue whether the ret2csu *mechanism*
  (register setup + control returning via the csu epilogue) is actually independent of the
  callee's body. If you think the hook over-simplifies, construct a case where it matters.
- The oracle asserts `final pc is symbolic`. Is "symbolic pc" really equivalent to "returned
  to a controllable next_pc"? Could the chain reach a symbolic pc via a *wrong* path (e.g.
  the csu loop not exiting, or an unintended branch)? Trace the executed addresses and
  confirm the path is loader → dispatch → callee → **csu epilogue** → ret, not something else.
- Re-derive the expected byte layout from `scripts/lowlevel.py` (target-proven by hand) and
  check angrop's produced chain reduces to it. Mismatch = bug.

---

## 3. Specific side effects to probe (don't just read — test)

1. **Guard relaxation (Blocker A).** The diff relaxes a guard added intentionally in angrop
   commit `8102d80` (ropbot), rationale undocumented. Construct a binary/gadget set where
   the relaxed guard makes `func_call`/ropbot pick a **worse** or **wrong** gadget, or blows
   up search. The suite's own ret2csu test (`test_unexploitable`) seeds only csu gadgets and
   **never hits this guard** — so the green suite does NOT cover the relaxation. Exploit that.
2. **`needs_return=None` semantics changed** to prefer a returning csu call. Find a caller or
   test where the old fire-and-forget (shorter) behavior was assumed.
3. **`copy.copy(g)` with overridden `stack_change`/`pc_offset`.** Look for other code paths
   (chain verification, dedup/caching, IBT/endbr, `__add__`) that read a jmp_mem gadget's
   true post-call fields and would misbehave on the synthesized copy.
4. **Discovery false-positive.** Find a non-csu `jmp_mem` gadget whose `pc_target` parses as
   `base + idx*scale` and check whether `_try_csu_return` wrongly produces a "returning" chain
   for it that does NOT actually return.
5. **Only x86-64 tested.** Check other arches aren't silently affected beyond the suite.

---

## 4. What a fair report looks like

For each claim: state whether you **broke it**, **failed to break it after real effort**, or
**it's out of scope to test**. Give the concrete command/input you used. Flag any place where
the author's harness could only have produced a confirming result (harness bias). Do not
inherit the author's framing — if you think the whole approach is wrong (e.g. this belongs in
a separate `mem_func_call`, or discovery-per-call is too costly), say so with reasoning.

Deliverables the author will act on: (a) any broken claim with repro, (b) any new side effect
not already in `REVIEW-BLINDSPOTS.md`, (c) a verdict on whether this is safe to share as a
*draft* PR (prototype) — not whether it's merge-ready.
