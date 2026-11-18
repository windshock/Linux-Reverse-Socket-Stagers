# Review blind spots — what the patch's author (me) cannot verify, but the maintainer can

This accompanies `returning-ret2csu.diff` / `DESIGN-returning-ret2csu.md`. The patch is
**target-proven for its goal** (returning, chainable ret2csu — see `evidence/`) and passes
the full chainbuilder suite (**53/53**). But "passes the tests" ≠ "no side effects." The
items below are side effects I could **not** rule out by running code, because they depend
on undocumented design intent or on behavior the test suite does not exercise. They are
written as questions for the maintainer (@Kyle-Kyle), who has the design knowledge.

Conclusion-strength reminder: *goal achieved* = target-proven; *no harmful side effect* =
**hypothesis-only (unverified)**.

---

## 0. The sharpest one: the test suite does not cover the region I changed

`tests/test_chainbuilder.py` is ~92% authored by the maintainer (git blame: 1196/1303
lines). Its ret2csu coverage is `test_unexploitable`, which **seeds only the csu gadgets**,
so it **side-steps the Blocker A guard entirely** — the guard never fires in that test.

Consequence: "53/53 pass" says very little about the safety of *relaxing that guard on a
full gadget set*, because the suite's ret2csu path never hits the guard in that scenario.
The green suite is a floor ("these behaviors still work"), not a ceiling ("nothing else
changed"), and it has a known hole exactly where this patch operates.

**Ask:** is there an off-suite scenario (ropbot on a real/large binary) that the guard was
protecting and that `test_unexploitable` deliberately does not represent?

---

## 1. Why does the Blocker A guard exist? (relaxation safety)

The guard at `func_caller.py` (`move.to_reg not in hard_regs → skip`) was added
intentionally in commit `8102d80` ("Feat/ropbot (#136)"), with **no rationale in code,
commit message, or tests**. The most plausible purpose is keeping ropbot's
register-selection search tractable (avoiding combinatorial blow-up).

- What I did: relaxed it only on the func_jmp path — keep a multi-move gadget if it supplies
  ≥1 otherwise-unsettable arg reg.
- What I verified: functional correctness (53/53) + the ret2csu target.
- What I could **not** measure: ropbot search time / chain-quality on large binaries, which
  is exactly the non-functional property a tractability guard would protect — and which no
  functional test would reveal.

**Ask:** does relaxing this guard (even path-gated) regress ropbot's search space or runtime?

---

## 2. Changed semantics of `needs_return=None`

Previously `needs_return=None` → fire-and-forget (shorter chain). My patch makes `None` try
a **returning** csu call first, falling back to terminal.

- What I could **not** know: whether internal callers (ropbot, other builders) or users rely
  on the old shorter/terminal behavior for `None`, and whether the longer returning chain
  changes downstream chain assembly or sizes in ways tests don't check.

**Ask:** is it safe to make `None` prefer a returning chain, or must `None` stay terminal?

---

## 3. Mutating gadget fields via `copy.copy(g)` (B2)

I shallow-copy the dispatch gadget and override `stack_change` (-8 → 64) and `pc_offset`
(None → cleanup_slots) so the existing return loop lays the frame.

- What I could **not** rule out: other code paths (chain verification, gadget dedup/caching,
  IBT/endbr handling, `__add__` merging) relying on a jmp_mem gadget's *true* post-call
  semantics, which the synthesized returning copy contradicts in cases not in the suite.
  A shallow copy also shares nested objects.

**Ask:** are there invariants on jmp_mem gadgets elsewhere that an overridden copy breaks?

---

## 4. Discovery false-positives and cost (B1)

`_discover_csu_epilogue` runs a bounded symbolic execution per csu-like gadget per
`func_call`. It hooks a scratch address (unhooked in `finally`).

- What I could **not** fully verify: (a) a non-csu gadget whose `pc_target` happens to parse
  as `base + idx*scale` being mistaken for a returning csu dispatch and yielding a wrong
  chain the oracle wouldn't catch on every target; (b) the per-call symbolic-exec cost at
  scale; (c) re-entrancy / concurrent use of the shared project around the temporary hook.

**Ask:** acceptable to run discovery inline, or should it be cached / moved to gadget
classification? Any gadget shapes that would false-match the parser?

---

## 5. Architectures other than x86-64

I measured only on x86-64 (`bins/vuln_client3`, `unexploitable`). On other arches the
parser returns `None` (safe fallback to existing behavior), and the suite covers
i386/arm/aarch64 func_call. But "safe fallback" is confirmed only to the suite's extent.

**Ask:** any arch where the csu-style `call [base+idx*scale]` shape differs enough that the
parser/discovery should be explicitly gated?

---

## How to read this

None of the above is a known bug — each is an **unknown I cannot close without the
maintainer's design knowledge or broader off-suite testing**. Presenting the patch as a
*prototype with these questions attached* (not as a proven-safe change) is the honest frame:
"here is a working mechanism and independent evidence; these five+one areas need your
judgment or a wider test."

---

## Update 2026-11-18 — blindspots #4b and #5 addressed in the diff (post-review fixes)

The independent adversarial review (`INDEPENDENT-REVIEW-VERDICT.md`) found two of the
unknowns above are NOT benign, and the diff now contains the fixes (still one file,
`func_caller.py`, now +182/−13):

- **#5 (other arches) — the "safe fallback" assumption was wrong.** Real ARM glibc 2.31
  contains 4 jmp_mem gadgets whose pc_target parses as csu-style (`0x4b985f/0x4b9861/
  0x4b9863/0x44361f`), and running discovery on the first one stalled >11 min CPU
  (vs 0.09s/gadget on AMD64). Fix: `_discover_csu_epilogue` now returns None unless
  `project.arch.name == "AMD64"` — non-x86-64 falls back to the old terminal behavior
  until the mechanism is proven there. Measured after the fix: all 4 ARM gadgets →
  None in 0.00s.
- **#4b (per-call cost) — confirmed real, now cached.** Measured 0.106s per returning
  `func_call` on the lab target, all of it discovery, re-paid on every call. Fix:
  per-gadget-addr cache on the FuncCaller (None results cached too); after the first
  call, subsequent returning `func_call`s drop to 0.015s.

Regression state after both fixes: `tests/test_chainbuilder.py` 53/53; lab3 target-proof
all BUILT; independent exec-level oracle (dual-call + trace + sentinel) PASS.
Still open for the maintainer: #1 (guard rationale), #2 (None semantics — measured
pristine 9-word terminal vs patched 17-word returning on the seeded scenario), #3
(no copy.copy leak found), #4a (parser matches a pure `jmp [base+idx*8]` shape; still
semantically correct for returning callees, unchanged by these fixes).

---

## Update 2026-11-19 — INDEPENDENT v2 review (V2-ADVERSARIAL-VERDICT.md): one claim above was FALSE

A fresh-context agent re-reviewed the v2 diff with its own probes (`probes2/`), per the
package's methodology (the 2026-11-18 fixes were implemented by the same agent that
wrote the 11-17 review, so they were NOT independent — this second pass is). Results:

- **My "#3 no copy.copy leak found" above was FALSE (finding NF1, now fixed).**
  `copy.copy(g)` routes through `RopGadget.__getstate__` (which nulls `project` for
  pickling), so the synthesized returning gadget had `project=None`, and
  `str(chain)`/`dstr()`/`payload_code()` raised AttributeError on EVERY returning
  chain (reproduced: `print(chain)` crashed). Fix applied: `g2 = g.copy()`
  (RopGadget.copy preserves project) — diff is now +185/−13, round-trip re-verified;
  post-fix: 53/53, lab3 all BUILT, both oracles PASS, `str(chain)` renders correctly.
- **NF2 (disclose, pre-existing from the original B1 code):** discovery hooks scratch
  address 0x43430000 with `replace=True` and unhooks in a `finally` — a USER hook
  already installed at that address is silently destroyed. A mapped-segment collision
  was argued out of scope. Suggested PR-text disclosure (or save/restore the prior hook).
- **NF3 (disclose, NEW with F2):** the pre-existing transient hook race becomes STICKY
  under negative caching — a raced unhook can cache a permanent `None`, making later
  returning `func_call`s hard-fail. Live 4-thread race was clean; hazard is model-level.
- Everything else SURVIVED genuine attack: core mechanism re-proven with an independent
  dual oracle (real machine-code callee + sentinel), suite full-dir failure set identical
  to pristine (control), ARMEL census exactly the 4 reported addrs (discovery None in
  0.0000s), gate proven sole-entry and cost-only residual on non-Linux AMD64, cache
  proven correct across different target functions from one entry, no aliasing/mutation,
  costs re-measured (0.1068s→0.0148s, n=20), diff round-trip byte-identical, 53/53.

Net verdict (per the independent reviewer): safe to share as a DRAFT PR after NF1 —
now fixed — with NF2/NF3 disclosed in the PR text. Remaining for the maintainer:
#1 (guard rationale), #2 (None semantics).
