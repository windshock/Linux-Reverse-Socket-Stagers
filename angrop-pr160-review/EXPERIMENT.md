# Experiment block (security-hypothesis-lab discipline)

Question:
  Is func_call's failure on the full gadget set caused specifically by the
  `move.to_reg not in hard_regs` rejection at func_caller.py ~239, in the REAL
  code path (not my hand-reimplementation of the condition)?

Facts (directly observed):
  - unexploitable has __libc_csu_init, zero `pop rdx`.
  - default find_gadgets() discovers csu dispatch 0x4005D0 (jmp_mem,
    reg_moves r15->rdx,r14->rsi,r13->rdi) and csu pop 0x4005E6.
  - real func_call: PASS with 2-gadget DB (rdx controlled), FAIL with 109-gadget DB.
  - In a HAND-REPLICATED copy of the line-239 condition: skip=False in A, skip=True
    in B (tripped on a move whose to_reg is directly settable).

Premises (assumed, not yet directly observed):
  - The real func_call fails in B for the SAME reason my replication skips
    (i.e. line 239, not some other RopException downstream).

Hypothesis:
  - Relaxing ONLY line 239 (drop `to_reg not in hard_regs`, keep from_reg conflict
    guard, require the gadget to cover >=1 hard arg reg) flips B to PASS, and the
    resulting chain actually contains the csu dispatch 0x4005D0.

Next experiment:
  - Patch func_caller.py line 239 region minimally in the editable clone.
  - Rerun REAL func_call: B (expect PASS + chain uses 0x4005D0), A (expect still PASS),
    upstream test_unexploitable (expect still PASS). One variable changed.
  - Revert patch; confirm B returns to FAIL (before/after comparison).

Exit rule:
  - confirm if: patched B PASSes with rdx=0x43..434 AND chain includes 0x4005D0,
    AND A + test_unexploitable still pass, AND reverting restores B=FAIL.
  - falsify if: patched B still FAILs, or passes WITHOUT using csu (other path),
    or the patch breaks A / test_unexploitable (cause mis-identified).
  - invalid if: the patch changes behavior beyond the selection guard, or the
    harness (bootstrap, gadget set) differs between runs.

Conclusion strength target: lab-proven on `unexploitable` (angr 10.0.7 / angrop HEAD).
NOT target-proven (not run in upstream CI). The proposed FIX remains hypothesis-only
until this flip test passes.

## Result: CONFIRMED (lab-proven)

Before/after/revert (real func_call on unexploitable, single variable = line-239 guard):
- BEFORE  : B(109) FAIL ; A(2) PASS uses_csu
- AFTER   : B(109) PASS, rdx=0x43..434, ip->sleep, chain = csu dispatch 0x4005ca
            (xor ebx,ebx; mov rdx,r15; ...; call [r12+rbx*8]) + csu pop 0x4005f0.
            => genuine ret2csu. "uses_csu=False" earlier was a checker artifact
            (hardcoded 0x4005D0; angrop entered the csu block at 0x4005ca/0x4005f0).
- REVERTED: B(109) FAIL again. Loop closed.

Root cause CONFIRMED: func_caller.py ~239 `move.to_reg not in hard_regs` rejects a
multi-move jmp_mem gadget unless EVERY destination reg is hard. Realistic binary
(pop rdi/rsi present, no pop rdx) => hard={rdx} => csu discarded => rdx unsettable
=> func_call fails. Works only when all arg regs are hard (narrowed DB), which is
why upstream test_unexploitable narrows via analyze_gadget.

Harness artifacts caught by the skill discipline:
- rootcause.py re-implemented the condition (Pattern 5) -> replaced by real-code flip.
- uses_csu checker hardcoded 0x4005D0 (false negative) -> resolved by disassembly.

Still OPEN (not proven):
- Full angrop suite regression of the one-guard relaxation (needs angr/binaries).
  Reasoning only: relaxed code sits in the func_jmp fallback (reached after
  self-contained set_regs fails), so normal pop-based calls shouldn't be affected.
- Not target-proven (not run in upstream CI; not end-to-end on lab3).

## Intent + regression (round 2, prompted by "was it narrowed on purpose?")

Git archaeology of the guard (func_caller.py ~239):
- ef90763 (2025-02, Kyle Zeng) "draft of func_jmp_gadgets": NO guard — used any
  move-gadget touching a needed reg (more permissive than my relaxation).
- 8102d80 (2026-01, Kyle Zeng) "Feat/ropbot (#136)": ADDED
  `if move.from_reg in hard_regs or move.to_reg not in hard_regs: skip`.
  => The restriction is INTENTIONAL, added by the maintainer (= Kyle-Kyle, the PR
     commenter). NOT an oversight. The commit msg does not state why (big refactor).

Full suite, with keystone (brew libkeystone + DYLD_LIBRARY_PATH, setuptools for
distutils on py3.12):
- BASELINE (unpatched): tests/test_chainbuilder.py  => 53 passed
- PATCHED  (relax 239):  tests/test_chainbuilder.py  => 53 passed
=> my one-line relaxation breaks NOTHING, and NO existing test requires it.

Why the suite can't see scenario B: the only ret2csu test (test_unexploitable)
narrows the gadget DB via analyze_gadget to the 2 csu gadgets = scenario A, which
passes before and after. There is no test exercising func_call ret2csu on a full
gadget set. So the suite is blind to the B failure either way.

Open (NOT resolved):
- WHY the guard was added (no stated rationale) — likely a pruning heuristic
  ("don't use a move-gadget for a reg you can set directly"); side effect: rejects
  partial-use of csu (csu for rdx only) on realistic binaries. HYPOTHESIS, not confirmed.
- Whether the maintainer views B as a bug or as "not what func_call is for". His PR
  comment implies he believes ret2csu is picked up automatically — but that may rest
  on the narrowed test.
- Continuation correctness: all ret2csu passes were checked at the call entry
  (register values), NOT return/continuation. csu `call [mem]` is modeled as jmp_mem
  (ignores the post-call csu epilogue). Fine for fire-and-forget final stages; UNVERIFIED
  for needs_return=True / chained calls. The guard relaxation does not address this.

Conclusion strength:
- lab-proven: guard is intentional; B fails on full set; relaxing it fixes B and
  passes the full chainbuilder suite.
- hypothesis-only: the *reason* for the guard, whether B is considered a defect, and
  whether the relaxation is correct in general (continuation + non-x86 + chains).
=> Right move is to ASK the maintainer why #136 added the guard, with the minimal
   repro, not to assert he was wrong.
