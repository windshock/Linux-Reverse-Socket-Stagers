# Empirical findings — angrop ret2csu / PR #160

Env: angr 10.0.7, angrop @ upstream HEAD (editable clone, 9.2.13.dev0), claripy 9.3.7,
Python 3.12, macOS arm64. Binary: angr/binaries `tests/x86_64/unexploitable`
(has `__libc_csu_init`, zero `pop rdx` gadgets — canonical ret2csu target).

## What angrop already does (contrary to my original PR framing)

- Default `find_gadgets()` DOES discover the csu dispatch `0x4005D0`
  (`mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]`) and the csu
  pop gadget `0x4005E6`.
- The dispatch is classified `transit_type = jmp_mem` with
  `reg_moves = [r13->rdi, r14->rsi, r15->rdx]`. So the `call [mem]` IS modeled,
  and angrop knows it moves values into the arg registers.
- `func_call` already knows how to use it: with a gadget DB restricted to the two
  csu gadgets, `func_call("sleep", [0x41414141, 0x42..64.., 0x43..64..])` builds a
  working chain and controls rdi/rsi/**rdx** (verified by concrete exec).
  This matches the existing upstream test `test_unexploitable`.

=> A dedicated hardcoded `ret2csu()` that takes explicit gadget addresses is the
   wrong abstraction. The maintainer is right that this comes (largely) for free.

## The reproducible gap

`func_call("sleep", [a,b,c])` on the SAME binary:

| setup                                   | gadgets | csu in func_jmp pool | result |
|-----------------------------------------|---------|----------------------|--------|
| A: only the 2 csu gadgets (analyze)     | 2       | yes                  | PASS (rdx controlled) |
| B: default find_gadgets()               | 109     | yes                  | FAIL ("fail to invoke function: sleep") |
| C: B + needs_return=False               | 109     | yes                  | FAIL |
| D: B + re-analyze the csu gadgets       | 111     | yes                  | FAIL |

So it is NOT a discovery problem and NOT a classification problem. With the full,
realistic gadget set, func_call cannot assemble the ret2csu chain even though the
csu gadgets are present and in `_func_jmp_gadgets`. It only succeeds when the DB is
narrowed to the csu gadgets (which is effectively what the upstream test does via
`analyze_gadget`). The automatic ret2csu path is fragile under a full gadget set.

## Exact root cause (verified)

`func_caller.func_call`, the func_jmp selection loop, line ~239:

```python
hard_regs = [x for x in registers if not reg_setter.can_set_reg(x)]
...
for move in g.reg_moves:
    if move.from_reg in hard_regs or move.to_reg not in hard_regs:
        skip = True; break      # <-- discards the whole gadget
```

The rule only keeps a multi-move gadget if EVERY one of its destination registers is
"hard" (not directly settable). The csu dispatch moves r15->rdx, r14->rsi, r13->rdi.

Verified on `unexploitable`:
- A (2 gadgets): can_set_reg rdi=rsi=rdx = False  => hard={rdi,rsi,rdx}
  => no move trips the test => csu kept => chain built, rdx controlled. PASS
- B (109 gadgets): can_set_reg rdi=True, rsi=True, rdx=False => hard={rdx}
  => move r14->rsi trips `to_reg not in hard_regs` (rsi is directly settable)
  => csu gadget skipped entirely => nothing else sets rdx => FAIL.

So the partial-use case — "use csu only for the reg I can't set otherwise (rdx), and
set rdi/rsi by normal pops" — is unsupported. On any realistic binary that has
`pop rdi`/`pop rsi` but no `pop rdx`, the csu dispatch is always discarded, so
`func_call`'s ret2csu path fails precisely in the common case. It succeeds only on a
degenerate binary where none of rdi/rsi/rdx are directly settable.

Fix direction: relax the selection so a move-gadget is usable when it supplies at
least one otherwise-unsettable arg reg, setting the remaining destinations as extra
constrained regs (they already flow through set_regs). That makes the existing
ret2csu path fire from the full gadget set — no hardcoded frame builder needed.

## Takeaway for the PR

Reframe away from a hardcoded frame builder toward either:
1. strengthening `func_call`/reg_setter so the existing ret2csu path is assembled
   reliably from the full gadget set (repro above as the regression test), and/or
2. a `mem_func_call(table_ptr, index, args)` that deterministically uses the csu
   pop+dispatch when arg regs can't be set directly — i.e. the maintainer's
   suggestion, grounded by the failing case.

Repro scripts: run_test.py, probe.py, diag.py (this dir).
