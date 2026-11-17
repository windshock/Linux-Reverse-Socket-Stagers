# Design sketch — returning / chainable ret2csu in angrop

Goal: let `func_call()` (or a discovery-based `mem_func_call`) auto-assemble a
**returning** ret2csu on a non-PIE, no-`pop rdx` target, so `leak → recv stage-2 →
pivot` composes in one chain — the thing `scripts/lowlevel.py` already does by hand.

This is the implementation-side companion to `SUMMARY.md` §5 (Blockers A + B) and the
oracle is `scripts/lowlevel.py`. Everything here is anchored to
`angrop/chain_builder/func_caller.py` at HEAD `7976832`.

Status of each piece: **[DONE]** verified, **[DESIGN]** proposed here, **[OPEN]** needs a decision/experiment.

---

## 0. STATUS — IMPLEMENTED & VERIFIED

The first-PR scope (A + B1–B4) is **built and target-proven**. Patch:
`returning-ret2csu.diff` (+163/-13 in `func_caller.py`). Evidence in `evidence/`:

- **Oracle (symbolic exec, `scripts/validate.py`):** patched `func_call(net_send,
  [fd,buf,len], needs_return=True)` produces a chain that executes correctly —
  `edi=fd, rsi=buf, rdx=len` at the call, and control **returns** to a symbolic next_pc.
  `chain + chain` composes (the open3 blocker is gone). → `evidence/validate_oracle_AFTER.txt`
- **lab3 target-proof flipped (`scripts/lab3_targetproof.py`):** every call form that used
  to RAISE now BUILDS — returning `net_send`/`send`/`net_recv`, **and the chained
  `net_send(...) + net_recv(...)`** (leak→stage-2 in one chain).
  → `evidence/lab3_targetproof_AFTER.txt`
- **Regression:** `tests/test_chainbuilder.py` **53/53 pass** (both the hardcoded and the
  discovery-based B1). → `evidence/pytest_chainbuilder_AFTER.txt`
- **B1 is real discovery, not a glibc hardcode:** symbolic execution recovers
  `cleanup_slots = 7` and the required `pins = {rbx:0, rbp:1}` automatically
  (`scripts/discover_test.py`).

What's deliberately left for a follow-up: multi-entry tables (idx≠0), lifting B1/B2 into a
first-class `call_mem` transit type, and per-gadget caching of discovery. See §7.

**Important — this patch is a prototype, not a proven-safe change.** "53/53 pass" ≠ "no
side effects." The side effects I could not rule out by running code (they need the
maintainer's design knowledge, e.g. *why the Blocker A guard exists* and what it protects in
ropbot's search) are enumerated in **`REVIEW-BLINDSPOTS.md`** — including the sharp point
that the suite's own ret2csu test (`test_unexploitable`) side-steps the guard, so the green
suite says little about the exact region this patch touches.

---

## 1. Ground truth — what a working returning ret2csu looks like

From `scripts/lowlevel.py` (target-proven on `bins/vuln_client3`), the chain is a
**two-gadget composite plus a cleanup tail**:

```
           stack (low -> high)                 what consumes it
  ---------------------------------------------------------------------
  [ rbx=0 ]  \                                 LOADER gadget:
  [ rbp=1 ]   |                                  pop rbx;rbp;r12;r13;r14;r15;ret
  [ r12=fd ]  |  6 pops  (loop idx, loop cap,     (sets the 6 csu input regs)
  [ r13=buf ] |          + the 3 args + table)
  [ r14=len ] |
  [ r15=TAB] /
  [ DISPATCH ] <- loader's ret lands here      DISPATCH gadget:
                                                 mov rdx,r14; mov rsi,r13;
                                                 mov edi,r12d; call [r15+rbx*8]
                                                 -> calls table[0](edi,rsi,rdx)
  [ fill ] \                                    CSU EPILOGUE (runs after the call
  [ fill ]  |                                   returns, because rbx+1==rbp so the
  [ fill ]  |  7 "cleanup" slots                loop exits):
  [ fill ]  |  = add rsp,8 (1) + 6 pops (6)       add rbx,1; cmp rbx,rbp; jne ..;
  [ fill ]  |                                      add rsp,8; pop rbx;rbp;r12..r15; ret
  [ fill ]  |
  [ fill ] /
  [ NEXT_PC ] <- epilogue's final ret           continue the chain here
```

Key facts this layout encodes (each is a requirement for the builder):
- **R1** the 6 csu input regs are set by the LOADER (`set_regs` can already do this).
- **R2** `rbx=0, rbp=1` are not "args" — they are **loop-control**: they make the csu
  epilogue loop run exactly once so control returns. The builder must pin them.
- **R3** `r15 + rbx*8 == &table_entry`, and `table[0]` is the function pointer
  (`ptr_to_func`). angrop's `jmp_mem_target` constraint path already expresses this.
- **R4** after the `call` returns there are **exactly 7 cleanup slots** then the real
  return slot. 7 = `add rsp,8` (1) + 6 pops. This count is **glibc/layout specific** and
  must be *discovered*, not hardcoded.

---

## 2. What angrop already gives us (do NOT rebuild these)

### 2a. The returning machinery already exists in `_func_call`  **[DONE-reading]**
`func_caller.py:148-166`:
```python
# recover stack from previous gadget effect.
for delta in range(func_gadget.stack_change//arch_bytes):
    if func_gadget.pc_offset is None or delta != func_gadget.pc_offset:
        chain.add_value(self._get_fill_val())
    else:
        chain.add_value(claripy.BVS("next_pc", self.project.arch.bits))
```
This loop lays out *exactly* `[fill]*k + [next_pc]` driven **only** by
`func_gadget.stack_change` and `func_gadget.pc_offset`. If the dispatch gadget carried
`stack_change = (7+1)*arch_bytes` and `pc_offset = 7`, this loop would emit the §1 tail
verbatim. **So the return layout is not missing — it is mis-parameterized for `call [mem]`.**

### 2b. The arg→csu-reg remapping already exists  **[DONE-reading]**
`func_caller.py:242-249` rewrites `{rdi,rsi,rdx} -> {r12,r13,r14}` using the dispatch
gadget's `reg_moves`, so `set_regs` ends up setting the loader regs. (This is R1.)

### 2c. The jmp-target constraint already exists  **[DONE-reading]**
`func_caller.py:135-142` + `259-260` constrain `pc_target == ptr_to_func`, i.e. R3.
`_find_function_pointer` resolves `ptr_to_func` (GOT/PLT or a data scan).

### 2d. `set_regs` can set the 6 csu input regs in one gadget  **[DONE]**
Target-proven (`scripts/lowlevel.py` Part 1; `scripts/lab3_why.py`).

**Net:** R1, R3 are covered; the return loop (2a) is covered *if fed the right fields*.
The gaps are R2 (loop-control pinning) and R4 (discovering the 7-slot epilogue), plus two
guards that stop the flow before it reaches 2a.

---

## 3. The exact gap — measured fields of the dispatch gadget  **[DONE]**

Measured on `bins/vuln_client3`, angrop HEAD `7976832` (`scripts/probe_fields.py`,
83 gadgets found):

| addr | transit_type | stack_change | pc_offset | reg_moves | pc_target |
|---|---|---|---|---|---|
| 0x401510 (dispatch, canonical) | `jmp_mem` | **-8** | **None** | `r14→rdx, r12→rdi, r13→rsi` | `r15 + rbx*8` |
| 0x401511 (dispatch, alt entry) | `jmp_mem` | -8 | None | `rsi→rdx, r12→rdi, r13→rsi` | `r15 + rbx*8` |
| 0x40152a (loader) | `pop_pc` | 56 (=7·8) | 48 (=6·8) | — | — |

Hypothesis **confirmed**. Two things fall out:

1. **`pc_offset = None`** → pc is taken from memory (`[r15+rbx*8]`), not a stack slot, so
   §2a's loop would never place a `next_pc`.
2. **`stack_change = -8`** (not 0, not +N): angrop accounts only the return address the
   `call` *pushes*, and models **nothing after the call returns**. Plugged into §2a:
   ```python
   for delta in range(func_gadget.stack_change // arch_bytes):   # range(-8 // 8) == range(-1)
   ```
   `range(-1)` is **empty** → zero cleanup slots, zero `next_pc`. The csu epilogue
   (`add rsp,8` + 6 pops + ret) is invisible to angrop. **This is the precise mechanical
   form of Blocker B.**

The loader (0x40152a) is a normal self-contained `pop_pc` gadget — `set_regs` uses it to
set the 6 csu input regs (R1), exactly as `scripts/lowlevel.py` does. So the only
mis-modeled piece is the dispatch gadget's post-call accounting.

Note `pc_target = r15 + rbx*8` (symbolic) is exactly R3, and the `reg_moves` are exactly
R1's remap source — both already present, confirming §2b/§2c need no new work.

---

## 4. Blocker A — the register-selection guard  **[DONE]**

`func_caller.py:238-241`. The original guard keeps a multi-move gadget only if *every*
destination is "hard" (unsettable); the csu dispatch also moves into `rdi`/`rsi` (settable)
so it is dropped wholesale. `candidate-relaxation.diff` keeps the gadget if it supplies
≥1 otherwise-unsettable arg reg. Verified: flips the full-set case FAIL→PASS, 53/53
chainbuilder tests still pass. **Scope note:** relax this only on the ret2csu/func_jmp
path, not globally, to preserve ropbot's search tractability (the guard's original intent).

---

## 5. Blocker B — make the csu dispatch return  **[DESIGN]**

The whole fix is: **teach the builder the post-call epilogue, express it as
`stack_change`/`pc_offset` on the dispatch gadget, pin the loop-control regs, and stop
pre-emptively refusing `needs_return`.** Then §2a does the rest.

### Step B1 — discover the epilogue (R4)  **[DESIGN]**
From the instruction *after* the `call [mem]` site, symbolically execute (concrete stack,
`table[0] -> ret` so the call returns immediately) until the function's `ret`, counting
the net stack pop. That yields `cleanup_slots` (expected 7 here) and confirms pc is taken
from `stack[cleanup_slots]`. This is the one genuinely new analysis. It belongs next to
gadget classification, not in `func_caller` — see §6.
- Reuse `scripts/lowlevel.py`'s method as the reference implementation and as the test
  oracle (it already walks exactly this path).

### Step B2 — carry the epilogue on the gadget  **[DESIGN]**
Represent the returning dispatch so that `_func_call`'s §2a loop fires correctly. With the
measured `cleanup_slots = 7` (§3), the fields must become:
- `stack_change = (cleanup_slots + 1) * arch_bytes = 8 * 8 = 64`   (today: **-8**)
- `pc_offset   = cleanup_slots = 7`                                (today: **None**)
Then §2a runs `range(64//8) = range(8)`, emitting `[fill]*7` for `delta 0..6` and a
`next_pc` BVS at `delta == 7` — byte-for-byte the `scripts/lowlevel.py` tail
(`[fill]*7 + [NEXTPC]`).

Two ways to deliver this (pick in §6): (i) a new `transit_type='call_mem'` computed at
classification time (so stack_change/pc_offset come out right natively); or (ii) synthesize
a `FunctionGadget`-like wrapper in the func_jmp path that overrides these two fields for the
csu case. (i) is the "proper" model; (ii) is the smaller, localized first PR.

### Step B3 — pin loop-control regs (R2)  **[DESIGN]**
Add `rbx=0, rbp=1` (generally: `rbx = idx`, `rbp = idx+1` for a single dispatch) to the
`registers` dict that `set_regs` receives, alongside the R3 constraint on `r15`/`rbx`.
Note `rbx` is shared between R2 (loop index) and R3 (`[r15+rbx*8]`) — they must agree:
`rbx=0` ⇒ table entry 0 ⇒ `r15 == ptr_to_table_entry0`. Keep them consistent.

### Step B4 — stop refusing the return  **[DESIGN]**
`func_caller.py:214-217` raises when `needs_return` and the self-contained path failed:
```python
needs_return = kwargs.get("needs_return", None)
if needs_return:
    raise RopException("fail to invoke function and return using all self-contained gadgets")
```
Once B1–B3 make the func_jmp path genuinely returning, this early raise must become
conditional: allow it to proceed **when a returning csu composite is available**. Do not
blanket-remove it — non-returning `pop rdi; jmp rax` style gadgets must still be refused
for `needs_return=True`.

---

## 6. Hook points (where the code goes)

| Piece | Location | Note |
|---|---|---|
| B1 epilogue discovery | gadget analysis (`gadget_analyzer` / `rop_gadget`), OR a helper called from func_jmp | classification is the "proper" home; a helper is the smaller PR |
| B2 `call_mem` transit / field override | `rop_gadget` transit model (`transit_arr`), or inline in `func_call` func_jmp branch | summary notes transit_arr = `["pop_pc","jmp_reg","jmp_mem",None]` today |
| B3 loop-control pinning | `func_call` func_jmp branch, where `registers` is built (~line 236-249) | fold into the move-rewrite loop |
| B4 return-refusal gate | `func_caller.py:214-217` | make conditional on a returning composite existing |
| A guard relaxation | `func_caller.py:238-241` | `candidate-relaxation.diff`, gate to this path |
| API surface | `func_call` delegating to a `mem_func_call`, or a `ret2csu` builder | discovery-based, no explicit addresses — per maintainer |

**Smallest shippable first PR:** A (guard) + B2(ii)+B3+B4 localized in the func_jmp
branch, with B1 as a small helper — no change to core gadget classification. A later PR
can lift B1/B2 into a first-class `call_mem` transit type.

---

## 7. Open questions / risks  **[OPEN]**

1. **Discovery vs hardcode of `cleanup_slots`.** Must be discovered (R4); 7 is specific to
   this glibc's `__libc_csu_init`. Different glibc/layout ⇒ different count. B1 handles it,
   but needs testing on ≥2 csu variants.
2. **Multi-call chaining.** The lab needs `send → recv → pivot`. Each returning ret2csu
   must leave the stack/regs clean for the next. Verify `chain + chain` composes once B4
   lands (today `scripts/open3.py` shows it raises). Likely the real acceptance test.
3. **`rbx`/`r15` coupling (B3).** `rbx` is both loop index and table index. For entries
   other than 0 the arithmetic changes; keep the single-entry case (rbx=0) first.
4. **Where B1 lives.** Classification-time (clean, bigger blast radius, touches the test
   corpus) vs func_caller-local (contained, slightly hacky). Decide with the maintainer —
   this is exactly the "direction" question posed in PR #160's comment.
5. **Does relaxed guard over-generate on big binaries?** Measure chain-search time on a
   large target before/after; gate to the func_jmp path if it regresses.

---

## 8. Validation plan

- **Oracle:** `scripts/lowlevel.py` — any builder output must reduce to its frame.
- **Blocker A:** `scripts/flip.py BEFORE/AFTER` (FAIL→PASS on full set).
- **Blocker B unit:** new test — `func_call(net_send, [fd,buf,len], needs_return=True)` on
  `bins/vuln_client3` returns a chain whose symbolic run reaches `next_pc` with
  `rdx/rsi/edi` correct (mirror `scripts/lowlevel.py`'s assertions).
- **Chaining:** `func_call(send,...) + func_call(recv,...)` composes (fixes
  `scripts/open3.py`).
- **Regression:** full `tests/test_chainbuilder.py` (currently 53/53).
- **Target proof:** `scripts/lab3_targetproof.py` flips from "every form raises" to pass.

---

## 9. Scope reminder

This project's purpose is a benchmark/demonstration of semantic gadget reasoning
(angrop) vs pattern tools (pwntools). Implementing §5 would **close** the gap this
benchmark found — a stronger result (found *and* fixed upstream), but also a real
maintenance commitment. Pursue only if the maintainer's reply (PR #160) points to a
welcome direction; otherwise the forensic finding stands on its own.
