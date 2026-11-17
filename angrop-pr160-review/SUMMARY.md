# ret2csu for same-socket reverse staging — the technique, and angrop's support gap

A readable synthesis of the investigation. For the forensic, evidence-by-evidence
version (with the author's own wrong turns flagged), see `HANDOFF.md`. For raw notes see
`EXPERIMENT.md` / `FINDINGS.md`. Everything here is reproducible via `setup.sh` + `scripts/`.

---

## TL;DR

- The attack technique is real and classic: on a non-PIE x86-64 target with **no
  `pop rdx`**, you set the 3rd call argument (`rdx`) by borrowing `__libc_csu_init`
  (**ret2csu**) and call through a function-pointer table. A correctly built ret2csu
  frame **returns**, so you can chain several such calls (leak → stage-2 → pivot) in one
  ROP chain. This is exactly what the `Linux-Reverse-Socket-Stagers` lab 03 does by hand.
- **angrop can build this — but only at the low level.** `set_regs(...)` plus a manually
  laid-out csu frame produces a working, returning, chainable ret2csu (verified end to
  end on the real lab3 binary).
- **angrop's high-level `func_call()` cannot auto-assemble it**, for two independent
  reasons (both verified): a register-selection **guard** discards the csu gadget, and
  the non-self-contained call path is **terminal-only** (cannot return / be chained).
- So the gap is *ergonomics/automation*, not capability: there is no one-call API that
  composes a returning ret2csu from discovered gadgets. PR #160 (`ret2csu()` helper) is
  one attempt at that missing convenience. The maintainer floated a `mem_func_call` stub
  instead — but note that covers only the *indirect-call-through-a-pointer* surface; it
  does not by itself address the two things that make this hard (setting `rdx` with no
  `pop rdx`, and returning). See §5.

---

## 1. The technique

Target shape (lab 03 / the classic "unexploitable" challenge): non-PIE, no stack
canary, **no `pop rdx`** gadget, but `__libc_csu_init` is present (glibc ≤ 2.33).

To call `f(a, b, c)` you need `rdi=a, rsi=b, rdx=c`. With no `pop rdx`, `rdx` is set via
the two `__libc_csu_init` gadgets:

```
; gadget 1 (loader): pop the control registers
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
   rbx = 0            ; loop index
   rbp = 1            ; so the epilogue loop runs exactly once
   r12..r15           ; args + table pointer (layout is glibc-version specific)

; gadget 2 (dispatch): move regs into the ABI arg registers, then indirect-call
mov rdx, r14 ; mov rsi, r13 ; mov edi, r12d ; call [r15 + rbx*8]
   ; -> calls table[0](edi, rsi, rdx)
   ; after the call returns, the csu epilogue runs:
   ;   add rbx,1 ; cmp rbx,rbp ; jne <loop>   (loop exits because rbx==rbp)
   ;   add rsp,8 ; pop rbx;rbp;r12;r13;r14;r15 ; ret   <-- consumes 7 "cleanup" slots
```

Because gadget 2 ends in a real `call` (not a jump), control **returns** into the csu
epilogue and finally `ret`s to the next chain entry. That is why ret2csu is chainable:
you spend `1 + 6 = 7` cleanup stack slots and then continue. The lab's whole premise —
one chain that does `send(leak)` → `recv(stage-2)` → `pivot` over a single socket —
relies on each ret2csu call returning.

(lab 03 wraps the libc calls as `net_send`/`net_recv` reached through a fixed `fnptr`
table, so the `call [r15+rbx*8]` lands on the wrapper; the mechanism is identical.)

---

## 2. What angrop does today

Verified on angr 10.0.7 / angrop HEAD `7976832`, against `unexploitable` and the repo's
own lab3 binary (built from `bins/src/vuln_client3.c`).

| Capability | angrop today | Evidence |
|---|---|---|
| Discover the csu dispatch gadget | ✅ found by default `find_gadgets()`, classified `jmp_mem` with reg-moves `r*→rdi/rsi/rdx` | `scripts/probe.py` |
| Set the 6 csu input regs (`rbx,rbp,r12–r15`) | ✅ `set_regs(...)` builds it in one gadget | `scripts/lowlevel.py` Part 1 |
| Execute a returning ret2csu frame | ✅ reaches the continuation with `rdx/rsi/edi` correct | `scripts/lowlevel.py` Part 2 |
| **Auto-assemble ret2csu via `func_call()`** on a full gadget set | ❌ fails | `scripts/flip.py`, `scripts/lab3_targetproof.py` |
| **Return / chain after a `func_call` csu call** | ❌ raises | `scripts/open3.py` |

So: the **building blocks exist** and a **returning ret2csu is achievable** with angrop's
low-level API; what's missing is the **high-level automation**.

---

## 3. Why `func_call()` can't auto-assemble it (two independent blockers)

### Blocker A — the register-selection guard
`chain_builder/func_caller.py`, the `func_jmp` path:
```python
hard_regs = [x for x in registers if not reg_setter.can_set_reg(x)]  # regs with no direct setter
...
for move in g.reg_moves:
    if move.from_reg in hard_regs or move.to_reg not in hard_regs:
        skip = True; break      # discard the whole gadget
```
A multi-move gadget is kept only if **every** destination register is "hard" (not
directly settable). On a realistic binary `pop rdi`/`pop rsi` exist but `pop rdx` doesn't,
so `hard = {rdx}`; the csu dispatch (which also moves into `rdi`/`rsi`) is rejected
wholesale — even though it is the only way to set `rdx`. (`scripts/rootcause.py`,
`scripts/flip.py`: relaxing just this guard flips the full-set case from FAIL to PASS and
breaks none of the 53 chainbuilder tests.)

### Blocker B — the non-self-contained call path is terminal-only
Right before the `func_jmp` path:
```python
# we don't guarantee returns
if needs_return: raise RopException("fail to invoke function and return ...")
if needs_return is None: l.warning("function %s won't return!", s); kwargs['needs_return'] = False
```
angrop models the csu `call [mem]` as `jmp_mem` (a jump) and does not model the post-call
csu epilogue, so a `func_call` csu call is strictly fire-and-forget: `needs_return=True`
raises, and `chain + chain` raises `"can't add to a chain that does not return!"`
(`scripts/open3.py`). Even the one-line guard relaxation only enables a single terminal
csu call — it does **not** give returning/chainable ret2csu.

### Net effect on lab3
`scripts/lab3_targetproof.py`: every call form the lab needs — returning `net_send`,
returning `net_recv`, the `net_send + net_recv` chain, even a single terminal call —
raises. (`scripts/lab3_why.py` confirms the terminal failure is Blocker A: the csu gadget
is found, is in the func_jmp pool, and the `fnptr` pointer is resolved; `rdx` is simply
unsettable and the guard drops the gadget.)

---

## 4. Authorship / intent context

- `FuncCaller` credits `@tomgond` for "a great portion of this class"; the current
  `func_call` / `func_jmp` / ret2csu logic is **~250 of ~260 lines by Kyle Zeng**
  (git blame), i.e. the angrop maintainer **@Kyle-Kyle**, who also reviewed PR #160.
- He added ret2csu-via-`func_call` support (commit `fed8eb4`, 2025-02, "we are able to
  find ret2csu style chains now") **and** later added Blocker A's guard
  (commit `8102d80`, "Feat/ropbot (#136)", 2026-01). The guard is **intentional**; its
  rationale is **not documented** in code, commit message, PR discussion, or any test.
- His review comment — "if this chain is useful, angrop is going to pick it up
  automatically" — is most plausibly grounded in the narrowed test (`test_unexploitable`
  seeds only the csu gadgets, side-stepping Blocker A) rather than full-set behavior.

---

## 5. What would make angrop support the technique

In increasing order of effort:

1. **Relax Blocker A only** (one-line change, `candidate-relaxation.diff`): keep a
   move-gadget if it supplies ≥1 otherwise-unsettable arg reg. Enables a *single terminal*
   csu call on a full gadget set. Passes the whole chainbuilder suite. **Insufficient for
   the lab** (no return/chain).
2. **Model the csu call-continuation** so a csu-dispatched call can return (account for
   the epilogue's `add rsp,8` + 6 pops, `cleanup_slots=7`). This is what unlocks the
   leak→stage→pivot flow. Substantially larger than (1).
3. **A convenience API** that composes the above from discovered gadgets. PR #160
   proposes a csu-specific `ret2csu()` (taking explicit addresses). The maintainer
   suggested a `mem_func_call` stub instead.

   A caveat on `mem_func_call`: as the maintainer framed it ("invoke a function pointer
   at a known memory address with some specific arguments"), it names only the
   *indirect-call-through-a-pointer* surface and appears to assume the args are set
   normally. It does **not** by itself solve the two hard parts above (setting `rdx`
   with no `pop rdx` via csu, and returning). A naive `mem_func_call` would hit the same
   two blockers. So `mem_func_call` is a reasonable *home/shape* for the API, but whether
   it also owns the rdx-via-csu + returning logic is an open design question to put to
   the maintainer — not something his comment already settled.

Design axes, regardless of the name: explicit-address vs **discovery-based** (the latter
is clearly preferable and is the maintainer's other objection to PR #160); and a separate
builder vs having `func_call` delegate to it (so callers keep one API).

Note: (2)+(3) is effectively "automate what `scripts/lowlevel.py` does by hand." The
capability is present; these turn it into a supported, discoverable path.

---

## 6. Conclusion strength

| Claim | Strength |
|---|---|
| The technique (returning, chainable ret2csu) is real and executes | **target-proven** (lab3 binary, `scripts/lowlevel.py`) |
| angrop can build it at the low level (`set_regs` + manual frame) | **target-proven** (lab3) |
| `func_call` cannot auto-assemble it (Blockers A + B) | **target-proven** (lab3) + lab-proven (`unexploitable`) |
| Blocker A is one specific, intentional guard | **lab-proven** + git-history confirmed |
| The one-line relaxation fixes Blocker A without breaking tests | **lab-proven** (53/53 suite) |
| Why the guard exists / whether B is a defect or intended scope | **open** (undocumented) |
| Whether the relaxation is correct in general (other arches/binaries) | **open** (tested on 2 targets only) |

---

## 7. Reproduce

```bash
cd angrop-pr160-review
./setup.sh                      # venv + angr 10.0.7 + angrop@7976832 + binaries (bins/ are vendored)
./venv/bin/python scripts/probe.py            # §2: discovery + classification
./venv/bin/python scripts/flip.py BEFORE      # Blocker A: full-set func_call fails
./venv/bin/python scripts/open3.py            # Blocker B: csu func_call can't return/chain
./venv/bin/python scripts/lab3_targetproof.py # lab3: every needed call form fails
./venv/bin/python scripts/lowlevel.py         # low-level returning ret2csu WORKS
# apply candidate-relaxation.diff to angrop-src and re-run flip.py AFTER to see Blocker A flip
```
