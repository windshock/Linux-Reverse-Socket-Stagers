# Independent review handoff — angrop PR #160 / ret2csu via `func_call`

You are an independent reviewer. The author below has been wrong several times in
this investigation (noted inline). **Do not take the conclusions on trust — reproduce
and challenge them.** Treat every "claim" as a hypothesis to falsify. Raw outputs and
exact repro steps are included so you can rebuild from scratch.

---

## 0. Subject

- PR: **angr/angrop #160** "Add explicit AMD64 ret2csu chain builder"
  (adds `ChainBuilder.ret2csu(pop_gadget, call_gadget, table, index, args, ...)` — a
  helper that lays out a raw `__libc_csu_init` frame from explicit gadget addresses).
- Maintainer (Kyle Zeng / @Kyle-Kyle) left two review comments:
  1. "I wonder why this is necessary ... If this chain is useful ... angrop is going
     to pick it up automatically. Can you explain the use case?"
  2. "my guess is you want to invoke a function pointer at a known memory address with
     specific arguments? in that case a `mem_func_call` stub will be more proper."

The author's job was to decide whether the PR is justified. This handoff is the
evidence gathered while doing that.

## 1. Question under review

On a non-PIE x86-64 binary with `__libc_csu_init` and **no `pop rdx`**, does angrop
*already* assemble a ret2csu call (control rdi/rsi/**rdx** and call through a pointer
table) via the existing `func_call`, or is a dedicated builder needed? If it "should"
work automatically, why doesn't it — and is any gap a real defect or intended?

## 2. Environment (exact)

- macOS arm64. angr **10.0.7**, claripy 9.3.7, z3-solver 5.3.3.0, Python **3.12**.
- angrop installed **editable from upstream HEAD** commit `7976832` (NOT the PyPI
  release, which is older — this matters; PyPI angrop was 9.2.12 and differs).
- Test binary: `angr/binaries` → `tests/x86_64/unexploitable`
  (ELF x86-64, has `__libc_csu_init` @0x400580, **zero `pop rdx` gadgets** — the
  canonical ret2csu target). Raw:
  https://raw.githubusercontent.com/angr/binaries/master/tests/x86_64/unexploitable
- For the full suite: `angr/binaries` sparse-checkout of
  tests/{x86_64,i386,armel,aarch64,mips,riscv} + tests_data/angrop_gadgets_cache.
  angrop expects it at `<angrop_repo>/../binaries`.
- keystone needed for ~24 synthetic-asm tests: on py3.12 `pip install setuptools`
  (distutils shim) + `brew install keystone` + run pytest with
  `DYLD_LIBRARY_PATH=/opt/homebrew/lib`. Without it those tests error with
  "Keystone is not installed!" (environment, not logic).

See `scripts/` for the probes and `candidate-relaxation.diff` for the one-line change.

## 3. What is CONFIRMED (lab-proven on `unexploitable`)

Reproduce with `scripts/flip.py` (runs the REAL `func_call`, concretely executes the
chain to the call target, reads rdx, and checks whether the chain contains the csu
dispatch block).

### 3a. angrop already models + discovers the csu dispatch
`scripts/probe.py` output:
```
total gadgets: 109
0x4005d0 in default find_gadgets? True
0x4005e6 in default find_gadgets? True
0x4005D0 transit_type = jmp_mem
0x4005D0 reg_moves    = [('r15','rdx'), ('r14','rsi'), ('r13','rdi')]
```
=> The `call qword [r12+rbx*8]` block IS found by default `find_gadgets()` and is
classified `jmp_mem` with the register moves recorded. (This **falsifies** the
author's FIRST theory that "angrop can't model call-through-memory / the transit
model stops at jmp_mem". It can.)

### 3b. func_call builds a working ret2csu chain — but only on a narrowed gadget DB
`scripts/flip.py` (BEFORE = unpatched upstream HEAD):
```
A seed-only   ndg=2   -> PASS rdx=0x4343434343434343 uses_csu=True
B default     ndg=109 -> FAIL: fail to invoke function: sleep
```
- A = only the 2 csu gadgets in the DB (via `analyze_gadget`, which is what the
  upstream test `test_unexploitable` does): `func_call("sleep",[a,b,c])` controls rdx.
- B = default `find_gadgets()` (109 gadgets): same call FAILS.
So the automatic path fails on a realistic full gadget set and only works when the DB
is narrowed to the csu gadgets.

### 3c. Root cause: an intentional guard in `func_caller.func_call`
Code (`angrop/chain_builder/func_caller.py`, func_jmp loop):
```python
hard_regs = [x for x in registers if not reg_setter.can_set_reg(x)]
...
for move in g.reg_moves:
    if move.from_reg in hard_regs or move.to_reg not in hard_regs:
        skip = True; break   # discards the whole gadget
```
A multi-move gadget is kept only if EVERY destination reg is "hard" (not directly
settable). `scripts/rootcause.py` output:
```
[A seed-only] can_set_reg rdi=F rsi=F rdx=F  hard={rdi,rsi,rdx}  skip csu? False
[B default]   can_set_reg rdi=T rsi=T rdx=F  hard={rdx}          skip csu? True
              (tripped on move r14->rsi: to_reg not hard)
```
On a realistic binary `pop rdi`/`pop rsi` exist but `pop rdx` doesn't, so hard={rdx};
the csu gadget (which also moves into rdi/rsi) is rejected wholesale → rdx unsettable
→ func_call fails. It works only when all arg regs are hard (degenerate/narrowed DB).

> CAUTION (author error #1 the reviewer should double-check): `rootcause.py`
> *re-implements* the guard condition rather than observing the real code path. It is
> corroborating, not primary. The primary evidence is the flip test (3d).

### 3d. The guard is causal (flip test) AND is intentional (git history)
Apply `candidate-relaxation.diff` (drops only `or move.to_reg not in hard_regs`, adds a
"must help >=1 hard reg" precondition), rerun `scripts/flip.py`:
```
AFTER:   A ndg=2 PASS uses_csu=True ; B ndg=109 PASS rdx=0x43..434 uses_csu=False
REVERT:  B ndg=109 FAIL   (identical to BEFORE)
```
Single variable flips B FAIL↔PASS. `uses_csu=False` in AFTER was a **checker artifact**
(author error #2): `flip.py` hardcodes address 0x4005D0, but `scripts/inspectB.py`
disassembles the AFTER-B chain and shows it IS genuine ret2csu via the same csu block
at a different entry:
```
0x4005f0  mov r12,[rsp+0x18]; mov r13,[rsp+0x20]; mov r14,[rsp+0x28]; mov r15,[rsp+0x30]; add rsp,0x38; ret
0x4005ca  xor ebx,ebx; mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
rdx=0x4343434343434343 ip=0x700010 (sleep=0x700010)
```

Git history of the guard (full-history `git log -L` on the line):
- `ef90763` (2025-02, Kyle Zeng) first func_jmp draft: **no guard** (more permissive
  than the candidate relaxation).
- `8102d80` (2026-01, Kyle Zeng, "Feat/ropbot (#136)"): **added** the guard.
=> The restriction is **intentional**, added by the maintainer who is also the PR
commenter. The commit message (a large refactor) does not state the reason.

### 3e. The candidate relaxation breaks no existing test
Full `tests/test_chainbuilder.py` with keystone enabled:
```
BASELINE (unpatched): 53 passed
PATCHED  (relaxed)  : 53 passed
```
And the suite has NO test exercising func_call ret2csu on a full gadget set — the only
ret2csu test (`test_unexploitable`) narrows the DB to the 2 csu gadgets (= scenario A).
So the suite is blind to scenario B either way.

## 4. What is NOT established (open — please scrutinize)

1. **Why the guard exists.** No stated rationale. Author's guess: a pruning heuristic
   ("don't use a move-gadget for a reg you can set directly"). Unconfirmed. There may
   be a correctness reason the author is missing.
2. **Whether B is a defect or intended.** The maintainer's comment implies he believes
   ret2csu is picked up automatically; that belief may rest on the narrowed test. Not
   resolved.
3. **Continuation / return correctness (IMPORTANT, untested).** Every ret2csu "PASS"
   here checks register values at the call *entry* (`concrete_exec_til_addr(sleep)`).
   None checks correct return/continuation. angrop models csu `call [mem]` as `jmp_mem`
   (a pure jump) and ignores the post-`call` csu epilogue loop
   (`add rbx,1; cmp rbx,rbp; jne ...; ret`). This is fine for a fire-and-forget final
   stage but UNVERIFIED for `needs_return=True` / chained calls. The candidate
   relaxation does not address this and could surface wrong chains where continuation
   matters. **A reviewer should test this directly.**
4. **Generality.** Only x86-64 `unexploitable` was tested. Other arches / binaries /
   multi-arg patterns not covered. The candidate relaxation's "route all moves" branch
   could over-constrain or pick worse chains on binaries not in the suite.
5. **Not target-proven.** Nothing was run in upstream CI, nor end-to-end against the
   author's own lab (a separate repo with a planted fnptr table + net_send/net_recv).

## 5. The author's current recommendation (for you to accept or reject)

- The PR as written (a hardcoded frame builder taking explicit gadget addresses) is
  likely the wrong abstraction: angrop already discovers/classifies/assembles ret2csu.
- There is a real, reproducible gap (scenario B) caused by an intentional guard.
- Therefore the right move is to **ask the maintainer why #136 added the guard**, with
  the minimal repro, rather than assert a bug or push the relaxation as a fix —
  especially given open item #3 (continuation) is unverified.

**Independent reviewer, please check at least:** (a) reproduce 3b/3d from scratch on a
clean install; (b) decide whether 3c is the true and complete cause or a partial one;
(c) resolve open #3 (does a relaxed ret2csu chain execute correctly when the call must
return?); (d) judge whether the candidate relaxation is sound in general or whether the
guard is protecting something the suite doesn't cover.

## 6. Files

- `candidate-relaxation.diff` — the one change under test (apply to angrop HEAD 7976832).
- `scripts/flip.py` — primary before/after evidence (real func_call).
- `scripts/probe.py` — discovery + classification of the csu dispatch.
- `scripts/rootcause.py` — guard condition replay (corroborating only; see error #1).
- `scripts/inspectB.py` — disassembles the relaxed-B chain (resolves error #2).
- `scripts/diag.py`, `scripts/run_test.py` — earlier scenario matrices.
- `EXPERIMENT.md`, `FINDINGS.md` — the author's running notes (may contain the earlier
  wrong framing; kept for audit).

## 7. Guard rationale — is it documented anywhere? (investigated)

Direct answer: the guard's *purpose* is not stated in code, commit, PR, or tests.

- **Code comment:** none. `func_caller.py` `hard_regs` (line ~228) and the guard
  (line ~239) have no explanatory comment. `reg_setter.can_set_reg` has no docstring
  and is simply `bool(self._reg_setting_dict[reg])` (does NOT consider badbytes).
- **Commit 8102d80 (#136):** an ~80-bullet squashed refactor; the guard is not mentioned.
  The guard was introduced here together with converting the func_jmp fallback from
  `raise NotImplementedError`/`assert` into graceful `continue`, and adding a
  `ptr_to_func is not None` gate.
- **PR #136 discussion:** no rationale. Body is just links to sibling PRs
  (archinfo#323, angr#5972, binaries#149); the only comment is an automated bot post.
- **Tests:** none pin the guard. Before/after the candidate relaxation:
  - `test_chainbuilder.py`: 53 passed == 53 passed
  - `test_badbytes.py`+`test_rop.py`: 10 passed / 2 failed == identical (the 2 failures
    are pre-existing/environment, same both ways)
  No test references the func_jmp path or `hard_regs` in func_caller. `test_hard_regs_loop`
  (test_badbytes) targets reg_setter's *separate* `_handle_hard_regs` (badbyte crafting),
  not this guard. The one ret2csu test (`test_unexploitable`) narrows the gadget DB so it
  never reaches the guard's failure mode.

Best-supported interpretation (INFERENCE, still unconfirmed): the "hard register"
machinery is designed around setting a register that cannot be set directly, and
reg_setter's related `_handle_hard_regs` explicitly bails when `len(hard_regs) > 1`
("too many registers contain bad bytes! bail out!") — i.e. it crafts at most ONE hard
reg at a time. In that design, the func_caller guard reads as a pruning heuristic:
"only use a move-gadget for a destination you can't set directly; don't reroute a reg
you could just pop into its source reg (which may be harder or clobber other setup)."
That is reasonable for single-move gadgets but **over-broad for a multi-move gadget
(csu) that bundles one hard reg (rdx) with non-hard regs (rdi/rsi)** — the per-move
`any`-style rejection throws out the whole gadget, even though it is the only way to
set rdx. Whether this over-breadth was intended or overlooked is exactly the question
to put to the maintainer.

## 8. open #3 RESOLVED — csu/func_jmp path cannot return or chain

Empirically (scripts/open3.py, on `unexploitable`, scenario A where csu func_call works):
- `func_call(..., needs_return=True)` -> RAISES "fail to invoke function and return
  using all self-contained gadgets".
- `func_call(...)` (default) -> builds, but logs "function sleep won't return!" and the
  chain is terminal (needs_return forced False).
- `func_call(...) + func_call(...)` -> RAISES "can't add to a chain that does not return!".

Code basis (func_caller.py, right before the func_jmp loop):
```python
# well, let's try non-self-contained gadgets, but this time, we don't guarantee returns
needs_return = kwargs.get("needs_return", None)
if needs_return:
    raise RopException("fail to invoke function and return using all self-contained gadgets")
if needs_return is None:
    l.warning("function %s won't return!", s); kwargs['needs_return'] = False
```
=> The csu path models `call [r12+rbx*8]` as `jmp_mem` (a jump) and does NOT model the
post-call __libc_csu_init epilogue; so by design a csu-dispatched call is strictly
fire-and-forget: only valid as the LAST call, nothing can follow it.

Consequence for the candidate relaxation (§3d): it only lets the FINAL, non-returning
call use csu. It does NOT give returning/chainable ret2csu. So §3's "fix" is narrower
than it first appears.

Consequence for an exploit that needs a leak-then-stage sequence (send-that-returns,
then recv, then pivot) on a no-`pop rdx` binary: angrop cannot build it, because the
returning send would need csu and csu can't return. Making this work requires angrop to
MODEL the csu call-continuation (a substantially bigger change than the guard tweak) or
a different primitive (e.g. a returning `mem_func_call`).

## 9. TARGET-PROVEN on the real lab3 binary (03-ret2csu-flags-zero)

Binary built from the repo's own source (Ubuntu 20.04 / glibc 2.31, non-PIE,
-fno-stack-protector): `__libc_csu_init` @0x4014d0, **zero `pop rdx`**, local
`net_send`@0x4011c6 / `net_recv`@0x4011f2 reachable via `fnptr` table @0x403e10.
angrop default find_gadgets() -> 197 gadgets. (scripts/lab3_targetproof.py, lab3_why.py)

UNPATCHED angrop, the call forms the lab's leak->stage->pivot flow requires:
- `func_call("net_send",[fd,got,8], needs_return=True)`  -> RAISED (return)
- `func_call("send",...,needs_return=True)`              -> RAISED (return)
- `func_call("net_recv",...,needs_return=True)`          -> RAISED (return)
- `func_call("net_send",...) + func_call("net_recv",...)` (chain) -> RAISED
- `func_call("net_send",...)` default (terminal)         -> RAISED ("fail to invoke")

Attribution (scripts/lab3_why.py): csu dispatch (0x401509/10/11, jmp_mem, move->rdx)
IS found and IS in the func_jmp pool; `net_send` pointer IS found (fnptr @0x403e10);
`can_set_reg` rdi=True rsi=True rdx=False -> hard={rdx}. So the terminal failure is the
GUARD (scenario B), not discovery or pointer resolution.

Two independent blockers, cleanly separated on the real target (PATCHED guard):
- terminal `net_send(fd,got,8)`            -> BUILT (3 gadgets)   [guard was the blocker]
- `net_send(...) needs_return=True`        -> RAISED (return)     [open #3, NOT fixed by patch]
- `net_send(...) + net_recv(...)` chain    -> RAISED (return)     [open #3]

CONCLUSION (target-proven): unmodified angrop cannot generate the lab3 exploit. The
one-line guard relaxation enables only a single terminal csu call; the lab's actual
flow needs the leak call (send) to RETURN so the chain can continue to recv + pivot,
and angrop's csu path is non-returning by design (models `call [mem]` as jmp_mem,
ignores the csu epilogue). Making lab3 angrop-solvable requires modeling the csu
call-continuation (a returning/chainable ret2csu, or a returning mem_func_call) — a
substantially larger change than the guard tweak.

Repro of the binary:
  docker run --rm --platform=linux/amd64 -v <repo>/03-ret2csu-flags-zero/src:/s ubuntu:20.04 \
    bash -c 'apt-get update && apt-get install -y gcc && \
    gcc -no-pie -fno-stack-protector -fcf-protection=none -O0 -g -w -o /s/vuln_client3 /s/vuln_client3.c'

## 10. Known unknowns — what this investigation did NOT test (read before trusting §8-§9)

The author has been wrong repeatedly; these are the live holes. A reviewer should
probe them, and the §8-§9 conclusions are scoped accordingly.

1. **func_call-only scope (biggest).** All "angrop cannot do it" results use the
   HIGH-LEVEL `func_call`. The author did NOT test whether a RETURNING / chainable
   ret2csu can be composed via angrop's LOWER-LEVEL API:
   `set_regs(rbx=0, rbp=1, r12=<table>, r13=fd, r14=buf, r15=len)` +
   `chain.add_gadget(<csu_dispatch>)` + the 7 csu-epilogue cleanup slots + next_pc,
   then continue the chain. This is still "using angrop" (not raw hand-writing) and is
   essentially what PR #160's `ret2csu()` lays out. If this composition returns
   correctly, then "angrop can't generate lab3" must be narrowed to "func_call can't",
   and the real gap is only that func_call doesn't *automatically* assemble it.
   -> UNTESTED. This could overturn §9's framing. Test it first.
2. **Intended scope vs defect.** Whether the maintainer considers a leak-then-stage,
   same-socket, returning-csu flow in-scope for angrop at all. func_call may be
   deliberately terminal-only for non-self-contained gadgets. (§7: guard is intentional;
   its rationale is undocumented.)
3. **Continuation correctness never positively verified.** The author only observed
   that angrop REFUSES returning csu (raises). It was never shown whether a correctly
   laid-out csu return (rbx=0,rbp=1 so the epilogue loop runs once, then pops + ret)
   executes correctly under angr's engine. The jmp_mem model ignores the epilogue; a
   reviewer should confirm what actually happens at the instruction level.
4. **Version pins.** angr 10.0.7 with claripy 9.3.7 (minor mismatch; a clean resolve
   might differ). angrop pinned to HEAD 7976832. A newer angrop/branch may behave
   differently. Not checked against upstream CI.
5. **Harness roughness.** `send` (PLT import) did not resolve via get_symbol in
   scripts/lab3_targetproof.py (addr=None), so that one line is inconclusive; the clean
   evidence is `net_send` (a local symbol with a real fnptr pointer).
6. **One target.** Only x86-64 `unexploitable` and the repo's lab3 were tested. No other
   binary/arch; the candidate relaxation's general soundness is only "53/53 suite + these
   two targets", not a proof.

Note: `EXPERIMENT.md` and `FINDINGS.md` are the author's round-1/round-2 running notes
(incl. the earlier WRONG framing). Where they differ from this file, **HANDOFF.md
§8-§10 supersede them.**

## 11. CORRECTION to §9 — low-level composition DOES work (open #10.1 resolved)

Prompted by "you might be missing something", the author tested open unknown §10.1
(the func_call-only scope). Result: **the earlier "angrop cannot generate lab3"
conclusion was an OVERCLAIM.** (scripts/lowlevel.py, on the real lab3 binary)

lab3 csu (standard glibc 2.31):
- dispatch 0x401510: `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]`
  (table=r15, index=rbx, args r12d/r13/r14)
- pop tail 0x40152a: `pop rbx;rbp;r12;r13;r14;r15; ret` (preceded by 0x401526 `add rsp,8`)

Verified:
- Part 1: `rop.set_regs(rbx=0, rbp=1, r12=fd, r13=buf, r14=len, r15=table)` -> BUILT in
  one gadget (0x40152a). angrop's low-level API sets all six csu input regs trivially.
- Part 2: a manually laid-out RETURNING csu frame
  `[pop] rbx=0,rbp=1,r12,r13,r14,r15, [dispatch], <7 cleanup slots>, next_pc`
  (table[0] -> a `ret` gadget) was executed in angr: control went
  dispatch -> call[table] -> ret -> csu epilogue (loop exits, add rsp,8, 6 pops, ret)
  -> **reached next_pc with rdx==len, rsi==buf, edi==fd**. i.e. a returning,
  chainable ret2csu. cleanup_slots = 1 (add rsp,8) + 6 (pops) = 7, matching PR #160.

Corrected conclusions (supersede §8-§9 where they conflict):
- angrop CAN build a returning/chainable ret2csu at the LOW LEVEL (`set_regs` for the
  six regs + lay out dispatch + 7 cleanup + next_pc). This is still "using angrop",
  not raw hand-writing, and is exactly what PR #160's `ret2csu()` automates.
- What angrop CANNOT do is auto-assemble it via the HIGH-LEVEL `func_call`
  (blocked by the hard_regs guard §3, and func_jmp being terminal-only §8).
- Therefore lab3 IS achievable with angrop (low-level / via a helper like PR #160).
  The non-func_call option is NOT limited to raw hand-writing.
- This RE-JUSTIFIES the PR's direction (a helper to compose returning ret2csu). The
  open design question is only its SHAPE: csu-specific `ret2csu()` vs a general
  `mem_func_call` (maintainer's suggestion), and explicit addresses vs discovery.

Caveat: Part 2 lays out the dispatch+cleanup+next_pc as raw stack values (what the PR
helper does internally); the author did not drive it through a single existing angrop
one-call API (there isn't one yet — that's what the PR adds). The register setup half
is a real angrop call (set_regs). Mechanism + setup are both verified; the missing
piece is purely the convenience wrapper.
