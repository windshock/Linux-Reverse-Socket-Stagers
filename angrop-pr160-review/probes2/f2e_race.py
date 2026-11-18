"""
V2 review probe F2e: concurrency hazard of the plain-dict cache + non-reentrant
FAKE hook. Two parts:
  A. deterministic interleaving model: unhook FAKE between hook() and simgr run
     (what a second thread's discovery could do) -> does a WRONG None get cached
     permanently?
  B. real thread race: N threads calling returning func_call on a fresh FuncCaller
     at the same time; compare outcomes vs serial run.
Run from repo root.
"""
import os, threading, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angrop.errors import RopException

# ---- part A: deterministic interleaving model ----
p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
fc = r._chain_builder._func_caller

orig_inner = fc._discover_csu_epilogue_inner
def sabotaged_inner(*a, **k):
    # model: ANOTHER THREAD's discovery finished right now and unhooked FAKE
    p.unhook(0x43430000)
    return orig_inner(*a, **k)
fc._discover_csu_epilogue_inner = sabotaged_inner

res = fc._discover_csu_epilogue(next(g for g in fc._func_jmp_gadgets if g.addr == 0x401510), "r15", "rbx")
print("[A] race-mode discovery result:", res)
print("[A] cache after race-mode discovery:", {hex(k): v for k, v in fc._csu_epilogue_cache.items()})
try:
    c = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
    print("[A] func_call after poisoned cache: returning chain built=%s (falls back to terminal?)"
          % (c is not None))
    if c is not None:
        print("[A] next_pc_idx:", c.next_pc_idx(), "-> returning" if c.next_pc_idx() is not None else "-> TERMINAL")
except RopException as e:
    print("[A] func_call after poisoned cache RAISES:", e)

# ---- part B: real threads ----
import copy as _copy
def fresh():
    pp = angr.Project("bins/vuln_client3", auto_load_libs=False)
    rr = pp.analyses.ROP()
    rr.load_gadgets("gadgets.cache")
    return pp, rr

# serial baseline (3 sequential returning calls)
pp, rr = fresh()
serial = []
for i in range(3):
    try:
        ch = rr.func_call(0x4011C6, [i + 1, 2, 3], needs_return=True)
        serial.append("ok:%d" % ch.next_pc_idx())
    except Exception as e:
        serial.append("%s" % type(e).__name__)
print("[B] serial baseline:", serial, "cache:", {hex(k): (v is not None) for k, v in rr._chain_builder._func_caller._csu_epilogue_cache.items()})

# concurrent: 4 threads on ONE shared project/ROP (the realistic shared-state hazard)
pp2, rr2 = fresh()
results = [None] * 4
def worker(i):
    try:
        ch = rr2.func_call(0x4011C6, [i + 1, 2, 3], needs_return=True)
        results[i] = "ok:%s" % ch.next_pc_idx()
    except Exception as e:
        results[i] = "%s: %s" % (type(e).__name__, str(e)[:60])
threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
for t in threads: t.start()
for t in threads: t.join()
print("[B] concurrent results:", results)
print("[B] concurrent cache:", {hex(k): (v is not None and v or None) for k, v in rr2._chain_builder._func_caller._csu_epilogue_cache.items()})
