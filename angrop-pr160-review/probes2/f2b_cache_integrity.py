"""
V2 review probe F2b: cache integrity — aliasing, staleness after optimize(),
negative-cache keying mechanism, cached-dict mutation.
Run from repo root.
"""
import os, copy as _copy, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
fc = r._chain_builder._func_caller

# --- find all jmp_mem candidates that reach _try_csu_return, log each attempt ---
attempts = []
orig_try = fc._try_csu_return
def logged_try(g, registers, ptr_to_func):
    attempts.append(g.addr)
    return orig_try(g, registers, ptr_to_func)
fc._try_csu_return = logged_try

c = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
print("[*] _try_csu_return attempts for one func_call:", [hex(a) for a in attempts])
print("[*] cache after one successful call:", {hex(k): v for k, v in fc._csu_epilogue_cache.items()})

# --- aliasing: is the cached dict mutated by building chains? ---
before = _copy.deepcopy(fc._csu_epilogue_cache)
c2 = r.func_call(0x4011C6, [7, 8, 9], needs_return=True)
c3 = r.func_call(0x4011C6, [0x111111, 0x222222, 0x333333], needs_return=True)
after = fc._csu_epilogue_cache
print("[*] cached dict unchanged across more calls:", before == after)
# also mutate the chain-built extras? verify pins dict identity is not shared into chains
epi = after[0x401510]
snapshot = dict(epi["pins"])
print("[*] pins before more calls:", snapshot, "after:", dict(epi["pins"]))

# --- staleness after rop.optimize() ---
print("[*] ROP.optimize exists:", hasattr(r, "optimize"))
gobj = {g.addr: g for g in fc._func_jmp_gadgets}.get(0x401510)
print("[*] gadget object id before optimize:", id(gobj),
      "moves:", [(m.from_reg, m.to_reg, m.bits) for m in gobj.reg_moves],
      "stack_change:", gobj.stack_change)
try:
    r.optimize()
    print("[*] optimize() ran")
except Exception as e:
    print("[*] optimize() raised:", type(e).__name__, e)
gobj2 = {g.addr: g for g in fc._func_jmp_gadgets}.get(0x401510)
print("[*] gadget object id after optimize:", id(gobj2),
      "same object:", gobj is gobj2,
      "moves:", [(m.from_reg, m.to_reg, m.bits) for m in gobj2.reg_moves] if gobj2 else None,
      "stack_change:", gobj2.stack_change if gobj2 else None)
print("[*] cache survived optimize:", {hex(k): v for k, v in fc._csu_epilogue_cache.items()})
# does a NEW func_call after optimize still return the cached epilogue? and does it build?
try:
    c4 = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
    print("[*] post-optimize func_call builds:", c4 is not None)
except Exception as e:
    print("[*] post-optimize func_call RAISES:", type(e).__name__, e)

# --- negative-cache keying mechanism demo (mechanism-level, not end-to-end) ---
# key is g.addr only: two DIFFERENT gadget objects with the same addr share the entry
from angrop.rop_gadget import RopGadget
fake_g = RopGadget(0x401510)
fake_g.project = p
res_for_fake = fc._discover_csu_epilogue(fake_g, "r15", "rbx")
print("[*] discovery for a DIFFERENT object with same addr returns cached:", res_for_fake)

# --- negative caching: force a None result then re-call ---
fc._csu_epilogue_cache.clear()
orig_inner = fc._discover_csu_epilogue_inner
fc._discover_csu_epilogue_inner = lambda *a, **k: None   # simulate discovery failure
res = fc._discover_csu_epilogue(gobj2 if gobj2 else gobj, "r15", "rbx")
print("[*] simulated-failure discovery ->", res, "cache now:", fc._csu_epilogue_cache)
fc._discover_csu_epilogue_inner = orig_inner
res2 = fc._discover_csu_epilogue(gobj2 if gobj2 else gobj, "r15", "rbx")
print("[*] after 'fixing' the gadget (same addr), discovery returns (stale None?):", res2)
try:
    c5 = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
    print("[*] func_call after simulated-failure cache: returning chain built=%s" % (c5 is not None))
except Exception as e:
    print("[*] func_call after simulated-failure cache RAISES:", type(e).__name__, e)
