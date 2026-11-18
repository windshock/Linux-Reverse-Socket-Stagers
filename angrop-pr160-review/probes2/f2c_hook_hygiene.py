"""
V2 review probe F2c: hook hygiene around discovery's temporary FAKE hook.
  1. pre-existing USER hook at 0x43430000 -> is it lost after discovery?
  2. pre-existing hook at FAKE via angr's own machinery (SimProcedure already there)
  3. does discovery touch/corrupt project memory at TABLE/STACK/FAKE?
Run from repo root.
"""
import os, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angr import SimProcedure

FAKE, TABLE, STACK = 0x43430000, 0x42420000, 0x41410000

class UserHook(SimProcedure):
    IS_FUNCTION = True
    def run(self):
        return 0x51515151

# ---- scenario 1: user hook at FAKE before discovery ----
p = angr.Project("bins/vuln_client3", auto_load_libs=False)
p.hook(FAKE, UserHook())
print("[1] before discovery: is_hooked(FAKE)=%s hooked_by=%s"
      % (p.is_hooked(FAKE), type(p.hooked_by(FAKE)).__name__))
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
c = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
print("[1] after returning func_call: is_hooked(FAKE)=%s hooked_by=%s  chain_built=%s"
      % (p.is_hooked(FAKE), type(p.hooked_by(FAKE)).__name__ if p.is_hooked(FAKE) else None, c is not None))
print("[1] USER HOOK LOST" if not p.is_hooked(FAKE) else "[1] user hook survived")

# ---- scenario 2: hook at FAKE survives nothing / re-run uses cache (no re-hook) ----
print("[2] cache after scenario1:", {hex(k): v for k, v in
      r._chain_builder._func_caller._csu_epilogue_cache.items()})

# ---- scenario 3: does discovery mutate the PROJECT's memory at TABLE? ----
p2 = angr.Project("bins/vuln_client3", auto_load_libs=False)
r2 = p2.analyses.ROP()
r2.load_gadgets("gadgets.cache")
fc2 = r2._chain_builder._func_caller
g = next(iter(fc2._func_jmp_gadgets))
s_before = p2.factory.blank_state()
table_val_before = s_before.memory.load(TABLE, 8, endness=p2.arch.memory_endness).concrete_value  # None if unmapped
fake_mapped = s_before.memory.load(FAKE, 1, endness=p2.arch.memory_endness)
fc2._discover_csu_epilogue(g, "r15", "rbx")
s_after = p2.factory.blank_state()
table_val_after = s_after.memory.load(TABLE, 8, endness=p2.arch.memory_endness).concrete_value
print("[3] project memory TABLE before=%r after=%r (mapped=%s, unchanged=%s)"
      % (table_val_before, table_val_after, table_val_before is not None, table_val_before == table_val_after))
print("[3] FAKE mapped in project? load raises/symbolic ->", end=" ")
try:
    v = s_after.memory.load(FAKE, 1, endness=p2.arch.memory_endness)
    print("symbolic=%s concrete=%s" % (v.symbolic, v.concrete_value))
except Exception as e:
    print("Exception: %s" % type(e).__name__)

# ---- scenario 4: fresh FuncCaller, NO user hook: hook installed & removed cleanly ----
p3 = angr.Project("bins/vuln_client3", auto_load_libs=False)
r3 = p3.analyses.ROP()
r3.load_gadgets("gadgets.cache")
print("[4] before: is_hooked(FAKE)=%s" % p3.is_hooked(FAKE))
c3 = r3.func_call(0x4011C6, [1, 2, 3], needs_return=True)
print("[4] after:  is_hooked(FAKE)=%s (should be False)" % p3.is_hooked(FAKE))
