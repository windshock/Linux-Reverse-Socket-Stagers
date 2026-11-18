"""
V2 review probe: control experiment — run the SAME scenarios on pristine AND
patched angrop, dump results as JSON lines to compare. Also works as the F1c
AMD64-unchanged check (needs_return=False / self-contained must be identical),
and re-derives the addendum's "pristine 9-word terminal vs patched 17-word
returning" seeded-DB claim.
Run from repo root:  ./venv/bin/python -I probes2/pristine_control.py
"""
import os, json, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angrop.errors import RopException

def dump(label, **kw):
    print("CTRL " + json.dumps({"label": label, **kw}, default=str), flush=True)

def chain_info(c):
    npc = c.next_pc_idx()
    vals = []
    for i, v in enumerate(c._values):
        vals.append("NEXT_PC" if i == npc else
                    (hex(c._blank_state.solver.eval(v.ast)) if v.symbolic else hex(v.data.concrete_value)))
    return {"words": vals, "gadgets": ["%#x" % g.addr for g in c._gadgets]}

# ---------- S1-S3: vuln_client3 (cache) ----------
p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
for nr, label in [(False, "S1_nrFalse"), (None, "S2_nrNone"), (True, "S3_nrTrue")]:
    try:
        c = r.func_call(0x4011C6, [0x41414141, 0x42424242, 0x43434343], needs_return=nr)
        dump(label, ok=True, **chain_info(c))
    except RopException as e:
        dump(label, ok=False, exc="RopException: %s" % e)
    except Exception as e:
        dump(label, ok=False, exc="%s: %s" % (type(e).__name__, e))

# ---------- S4: self-contained path (1-arg function) ----------
# find a function whose call the self-contained path handles identically
syms = [s.name for s in p.loader.main_object.symbols if s.name and s.name.startswith("net_")]
dump("S0_syms", syms=sorted(set(syms)))

# ---------- S5: unexploitable seeded-DB (test_unexploitable scenario) ----------
proj = angr.Project("binaries/tests/x86_64/unexploitable", auto_load_libs=False)
rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
g = rop.analyze_gadget(0x4005D0)
g2 = rop.analyze_gadget(0x4005E6)
dump("S5_seeds", g0_ok=g is not None, g1_ok=g2 is not None)
for nr, label in [(False, "S5_nrFalse"), (None, "S5_nrNone"), (True, "S5_nrTrue")]:
    try:
        c = rop.func_call("sleep", [0x41414141, 0x4242424242424242, 0x4343434343434343], needs_return=nr)
        dump(label, ok=True, **chain_info(c))
    except RopException as e:
        dump(label, ok=False, exc="RopException: %s" % e)
    except Exception as e:
        dump(label, ok=False, exc="%s: %s" % (type(e).__name__, e))

# ---------- S6: i386 cache load with optimize=True (optimize() crash pre-existing?) ----------
try:
    pi = angr.Project("binaries/tests/i386/i386_glibc_2.35", auto_load_libs=False)
    ri = pi.analyses.ROP()
    ri.load_gadgets("binaries/tests_data/angrop_gadgets_cache/i386_glibc_2.35")  # optimize=True
    dump("S6_i386_optimize", ok=True)
except Exception as e:
    dump("S6_i386_optimize", ok=False, exc="%s: %s" % (type(e).__name__, str(e)[:200]))
