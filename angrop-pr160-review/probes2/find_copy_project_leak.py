"""
V2 review probe: verify the copy.copy(g) project-None leak on the synthesized
csu gadget copy, and measure its blast radius on RopChain user-facing methods.
Run from repo root.
"""
import os, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

import copy as _copy
from angrop.rop_gadget import RopGadget

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
fc = r._chain_builder._func_caller

c1 = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)

# locate the synthesized copy: it is the gadget in chain._gadgets with project=None
orig_projects = []
print("[*] chain gadgets project attribute:")
for i, g in enumerate(c1._gadgets):
    print("   gadget[%d] addr=%#x project=%r stack_change=%d pc_offset=%r"
          % (i, g.addr, g.project, g.stack_change, g.pc_offset))
    orig_projects.append(g.project)

# direct mechanism check on a fresh gadget object
g = next(iter(r._chain_builder._func_caller._func_jmp_gadgets))
g2 = _copy.copy(g)
print("[*] stdlib copy.copy(RopGadget):  orig.project=%r  copy.project=%r" % (g.project, g2.project))
g3 = g.copy()
print("[*] RopGadget.copy():             orig.project=%r  copy.project=%r" % (g.project, g3.project))

# blast radius: user-facing chain introspection on a chain containing the copy
print("\n[*] blast radius on the returning csu chain:")
for label, fn in [
    ("chain.code()", lambda: c1.code()),
    ("chain.payload_code()", lambda: c1.payload_code()),
    ("chain.dstr()", lambda: c1.dstr()),
    ("chain.__str__()", lambda: str(c1)),
    ("g2.dstr() on the copy", lambda: next(x for x in c1._gadgets if x.project is None).dstr()),
]:
    try:
        out = fn()
        s = str(out)
        print("   %-24s OK  (%s...)" % (label, s[:60].replace("\n", " | ")))
    except Exception as e:
        print("   %-24s RAISES %s: %s" % (label, type(e).__name__, e))
