"""
V2 review probe: same concrete execution as c1_exec_oracle but WITHOUT redirecting
the fnptr table — the chain must reach the REAL net_send (0x4011c6) through the
binary's own table at 0x403e10, then return through the csu epilogue to the sentinel.
net_send is intercepted by a recording SimProcedure (returns immediately).
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

# what does the binary's table actually contain?
s0 = p.factory.blank_state()
print("[*] binary [0x403e10] = %#x (net_send claimed 0x4011c6)"
      % s0.memory.load(0x403e10, 8, endness=p.arch.memory_endness).concrete_value)

REC = []

from angr import SimProcedure
class NetSendRecorder2(SimProcedure):
    IS_FUNCTION = True
    def run(self):
        REC.append((self.state.solver.eval(self.state.regs.rdi),
                    self.state.solver.eval(self.state.regs.rsi),
                    self.state.solver.eval(self.state.regs.rdx)))
        return 0

p.hook(0x4011c6, NetSendRecorder2())
print("[*] hooked net_send 0x4011c6; project.is_hooked:", p.is_hooked(0x4011c6))

r2 = p.analyses.ROP()
r2.load_gadgets("gadgets.cache")
c1 = r2.func_call(0x4011C6, [0x11111111, 0x22222222, 0x33333333], needs_return=True)
words = []
npc = c1.next_pc_idx()
for i, v in enumerate(c1._values):
    words.append(0x50000100 if i == npc else
                 (c1._blank_state.solver.eval(v.ast) if v.symbolic else v.data.concrete_value))
print("[*] words:", [hex(w) for w in words])

STACK_BASE = 0x70000000
SENT_MAGIC = 0x50000f80
s = p.factory.blank_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
s.memory.map_region(0x50000000, 0x2000, 'rwx')
sentinel_bytes = b"\x49\xba" + (0x50000f80).to_bytes(8, "little") + b"\x41\xc7\x02\xef\xbe\xad\xde\xc3"
s.memory.store(0x50000100, sentinel_bytes)
for i, w in enumerate(words):
    s.memory.store(STACK_BASE + i*8, claripy.BVV(w, 64), endness=p.arch.memory_endness)
s.regs.sp = STACK_BASE + 8
s.regs.pc = words[0]
trace = []
s.inspect.b('instruction', when=angr.BP_BEFORE, action=lambda st: trace.append(st.solver.eval(st.regs.pc)))
simgr = p.factory.simgr(s, save_unconstrained=True)
for _ in range(1000):
    if not simgr.active:
        break
    simgr.step()

print("[*] REC (hook captures):", [(hex(a), hex(b), hex(c)) for a, b, c in REC])
print("[*] 0x4011c6 in trace:", 0x4011c6 in trace)
print("[*] dispatch 0x401510 in trace:", 0x401510 in trace)
print("[*] epilogue loop-check 0x40151d in trace:", 0x40151d in trace)
print("[*] sentinel 0x50000100 in trace:", 0x50000100 in trace)
fin = (simgr.unconstrained + simgr.active + [e.state for e in simgr.errored])
for st in fin:
    try:
        v = st.memory.load(SENT_MAGIC, 4, endness=p.arch.memory_endness).concrete_value
    except Exception:
        v = None
    print("[*] final state pc=%s sentinel_magic=%s" % (hex(st.solver.eval(st.regs.pc)) if st.solver.symbolic(st.regs.pc) is False else "SYMBOLIC", v))
print("[*] VERDICT hook-variant:", "PASS" if (REC and REC[0] == (0x11111111, 0x22222222, 0x33333333)
      and 0x4011c6 in trace and 0x50000100 in trace) else "FAIL")
