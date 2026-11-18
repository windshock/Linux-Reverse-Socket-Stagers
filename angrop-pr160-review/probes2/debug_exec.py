"""
V2 review probe: debug why the concrete run stops after the loader; dump dispatch
gadget shape, pc_target, errored state details.
"""
import os, logging as _logging, struct
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")

c1 = r.func_call(0x4011C6, [0x41414141, 0x42424242, 0xC0DE], needs_return=True)
print("[*] gadgets:")
for g in c1._gadgets:
    print("   addr=%#x sc=%d pc_off=%r transit=%s moves=%s pc_target=%s project=%r"
          % (g.addr, g.stack_change, g.pc_offset, g.transit_type,
             [(m.from_reg, m.to_reg, m.bits) for m in g.reg_moves],
             g.pc_target, g.project))

blk = p.factory.block(0x401510)
blk.pp()
blk2 = p.factory.block(0x40152a)
blk2.pp()

# where does ptr_to_func land? check the chain's constraint on pc_target
st = c1._blank_state
print("[*] constraints:", st.solver.constraints[:5])

# concrete run, capturing errors
words = []
npc = c1.next_pc_idx()
for i, v in enumerate(c1._values):
    if i == npc:
        words.append(0x50000100)
    elif v.symbolic:
        words.append(st.solver.eval(v.ast))
    else:
        words.append(v.data.concrete_value)

STACK_BASE = 0x70000000
s = p.factory.blank_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
s.memory.map_region(0x50000000, 0x2000, 'rwx')
s.memory.store(0x50000800, b"\x90"*8 + b"\xc3")  # nop; ret callee
s.memory.store(0x403e10, struct.pack("<Q", 0x50000800), endness="little")
for i, w in enumerate(words):
    s.memory.store(STACK_BASE + i*8, claripy.BVV(w, 64), endness=p.arch.memory_endness)
s.regs.sp = STACK_BASE + 8
s.regs.pc = words[0]

simgr = p.factory.simgr(s, save_unconstrained=True)
for i in range(100):
    if not simgr.active:
        break
    simgr.step()
    if simgr.errored:
        e = simgr.errored[0]
        print("[!] errored at step %d: %r" % (i, e.error))
        stx = e.state
        print("    pc=%r r12=%#x r15=%#x rbx=%#x r13=%#x r14=%#x sp=%#x"
              % (stx.regs.pc, stx.solver.eval(stx.regs.r12), stx.solver.eval(stx.regs.r15),
                 stx.solver.eval(stx.regs.rbx), stx.solver.eval(stx.regs.r13),
                 stx.solver.eval(stx.regs.r14), stx.solver.eval(stx.regs.sp)))
        break
    print("   step %d: active=%s uncon=%s"
          % (i, [hex(x.addr) for x in simgr.active], [hex(x.addr) for x in simgr.unconstrained]))
