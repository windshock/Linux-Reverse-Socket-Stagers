# Independent oracle (reviewer's own) — stronger than scripts/validate.py:
#  1. two chained calls with DISTINCT args -> both must be captured in order
#     (defeats "capture only records the last call" bias)
#  2. trace executed pcs -> must pass through the dispatch and the csu epilogue,
#     not some wrong path that merely ends at a symbolic pc
#  3. final pc's variables must be exactly next_pc; pin a sentinel -> satisfiable
#  4. dump the produced chain words and compare to the lowlevel.py hand layout
import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR)
logging.getLogger("angr").setLevel(logging.CRITICAL)
BIN = "bins/vuln_client3"; CACHE = "gadgets.cache"
NET_SEND = 0x4011c6
A1 = (0x11111111, 0x2222222222222222, 0x3333333333333333)
A2 = (0x44444444, 0x5555555555555555, 0x6666666666666666)
DISPATCH, LOOPCHK, EPILOGUE, RET = 0x401510, 0x40151d, 0x401526, 0x401534
SENTINEL = 0x401544

calls = []
class CaptureSend(angr.SimProcedure):
    def run(self):
        s = self.state
        calls.append(tuple(s.solver.eval(v) for v in
                           (s.regs.edi, s.regs.rsi, s.regs.rdx)))
        return 0

p = angr.Project(BIN, auto_load_libs=False)
r = p.analyses.ROP(); r.load_gadgets(CACHE)
p.hook(NET_SEND, CaptureSend())

c1 = r.func_call(NET_SEND, list(A1), needs_return=True)
c2 = r.func_call(NET_SEND, list(A2), needs_return=True)
print("c1 words:", len(c1._values), "next_pc_idx:", c1.next_pc_idx())
chained = c1 + c2
print("chained words:", len(chained._values))

# --- replicate RopChain.exec()'s store procedure, but keep the simgr for tracing
state = chained._blank_state.copy()
concrete_vals = chained._concretize_chain_values(timeout=None, preserve_next_pc=True, append_shift=False)
for idx, val in enumerate(concrete_vals):
    off = idx * p.arch.bytes
    state.memory.store(state.regs.sp + off, val[0], p.arch.bytes, endness=p.arch.memory_endness)
state.regs.pc = state.stack_pop()

simgr = p.factory.simulation_manager(state, save_unconstrained=True)
seen = []
for _ in range(500):
    if not (simgr.active or simgr.unconstrained):
        break
    if simgr.active:
        seen.append(simgr.active[0].addr)
    if simgr.unconstrained:
        break
    simgr.step()
u = simgr.unconstrained[0] if simgr.unconstrained else None
if u is None:
    print("RESULT: FAIL (no unconstrained state)")
else:
    u.add_constraints(u.regs.pc == SENTINEL)
    sat = u.solver.satisfiable()
    print("final pc == sentinel satisfiable:", sat)
    print("calls captured:", [tuple(hex(x) for x in c) for c in calls])
    ok_calls = len(calls) == 2 and calls[0] == A1 and calls[1] == A2
    print("both calls in order with correct args:", ok_calls)
    hit = lambda a: a in seen
    print("trace hits DISPATCH(0x401510):", hit(DISPATCH),
          "| post-call LOOPCHK(0x40151d):", hit(LOOPCHK),
          "| EPILOGUE add rsp(0x401526):", hit(EPILOGUE),
          "| EPILOGUE ret(0x401534):", hit(RET))
    print("trace:", [hex(a) for a in seen])
    print("RESULT:", "PASS" if (ok_calls and sat and hit(EPILOGUE) and hit(RET) and hit(DISPATCH)) else "FAIL")

print("\nc1 payload words:")
for i, v in enumerate(c1._values):
    try:
        n = v.args[0] if v.op == 'BVV' else ('next_pc(BVS)' if 'next_pc' in str(v) else v.op)
    except Exception:
        n = repr(v)
    print("  [%2d] %s" % (i, hex(n) if isinstance(n, int) else n))
print("\ngadgets used:", [hex(g.addr) for g in c1._gadgets])
