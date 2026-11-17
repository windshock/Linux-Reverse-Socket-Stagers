# Probe on the synthetic ELF (probes/fp_synth):
#  T1 adaptivity: thunk_call 0x40101e has a CUSTOM 3-slot epilogue (not glibc's 7).
#     discovery must report cleanup_slots=3 and a returning chain must EXECUTE.
#  T2 non-csu shape: thunk_jmp 0x401010 is a pure JMP [r15+rbx*8] (no call/epilogue).
#     the parser matches its pc_target; what does _try_csu_return do? if it returns
#     a chain, execute it UNHOOKED (the callee fn is a plain `ret`) and see whether
#     control truly comes back to next_pc.
import logging, time, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR)
logging.getLogger("angr").setLevel(logging.CRITICAL)
from angrop.chain_builder.func_caller import FuncCaller
from angrop.errors import RopException

FN = 0x401033          # plain `ret` function
TBL = 0x402000         # table[0] = FN
THUNK_JMP, THUNK_CALL, LOADER = 0x401010, 0x40101e, 0x401000
ARGS = {'rdi': 0x11111111, 'rsi': 0x2222222222222222, 'rdx': 0x3333333333333333}

p = angr.Project("probes/fp_synth", auto_load_libs=False)
r = p.analyses.ROP(fast_mode=False, only_check_near_rets=False)
r.analyze_gadget(LOADER)
for a in (THUNK_JMP, THUNK_CALL):
    r.analyze_gadget(a)
fc = [b for b in vars(r.chain_builder).values() if isinstance(b, FuncCaller)][0]
fc.bootstrap()

def exec_chain(chain, sentinel=0x401036):
    state = chain._blank_state.copy()
    vals = chain._concretize_chain_values(timeout=None, preserve_next_pc=True, append_shift=False)
    for i, v in enumerate(vals):
        state.memory.store(state.regs.sp + i*p.arch.bytes, v[0], p.arch.bytes,
                           endness=p.arch.memory_endness)
    state.regs.pc = state.stack_pop()
    simgr = p.factory.simulation_manager(state, save_unconstrained=True)
    trace = []
    for _ in range(200):
        if not (simgr.active or simgr.unconstrained): break
        if simgr.active: trace.append(simgr.active[0].addr)
        if simgr.unconstrained:
            u = simgr.unconstrained[0]
            u.add_constraints(u.regs.pc == sentinel)
            # also check arg regs survived the trip for the call case
            return True, u.solver.satisfiable(), trace
        simgr.step()
    return False, None, trace

# --- T1: adaptive epilogue count
g = r.analyze_gadget(THUNK_CALL)
parsed = fc._parse_csu_dispatch(g.pc_target)
print("T1 thunk_call parsed:", parsed)
t0=time.time(); epi = fc._discover_csu_epilogue(g, *parsed); dt=time.time()-t0
print("T1 discovery (expect cleanup_slots=3, NOT 7):", epi, "(%.2fs)"%dt)
ptr = fc._find_function_pointer(FN)
print("T1 _find_function_pointer(0x401033) ->", hex(ptr) if ptr else None,
      "(scan missed on synthetic; using table addr explicitly)")
ptr = TBL
ch = fc._try_csu_return(g, dict(ARGS), ptr)
print("T1 chain built:", ch is not None)
if ch:
    print("T1 chain words:", len(ch._values), "layout tail:", [str(v)[:40] for v in ch._values[-5:]])
    reached, sat, trace = exec_chain(ch)
    print("T1 exec: unconstrained-reached=%s sentinel-sat=%s" % (reached, sat))
    print("T1 trace:", [hex(a) for a in trace])

# --- T2: pure jmp thunk (non-csu shape, parser matches)
g2 = r.analyze_gadget(THUNK_JMP)
parsed2 = fc._parse_csu_dispatch(g2.pc_target)
print("\nT2 thunk_jmp parsed:", parsed2, "(parser DOES match a non-csu jmp shape)" if parsed2 else "")
if parsed2:
    epi2 = fc._discover_csu_epilogue(g2, *parsed2)
    print("T2 discovery on jmp-thunk:", epi2)
    ch2 = fc._try_csu_return(g2, dict(ARGS), ptr)
    print("T2 chain built:", ch2 is not None)
    if ch2:
        print("T2 chain words:", len(ch2._values), "next_pc_idx:", ch2.next_pc_idx())
        reached, sat, trace = exec_chain(ch2)
        print("T2 exec UNHOOKED (real ret-callee): reached=%s sat=%s" % (reached, sat))
        print("T2 trace:", [hex(a) for a in trace])

# --- T3: END-TO-END func_call on the synthetic binary (the real code path:
#         reg_moves rewrite happens inside func_call, not in my direct calls above)
print("\nT3 func_call(0x401033, needs_return=True) end-to-end:")
caps = []
class Cap(angr.SimProcedure):
    def run(self):
        s = self.state
        caps.append(tuple(s.solver.eval(v) for v in (s.regs.edi, s.regs.rsi, s.regs.rdx)))
        return 0
try:
    c3 = r.func_call(FN, [ARGS['rdi'], ARGS['rsi'], ARGS['rdx']], needs_return=True)
    print("T3 built: words=%d next_pc_idx=%s gadgets=%s" % (
        len(c3._values), c3.next_pc_idx(), [hex(g.addr) for g in c3._gadgets]))
    p.hook(FN, Cap())
    reached, sat, tr = exec_chain(c3)
    print("T3 exec: reached=%s sentinel-sat=%s caps=%s" % (reached, sat, [tuple(hex(x) for x in c_) for c_ in caps]))
    print("T3 trace:", [hex(a) for a in tr])
except Exception as e:
    print("T3 RAISED:", type(e).__name__, e)
