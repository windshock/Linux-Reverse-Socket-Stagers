# Probe §3.4 — discovery false-positives: find EVERY jmp_mem gadget whose pc_target
# parses as base+idx*scale (not just the canonical csu), run _try_csu_return on it,
# and EXECUTE whatever chain it returns to check it truly returns to next_pc.
# Also times discovery (blindspot #4b: per-call symbolic-exec cost).
import logging, time, sys, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR)
logging.getLogger("angr").setLevel(logging.CRITICAL)
from angrop.chain_builder.func_caller import FuncCaller

def probe(binpath, cache):
    p = angr.Project(binpath, auto_load_libs=False)
    r = p.analyses.ROP(); r.load_gadgets(cache)
    fc = [b for b in vars(r.chain_builder).values() if isinstance(b, FuncCaller)][0]
    fc.bootstrap()
    print(f"== {binpath}: {len(fc._func_jmp_gadgets)} func_jmp gadgets")
    matches = []
    for g in fc._func_jmp_gadgets:
        if g.transit_type != 'jmp_mem':
            continue
        parsed = fc._parse_csu_dispatch(getattr(g, 'pc_target', None))
        if parsed:
            matches.append((g, parsed))
    print(f"   csu-parseable jmp_mem gadgets: {len(matches)}")
    for g, (base, idx) in matches:
        t0 = time.time()
        epi = fc._discover_csu_epilogue(g, base, idx)
        dt = time.time() - t0
        print("   g=%#x base=%s idx=%s -> %s  (%.2fs)" % (g.addr, base, idx, epi, dt))
    return p, r, fc, matches

def verify_chain_returns(p, r, fc, g, base, idx):
    # emulate what _try_csu_return does, but keep the chain for execution check
    ptr = fc._find_function_pointer(0x4011c6 if 'vuln_client3' in p.loader.main_object.binary else 0x4005f0)
    regs = {'rdi': 0x11111111, 'rsi': 0x2222222222222222, 'rdx': 0x3333333333333333}
    ch = fc._try_csu_return(g, regs.copy(), ptr)
    if ch is None:
        return None
    # execute: final pc must pin to a sentinel (controllable next_pc)
    state = ch._blank_state.copy()
    vals = ch._concretize_chain_values(timeout=None, preserve_next_pc=True, append_shift=False)
    for i, v in enumerate(vals):
        state.memory.store(state.regs.sp + i * p.arch.bytes, v[0], p.arch.bytes,
                           endness=p.arch.memory_endness)
    state.regs.pc = state.stack_pop()
    simgr = p.factory.simulation_manager(state, save_unconstrained=True)
    for _ in range(400):
        if not (simgr.active or simgr.unconstrained):
            break
        if simgr.unconstrained:
            u = simgr.unconstrained[0]
            u.add_constraints(u.regs.pc == 0x401544)
            return u.solver.satisfiable()
        simgr.step()
    return False

if __name__ == '__main__':
    p3, r3, fc3, m3 = probe("bins/vuln_client3", "gadgets.cache")
    pu, ru, fcu, mu = probe("bins/unexploitable", "gadgets_unexploitable.cache")
    # verify every NON-canonical match actually returns (false-positive hunt)
    canon3 = {0x401510, 0x401511, 0x401513, 0x401514, 0x401516}
    for g, (base, idx) in m3:
        if g.addr in canon3:
            continue
        print("VERIFY non-canonical", hex(g.addr), "->", verify_chain_returns(p3, r3, fc3, g, base, idx))
