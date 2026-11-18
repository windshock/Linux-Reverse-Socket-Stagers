"""
V2 review probe: independently build the returning ret2csu chain on bins/vuln_client3
and dump its structure. Runs from the repo root (angrop-pr160-review).
"""
import os, sys, time, logging as _logging
import angr
import angrop  # noqa: F401  (registers the ROP analysis)
from angr import claripy

os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

BIN = "bins/vuln_client3"
NET_SEND = 0x4011C6

p = angr.Project(BIN, auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
print("[*] gadgets loaded:", len(r._all_gadgets))

fc = r._chain_builder._func_caller
print("[*] arch.name =", p.arch.name, "| simos =", p.simos.name if p.simos else None)

t0 = time.perf_counter()
c1 = r.func_call(NET_SEND, [0x41414141, 0x42424242, 0x43434343], needs_return=True)
t1 = time.perf_counter()
print("[*] first func_call(needs_return=True): %.4fs" % (t1 - t0))
print("[*] cache after first call:", {hex(k): v for k, v in fc._csu_epilogue_cache.items()})

t0 = time.perf_counter()
c1b = r.func_call(NET_SEND, [0x11111111, 0x22222222, 0x33333333], needs_return=True)
t1 = time.perf_counter()
print("[*] second func_call (cached): %.4fs" % (t1 - t0))
print("[*] cache size:", len(fc._csu_epilogue_cache))

print("[*] chain1 gadgets:")
for g in c1._gadgets:
    print("   %#x  sc=%d  pc_off=%s  %s" % (g.addr, g.stack_change, g.pc_offset, g.dstr() if hasattr(g, 'dstr') else g.transit_type))
print("[*] chain1 next_pc_idx:", c1.next_pc_idx(), "payload_len:", c1.payload_len)

print("[*] chain1 values (resolved):")
for i, v in enumerate(c1._values):
    if v.symbolic:
        try:
            sol = c1._blank_state.solver.eval(v.ast)
            print("   [%2d] SYMBOLIC %s -> eval %#x (vars=%s)" % (i, v.ast, sol, sorted(v.ast.variables)))
        except Exception as e:
            print("   [%2d] SYMBOLIC %s (unresolvable: %s)" % (i, v.ast, e))
    else:
        print("   [%2d] %#x" % (i, v.converted_value if hasattr(v, 'converted_value') else v.data))

# what's in the fnptr table slot?
s = p.factory.blank_state()
print("[*] [0x403e10] =", hex(s.memory.load(0x403e10, 8).concrete_value))
print("[*] [0x403e18] =", hex(s.memory.load(0x403e18, 8).concrete_value))
print("[*] net_send symbol addr:", hex(p.loader.main_object.get_symbol('net_send').rebased_addr) if p.loader.main_object.get_symbol('net_send') else 'n/a')
for name in ("net_send", "net_recv", "net_open", "net_close"):
    sym = p.loader.main_object.get_symbol(name)
    if sym:
        print("   sym %s = %#x" % (name, sym.rebased_addr))
