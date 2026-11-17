# Probe §3.2 — needs_return=None semantics change.
# On the SEEDED csu scenario (where pristine succeeds at all), compare:
#   pristine default func_call          -> terminal chain (shorter)
#   patched  default func_call          -> returning chain (preferred now)
# Same args; measure chain word count and whether each still executes to the
# callee with rdx controlled (concrete exec like flip.py does).
# Usage: python sem_change.py <pristine|patched>
import logging, sys, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL)
logging.getLogger("angr").setLevel(logging.CRITICAL)
MODE = sys.argv[1] if len(sys.argv) > 1 else "?"
B = "bins/unexploitable"
ARGS = [0x41414141, 0x4242424242424242, 0x4343434343434343]

p = angr.Project(B, auto_load_libs=False)
rop = p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)

kw = {} if MODE == "patched" else {"needs_return": False}
chain = rop.func_call("sleep", ARGS, **kw)
n = len(chain._values)
np = chain.next_pc_idx()
sa = p.loader.main_object.imports['sleep'].value
st = chain.concrete_exec_til_addr(sa)
rdx = st.regs.rdx.concrete_value
gadgets = [hex(getattr(g, 'addr', 0)) for g in chain._gadgets]
print("%-8s default-call words=%d next_pc_idx=%s rdx=%#x rdx_ok=%s gadgets=%s" % (
    MODE, n, np, rdx, rdx == ARGS[2], gadgets))
