import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
B="bins/unexploitable"; A=[0x41414141,0x4242424242424242,0x4343434343434343]

def mk():
    p=angr.Project(B, auto_load_libs=False)
    rop=p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)   # scenario A (csu works)
    return p,rop

print("=== (1) func_call needs_return=True (require return after a csu call) ===")
p,rop=mk()
try:
    c=rop.func_call("sleep",A,needs_return=True)
    print("   built: YES (unexpected). gadgets:",[hex(getattr(g,'addr',0)) for g in c._gadgets])
except Exception as e:
    print("   RAISED:",e)

print("=== (2) func_call default needs_return (None) ===")
p,rop=mk()
import io,contextlib,logging as L
buf=io.StringIO(); h=L.StreamHandler(buf); L.getLogger("angrop.chain_builder.func_caller").addHandler(h); L.getLogger("angrop.chain_builder.func_caller").setLevel(L.WARNING)
c=rop.func_call("sleep",A)
print("   built: YES. gadgets:",[hex(getattr(g,'addr',0)) for g in c._gadgets])
print("   warning emitted:", "won't return" in buf.getvalue() or buf.getvalue().strip())

print("=== (3) try to CHAIN after a csu call: func_call + func_call ===")
p,rop=mk()
try:
    c=rop.func_call("sleep",A) + rop.func_call("sleep",A)
    print("   chained build: YES (len gadgets %d)"%len(c._gadgets))
except Exception as e:
    print("   chain RAISED:",e)
