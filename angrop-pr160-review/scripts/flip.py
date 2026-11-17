import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL)
logging.getLogger("angr").setLevel(logging.CRITICAL)
B = "bins/unexploitable"
ARGS = [0x41414141, 0x4242424242424242, 0x4343434343434343]

def run(label, seed_only):
    p = angr.Project(B, auto_load_libs=False)
    rop = p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    if seed_only:
        rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)
    else:
        rop.find_gadgets_single_threaded(show_progress=False)
    try:
        chain = rop.func_call("sleep", ARGS)
    except Exception as e:
        print("%-22s ndg=%-3d -> FAIL: %s" % (label, len(rop.rop_gadgets), e))
        return
    sa = p.loader.main_object.imports['sleep'].value
    st = chain.concrete_exec_til_addr(sa)
    rdx = st.regs.rdx.concrete_value
    # does the built chain actually use the csu dispatch gadget?
    gaddrs = []
    for g in chain._gadgets:
        a = getattr(g, "addr", None)
        if a is not None:
            gaddrs.append(a)
    uses_csu = 0x4005D0 in gaddrs
    ok = (rdx == 0x4343434343434343)
    print("%-22s ndg=%-3d -> %s rdx=%#x uses_csu=%s" % (
        label, len(rop.rop_gadgets), "PASS" if ok else "MISMATCH", rdx, uses_csu))

import sys
tag = sys.argv[1] if len(sys.argv) > 1 else "?"
print("=== %s === (angrop %s)" % (tag, angrop.__version__))
run("A seed-only", True)
run("B default", False)
