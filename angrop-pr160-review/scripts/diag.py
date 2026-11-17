import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR)
B="bins/unexploitable"

def try_call(label, seed_only=False, needs_return=None, extra_analyze=False):
    p=angr.Project(B, auto_load_libs=False)
    rop=p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    if seed_only:
        rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)
    else:
        rop.find_gadgets_single_threaded(show_progress=False)
        if extra_analyze:
            rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)
    # introspect func_jmp bootstrap
    fc=rop.chain_builder._func_caller
    fc.bootstrap()
    jmp=fc._func_jmp_gadgets or set()
    has_csu = any(g.addr==0x4005D0 for g in jmp)
    kw={} if needs_return is None else {"needs_return":needs_return}
    try:
        chain=rop.func_call("sleep",[0x41414141,0x4242424242424242,0x4343434343434343],**kw)
        sa=p.loader.main_object.imports['sleep'].value
        st=chain.concrete_exec_til_addr(sa)
        ok=(st.regs.rdx.concrete_value==0x4343434343434343)
        res="PASS rdx=%#x"%st.regs.rdx.concrete_value if ok else "MISMATCH"
    except Exception as e:
        res="FAIL: %s"%e
    print("%-42s ndg=%-3d jmp_has_csu=%-5s -> %s"%(label,len(rop.rop_gadgets),has_csu,res),flush=True)

try_call("A seed-only(2 gadgets)", seed_only=True)
try_call("B find_gadgets default", )
try_call("C find_gadgets + needs_return=False", needs_return=False)
try_call("D find_gadgets + re-analyze csu", extra_analyze=True)
