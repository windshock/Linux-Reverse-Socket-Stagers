import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL)
B="bins/unexploitable"

def analyze(label, seed_only):
    p=angr.Project(B, auto_load_libs=False)
    rop=p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    if seed_only:
        rop.analyze_gadget(0x4005D0); rop.analyze_gadget(0x4005E6)
    else:
        rop.find_gadgets_single_threaded(show_progress=False)
    cb=rop.chain_builder; fc=cb._func_caller; fc.bootstrap()
    rs=cb._reg_setter
    arg_regs=fc._cc.ARG_REGS[:3]   # rdi, rsi, rdx
    registers={r:0x41 for r in arg_regs}
    hard=[x for x in registers if not rs.can_set_reg(x)]
    print("\n[%s] gadgets=%d"%(label,len(rop.rop_gadgets)))
    print("  can_set_reg: " + ", ".join("%s=%s"%(r, rs.can_set_reg(r)) for r in arg_regs))
    print("  hard_regs =", hard)
    # find the csu dispatch gadget object and replay the skip test (line 239)
    csu=[g for g in (fc._func_jmp_gadgets or set()) if g.addr==0x4005D0]
    if not csu:
        print("  csu dispatch NOT in func_jmp pool"); return
    g=csu[0]
    moves=[(m.from_reg,m.to_reg) for m in g.reg_moves]
    print("  csu reg_moves =", moves)
    skip=False; trip=None
    for (fr,to) in moves:
        if fr in hard or to not in hard:
            skip=True; trip=(fr,to); break
    print("  -> skip csu gadget?", skip, ("(tripped on move %s->%s: to_reg not hard)"%trip if skip else ""))

analyze("A seed-only", True)
analyze("B default", False)
