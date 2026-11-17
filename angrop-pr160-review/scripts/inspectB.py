import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL); logging.getLogger("angr").setLevel(logging.CRITICAL)
p=angr.Project("bins/unexploitable", auto_load_libs=False)
rop=p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
rop.find_gadgets_single_threaded(show_progress=False)
chain=rop.func_call("sleep",[0x41414141,0x4242424242424242,0x4343434343434343])
sa=p.loader.main_object.imports['sleep'].value
st=chain.concrete_exec_til_addr(sa)
print("rdx=%#x ip=%#x (sleep=%#x)"%(st.regs.rdx.concrete_value, st.ip.concrete_value, sa))
print("chain gadget addrs:", [hex(getattr(g,'addr',0)) for g in chain._gadgets])
for g in chain._gadgets:
    a=getattr(g,'addr',None)
    if a is None: continue
    tt=getattr(g,'transit_type',None)
    mv=[(m.from_reg,m.to_reg) for m in getattr(g,'reg_moves',[])]
    blk=p.factory.block(a)
    print("\n%#x transit=%s moves=%s"%(a,tt,mv))
    print("   ", "; ".join(str(i) for i in blk.capstone.insns[:8]))
