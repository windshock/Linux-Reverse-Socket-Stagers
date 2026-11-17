import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL); logging.getLogger("angr").setLevel(logging.CRITICAL)
p=angr.Project("bins/vuln_client3", auto_load_libs=False)
rop=p.analyses.ROP(fast_mode=False, only_check_near_rets=False)
rop.find_gadgets_single_threaded(show_progress=False)
cb=rop.chain_builder; fc=cb._func_caller; fc.bootstrap(); rs=cb._reg_setter
# csu dispatch addr: find a jmp_mem gadget with reg_moves into rdi/rsi/rdx
csu=[g for g in rop.rop_gadgets if getattr(g,'transit_type',None)=='jmp_mem' and any(m.to_reg=='rdx' for m in getattr(g,'reg_moves',[]))]
print("csu-like jmp_mem gadgets (move->rdx):", [hex(g.addr) for g in csu])
print("in func_jmp pool:", [hex(g.addr) for g in (fc._func_jmp_gadgets or set()) if any(m.to_reg=='rdx' for m in g.reg_moves)])
print("can_set_reg rdi/rsi/rdx:", {r:rs.can_set_reg(r) for r in ('rdi','rsi','rdx')})
for name in ("net_send","send"):
    sym=p.loader.main_object.get_symbol(name)
    addr=sym.rebased_addr if sym else (p.loader.main_object.plt.get(name))
    ptr=fc._find_function_pointer(addr) if addr else None
    print("%-9s addr=%s ptr_to_func=%s"%(name, hex(addr) if addr else None, hex(ptr) if ptr else None))
