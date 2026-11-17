import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
def main():
    p=angr.Project("bins/vuln_client3", auto_load_libs=False)
    r=p.analyses.ROP(); r.load_gadgets("gadgets.cache")
    fc = r.chain_builder._func_caller if hasattr(r.chain_builder,'_func_caller') else None
    # find the FuncCaller builder
    from angrop.chain_builder.func_caller import FuncCaller
    fcs=[b for b in vars(r.chain_builder).values() if isinstance(b,FuncCaller)]
    fc=fcs[0]; fc.bootstrap()
    # find the canonical csu dispatch gadget
    for g in fc._func_jmp_gadgets:
        if getattr(g,'pc_target',None) is not None and g.transit_type=='jmp_mem':
            parsed=fc._parse_csu_dispatch(g.pc_target)
            if parsed:
                base,idx=parsed
                epi=fc._discover_csu_epilogue(g, base, idx)
                print("g=%#x parsed base=%s idx=%s -> %s"%(g.addr, base, idx, epi), flush=True)
if __name__=='__main__': main()
