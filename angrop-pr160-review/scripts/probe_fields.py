import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)

def main():
    print("START", flush=True)
    p=angr.Project("bins/vuln_client3", auto_load_libs=False)
    print("PROJECT loaded", flush=True)
    r=p.analyses.ROP()
    try:
        r.find_gadgets(show_progress=False, processes=1)
    except TypeError:
        r.find_gadgets(show_progress=False)
    print("GADGETS found:", len(r._all_gadgets), flush=True)
    want=[0x401509,0x401510,0x401511,0x40152a]
    for g in sorted(r._all_gadgets, key=lambda x:x.addr):
        if g.addr in want:
            print("addr=%#x transit=%s stack_change=%s pc_offset=%s self_contained=%s"%(
                g.addr, getattr(g,'transit_type',None), getattr(g,'stack_change',None),
                getattr(g,'pc_offset',None), getattr(g,'self_contained',None)), flush=True)
            print("   moves=", [(m.from_reg,m.to_reg) for m in getattr(g,'reg_moves',[])], flush=True)
            print("   pc_target=", getattr(g,'pc_target',None), flush=True)
    print("DONE", flush=True)

if __name__ == '__main__':
    main()
