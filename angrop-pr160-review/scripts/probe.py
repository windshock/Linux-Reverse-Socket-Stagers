import angr, angrop
B="bins/unexploitable"
p=angr.Project(B, auto_load_libs=False)
rop=p.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
rop.find_gadgets_single_threaded(show_progress=False)
addrs={g.addr for g in rop.rop_gadgets}
print("total gadgets:", len(addrs))
for a in (0x4005D0, 0x4005E6):
    print(hex(a), "in default find_gadgets?", a in addrs)
# classify the csu dispatch once explicitly analyzed
g=rop.analyze_gadget(0x4005D0)
print("0x4005D0 transit_type =", getattr(g,"transit_type",None))
print("0x4005D0 reg_moves    =", [(m.from_reg,m.to_reg) for m in getattr(g,"reg_moves",[])])
print("0x4005D0 self_contained =", getattr(g,"self_contained",None))
