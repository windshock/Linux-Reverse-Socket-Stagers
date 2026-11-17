import logging, os, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
from angrop.errors import RopException
BIN="bins/vuln_client3"; CACHE="gadgets.cache"
NET_SEND=0x4011c6
FD,BUF,LEN = 0x41414141, 0x42424242, 0x43434343

class CaptureSend(angr.SimProcedure):
    def run(self):
        s=self.state
        CaptureSend.cap = {'edi': s.solver.eval(s.regs.edi),
                           'rsi': s.solver.eval(s.regs.rsi),
                           'rdx': s.solver.eval(s.regs.rdx)}
        return 0

def main():
    p=angr.Project(BIN, auto_load_libs=False)
    r=p.analyses.ROP()
    r.load_gadgets(CACHE)
    p.hook(NET_SEND, CaptureSend())
    print("=== build returning chain ===", flush=True)
    chain = r.func_call(NET_SEND, [FD,BUF,LEN], needs_return=True)
    idx = chain.next_pc_idx()
    print("  next_pc_idx =", idx, "(None => NOT returning)", flush=True)

    print("=== chainability: chain + chain ===", flush=True)
    try:
        chained = chain + chain
        print("  chain+chain OK, total values =", len(chained._values), flush=True)
    except Exception as e:
        print("  chain+chain FAILED:", type(e).__name__, e, flush=True)

    print("=== ORACLE: symbolic exec of the chain ===", flush=True)
    try:
        final = chain.exec()
        cap = getattr(CaptureSend, 'cap', None)
        print("  net_send captured:", {k:hex(v) for k,v in cap.items()} if cap else None, flush=True)
        ok = cap and cap['edi']==FD and cap['rsi']==BUF and cap['rdx']==LEN
        print("  args correct (edi=FD,rsi=BUF,rdx=LEN)?", ok, flush=True)
        # unconstrained final pc == returned to symbolic next_pc
        pc = final.regs.pc
        print("  final pc symbolic (==returned to next_pc)?", pc.symbolic, flush=True)
        print("  RESULT:", "PASS" if (ok and pc.symbolic) else "FAIL", flush=True)
    except RopException as e:
        print("  exec FAILED:", e, flush=True)
        print("  RESULT: FAIL", flush=True)

if __name__ == '__main__':
    main()
