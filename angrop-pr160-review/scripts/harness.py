import logging, os, sys, angr, angrop
logging.getLogger("angrop").setLevel(logging.ERROR); logging.getLogger("angr").setLevel(logging.CRITICAL)
from angrop.errors import RopException

BIN="bins/vuln_client3"
CACHE="gadgets.cache"
NET_SEND=0x4011c6   # from lab3_why.py: net_send addr, ptr_to_func=0x403e10
FD,BUF,LEN = 0x41414141, 0x42424242, 0x43434343

def get_rop():
    p=angr.Project(BIN, auto_load_libs=False)
    r=p.analyses.ROP()
    if os.path.exists(CACHE):
        r.load_gadgets(CACHE); print("[*] loaded gadgets from cache", flush=True)
    else:
        print("[*] finding gadgets (slow, one-time)...", flush=True)
        r.find_gadgets_single_threaded(show_progress=False)
        r.save_gadgets(CACHE); print("[*] gadgets cached:", len(r._all_gadgets), flush=True)
    return p, r

def try_call(r, needs_return, label):
    try:
        chain = r.func_call(NET_SEND, [FD,BUF,LEN], needs_return=needs_return)
        print("  [%s] OK -> chain len=%d bytes" % (label, len(chain.payload_str())), flush=True)
        return chain
    except RopException as e:
        print("  [%s] RopException: %s" % (label, e), flush=True)
    except Exception as e:
        print("  [%s] %s: %s" % (label, type(e).__name__, e), flush=True)
    return None

if __name__ == '__main__':
    p, r = get_rop()
    print("=== BASELINE (pristine angrop) ===", flush=True)
    try_call(r, True,  "needs_return=True ")
    try_call(r, False, "needs_return=False")
    try_call(r, None,  "needs_return=None ")
