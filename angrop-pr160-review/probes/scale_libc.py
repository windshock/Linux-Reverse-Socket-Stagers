# Scale probe (§3.1 / blindspot #1): full realistic gadget set = glibc 2.19 (cache).
# Compare func_call outcomes pristine vs patched. Usage: python scale_libc.py <tag>
import logging, sys, time, angr, angrop
logging.getLogger("angrop").setLevel(logging.CRITICAL)
logging.getLogger("angr").setLevel(logging.CRITICAL)
MODE = sys.argv[1] if len(sys.argv) > 1 else "?"
BIN = "binaries/tests/x86_64/libc.so.6"
CACHE = "binaries/tests_data/angrop_gadgets_cache/amd64_glibc_2.19"
ARGS3 = [0x41414141, 0x4242424242424242, 0x4343434343434343]

p = angr.Project(BIN, auto_load_libs=False)
rop = p.analyses.ROP()
rop.load_gadgets(CACHE, optimize=False)
print("[%s] gadgets loaded: %d" % (MODE, len(rop.rop_gadgets)))

for sym, args, kw in [("sleep", ARGS3, {}),
                      ("sleep", ARGS3, {"needs_return": True}),
                      ("puts", [0x41414141], {"needs_return": True}),
                      ("malloc", [0x100], {"needs_return": True})]:
    t0 = time.time()
    try:
        ch = rop.func_call(sym, args, **kw)
        dt = time.time() - t0
        print("  %-8s %-24s -> BUILT words=%-3d next_pc=%-4s %.2fs gadgets=%s" % (
            sym, kw or "default", len(ch._values), ch.next_pc_idx(), dt,
            [hex(g.addr) for g in ch._gadgets]))
    except Exception as e:
        dt = time.time() - t0
        print("  %-8s %-24s -> RAISED %s (%.2fs)" % (sym, kw or "default", str(e)[:60], dt))
