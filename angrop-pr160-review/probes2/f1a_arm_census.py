"""
V2 review probe F1a: re-derive the ARMEL census of csu-parseable jmp_mem gadgets
in binaries/tests/armel/libc-2.31.so (cache armel_glibc_2.31), verify claimed
addresses, verify discovery returns None instantly, and verify NO hook is ever
installed on non-AMD64. Also scan i386 and aarch64 caches (claimed: 0 parseable).
Run from repo root.
"""
import os, time, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

CACHE_DIR = "binaries/tests_data/angrop_gadgets_cache"

def my_parse(pc_target):
    """independent re-implementation of the patch's _parse_csu_dispatch semantics"""
    if pc_target is None or pc_target.op != '__add__':
        return None
    base = idx = None
    for arg in pc_target.args:
        if arg.op == 'BVS' and arg.args[0].startswith('sreg_'):
            base = arg.args[0][5:].split('-')[0]
        elif arg.op in ('__lshift__', '__mul__'):
            stack = list(arg.args)
            while stack:
                sub = stack.pop()
                if sub.op == 'BVS' and sub.args[0].startswith('sreg_'):
                    idx = sub.args[0][5:].split('-')[0]
                    break
                stack.extend(sub.args if sub.op in ('__sub__', '__add__', '__lshift__',
                                                    '__mul__', '__and__', '__or__') else ())
    if base and idx:
        return base, idx
    return None

def census(binpath, cachepath, label):
    kw = {"armel": dict(fast_mode=False, only_check_near_rets=False, is_thumb=True),
          "i386": dict(fast_mode=False, only_check_near_rets=False),
          "aarch64": dict(fast_mode=True, only_check_near_rets=False)}[label]
    p = angr.Project(binpath, auto_load_libs=False)
    r = p.analyses.ROP(**kw)
    if os.path.exists(cachepath):
        r.load_gadgets(cachepath, optimize=False)
        r._chain_builder._func_caller.bootstrap()   # ensure func_jmp pool is built
    else:
        raise SystemExit("cache missing: " + cachepath)
    fc = r._chain_builder._func_caller
    jmp_mems = [g for g in fc._func_jmp_gadgets if g.transit_type == 'jmp_mem']
    hits = []
    for g in jmp_mems:
        pr = my_parse(g.pc_target)
        if pr:
            hits.append((g.addr, pr, g))
    print("[%s] arch.name=%r simos=%r jmp_mem gadgets=%d csu-parseable=%d"
          % (label, p.arch.name, p.simos.name if p.simos else None, len(jmp_mems), len(hits)))
    for addr, pr, g in sorted(hits):
        print("    %#x parse=%s pc_target=%s" % (addr, pr, g.pc_target))
    return p, fc, hits

# --- ARMEL: the claimed 4 gadgets ---
p, fc, hits = census("binaries/tests/armel/libc-2.31.so", CACHE_DIR + "/armel_glibc_2.31", "armel")
claimed = {0x4b985f, 0x4b9861, 0x4b9863, 0x44361f}
found = {a for a, _, _ in hits}
print("[armel] claimed set matches found set:", claimed == found,
      "| missing:", [hex(x) for x in claimed - found], "| extra:", [hex(x) for x in found - claimed])

# now run the PATCHED discovery on each: must return None instantly, and never hook
FAKE = 0x43430000
for addr, pr, g in sorted(hits, key=lambda t: t[0]):
    t0 = time.perf_counter()
    epi = fc._discover_csu_epilogue(g, pr[0], pr[1])
    dt = time.perf_counter() - t0
    print("[armel] discovery(%#x) -> %r  in %.4fs  hooked(FAKE)=%s cache=%d"
          % (addr, epi, dt, p.is_hooked(FAKE), len(fc._csu_epilogue_cache)))
    assert epi is None, "discovery returned non-None on ARM!"
    assert dt < 0.05, "discovery was not instant!"
    assert not p.is_hooked(FAKE), "hook leaked on non-AMD64!"

# also verify _try_csu_return falls back (returns None) for the first hit
addr, pr, g = sorted(hits, key=lambda t: t[0])[0]
t0 = time.perf_counter()
res = fc._try_csu_return(g, {}, 0x1234)
print("[armel] _try_csu_return(%#x) -> %r in %.4fs" % (addr, res, time.perf_counter() - t0))
assert res is None

# and the gate's placement: cache untouched on non-AMD64 even after repeated calls
fc._discover_csu_epilogue(g, pr[0], pr[1])
print("[armel] cache size after repeated discovery attempts:", len(fc._csu_epilogue_cache))

# --- i386 and aarch64 (claimed 0 parseable) ---
census("binaries/tests/i386/i386_glibc_2.35", CACHE_DIR + "/i386_glibc_2.35", "i386")
census("binaries/tests/aarch64/libc.so.6" if os.path.exists("binaries/tests/aarch64/libc.so.6")
       else "binaries/tests/aarch64/glibc", CACHE_DIR + "/aarch64_glibc_2.19", "aarch64")
print("[*] F1a census done")
