"""
V2 review probe F2d: cost re-measurement.
  - first returning func_call (discovery) vs cached repeat (n=20)
  - needs_return=False: discovery must be skipped entirely (monkeypatch counter)
  - discovery-only cost isolated
  - why only ONE cache entry after a successful call (candidate ordering)
Run from repo root.
"""
import os, time, logging as _logging
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)

p = angr.Project("bins/vuln_client3", auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")
fc = r._chain_builder._func_caller

disc_calls = []
orig_disc = fc._discover_csu_epilogue
def counting_disc(g, base, idx):
    t0 = time.perf_counter()
    res = orig_disc(g, base, idx)
    disc_calls.append((g.addr, time.perf_counter() - t0, res is not None))
    return res
fc._discover_csu_epilogue = counting_disc

# needs_return=False: discovery must not be called at all
t0 = time.perf_counter()
c_term = r.func_call(0x4011C6, [1, 2, 3], needs_return=False)
dt_false = time.perf_counter() - t0
print("[*] needs_return=False: %.4fs, discovery calls=%d, cache=%d"
      % (dt_false, len(disc_calls), len(fc._csu_epilogue_cache)))

# first returning call: discovery runs
t0 = time.perf_counter()
c1 = r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
dt_first = time.perf_counter() - t0
print("[*] first needs_return=True: %.4fs, discovery calls: %s"
      % (dt_first, [(hex(a), round(d, 4), ok) for a, d, ok in disc_calls]))

# 20 cached repeats
t0 = time.perf_counter()
for _ in range(20):
    r.func_call(0x4011C6, [1, 2, 3], needs_return=True)
dt_rep = (time.perf_counter() - t0) / 20
print("[*] cached repeat mean over 20: %.4fs (discovery calls now=%d)"
      % (dt_rep, len(disc_calls)))

# discovery-only cost, isolated, fresh FuncCaller (bypass chain assembly)
p2 = angr.Project("bins/vuln_client3", auto_load_libs=False)
r2 = p2.analyses.ROP()
r2.load_gadgets("gadgets.cache")
fc2 = r2._chain_builder._func_caller
g = next(g for g in fc2._func_jmp_gadgets if g.addr == 0x401510)
t0 = time.perf_counter()
epi = fc2._discover_csu_epilogue(g, "r15", "rbx")
dt_disc = time.perf_counter() - t0
print("[*] discovery-only (fresh): %.4fs -> %r" % (dt_disc, epi))
t0 = time.perf_counter()
epi2 = fc2._discover_csu_epilogue(g, "r15", "rbx")
dt_cached = time.perf_counter() - t0
print("[*] discovery-only (cached): %.6fs" % dt_cached)

# how many candidates reach _try_csu_return (explains single cache entry)?
attempts = []
orig_try = fc2._try_csu_return
def logged(g, registers, ptr):
    attempts.append(g.addr)
    return orig_try(g, registers, ptr)
fc2._try_csu_return = logged
r2.func_call(0x4011C6, [1, 2, 3], needs_return=True)
print("[*] candidates tried in order:", [hex(a) for a in attempts])
print("[*] full func_jmp pool:", sorted(hex(g.addr) for g in fc2._func_jmp_gadgets))
jmp_mems = [g for g in fc2._func_jmp_gadgets if g.transit_type == "jmp_mem"]
print("[*] jmp_mem gadgets in pool:", [(hex(g.addr), str(g.pc_target)) for g in jmp_mems])
