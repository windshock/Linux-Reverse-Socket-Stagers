import os, sys, traceback
import angr
import angrop  # noqa: F401  (registers the ROP analysis plugin)

BIN = os.path.join(os.path.dirname(__file__), "bins", "unexploitable")

def banner(s): print("\n==== %s ====" % s, flush=True)

def check(chain, proj):
    sleep_addr = proj.loader.main_object.imports['sleep'].value
    state = chain.concrete_exec_til_addr(sleep_addr)
    rdi = state.regs.rdi.concrete_value
    rsi = state.regs.rsi.concrete_value
    rdx = state.regs.rdx.concrete_value
    print("rdi=%#x rsi=%#x rdx=%#x" % (rdi, rsi, rdx), flush=True)
    ok = (rdi == 0x41414141 and rsi == 0x4242424242424242 and rdx == 0x4343434343434343)
    print("RESULT:", "PASS (rdx controlled)" if ok else "MISMATCH", flush=True)
    return ok

# -------- Scenario 1: PURE auto discovery, no manual gadget seeding --------
banner("Scenario 1: find_gadgets() default, then func_call('sleep',[a,b,c])")
try:
    proj = angr.Project(BIN, auto_load_libs=False)
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    rop.find_gadgets_single_threaded(show_progress=False)
    print("gadgets found:", len(rop.rop_gadgets), flush=True)
    chain = rop.func_call("sleep", [0x41414141, 0x4242424242424242, 0x4343434343434343])
    s1 = check(chain, proj)
except Exception as e:
    s1 = False
    print("Scenario 1 EXCEPTION:", repr(e), flush=True)
    traceback.print_exc()

# -------- Scenario 2: replicate upstream test_unexploitable exactly --------
banner("Scenario 2: upstream test_unexploitable (explicit analyze_gadget seeding)")
try:
    proj = angr.Project(BIN, auto_load_libs=False)
    rop = proj.analyses.ROP(max_block_size=40, fast_mode=False, only_check_near_rets=False)
    g = rop.analyze_gadget(0x4005D0)  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
    print("0x4005D0 analyzed:", g is not None, flush=True)
    g = rop.analyze_gadget(0x4005E6)  # mov rbx,[rsp+8]; ...; mov r15,[rsp+0x30]; add rsp,0x38; ret
    print("0x4005E6 analyzed:", g is not None, flush=True)
    chain = rop.func_call("sleep", [0x41414141, 0x4242424242424242, 0x4343434343434343])
    s2 = check(chain, proj)
except Exception as e:
    s2 = False
    print("Scenario 2 EXCEPTION:", repr(e), flush=True)
    traceback.print_exc()

banner("SUMMARY")
print("Scenario 1 (pure auto):      ", "PASS" if s1 else "FAIL", flush=True)
print("Scenario 2 (upstream test):  ", "PASS" if s2 else "FAIL", flush=True)
print("angr version:", angr.__version__, flush=True)
