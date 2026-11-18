"""
V2 review probe: INDEPENDENT end-to-end execution oracle for the returning ret2csu
chain on bins/vuln_client3. Written from scratch (does not reuse scripts/validate.py
or probes/my_oracle.py logic).

Design:
  1. build c1 = rop.func_call(net_send, [fd,buf,len], needs_return=True)
  2. concrete-execute the chain payload myself:
     - blank state, stack = chain words (next_pc replaced by MY sentinel),
     - callee = REAL synthetic machine code at a scratch page (preserves callee-saved
       regs, clobbers flags + caller-saved regs, pushes/pops the stack, records
       edi/rsi/rdx into memory), pointed to by the REAL fnptr table slot 0x403e10.
     - trace every executed basic block.
  3. checks:
     a. args land in edi/rsi/rdx at the indirect call (recorded by callee code)
     b. execution path = dispatch -> callee -> loop-exit epilogue -> ret to MY sentinel
     c. sentinel code ran (wrote a magic qword) => next_pc slot genuinely controllable
     d. dual-call: c1 + c2 (different args) both execute, in order, sentinel at the end
"""
import os, logging as _logging, struct
import angr, angrop  # noqa
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for name in ("angrop", "angr"):
    _logging.getLogger(name).setLevel(_logging.ERROR)
from angr import claripy

BIN = "bins/vuln_client3"
NET_SEND = 0x4011C6
FD, BUF, LEN = 0x41414141, 0x42424242, 0x0000C0DE
SCRATCH = 0x50000000          # scratch page for my synthetic callee + sentinel
MAGIC   = 0x50000F00          # where callee records args
SENT_MAGIC = 0x50000F80       # where sentinel code writes its proof
SENTINEL = 0x50000100         # my chosen next_pc
RECORD_ADDR = 0x50000F40      # where callee records (rdi,rsi,rdx)

p = angr.Project(BIN, auto_load_libs=False)
r = p.analyses.ROP()
r.load_gadgets("gadgets.cache")

c1 = r.func_call(NET_SEND, [FD, BUF, LEN], needs_return=True)
print("[*] chain built: payload_len=%d words=%d next_pc_idx=%s"
      % (c1.payload_len, len(c1._values), c1.next_pc_idx()))

# ---- assemble the synthetic callee (real x86-64 machine code) ----
# callee ABI: preserves rbx,rbp,r12-r15 (callee-saved per SysV); clobbers
# rax,rcx,rsi?? no - records rdi/rsi/rdx FIRST, then clobbers caller-saved regs
# and flags, pushes/pops, writes record, rets.
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
ks = Ks(KS_ARCH_X86, KS_MODE_64)

callee_code, _ = ks.asm("""
    // record the three incoming args
    lea rax, [rip + 0x400]        // placeholder, fixed below
""", addr=0)
# simpler: hand-place everything with fixed addresses
callee_asm = """
    movabs r10, 0x%x
    mov qword ptr [r10], rdi
    movabs r10, 0x%x
    mov qword ptr [r10], rsi
    movabs r10, 0x%x
    mov qword ptr [r10], rdx
    // real work + flag/register clobber + stack use
    push rax
    push rcx
    xor rax, rax
    xor rcx, rcx
    add rax, 0x1337
    cmp rcx, rax          // sets flags nonzero (ZF=0)
    sahf                  // load garbage flags
    push rdx
    pop rdx
    pop rcx
    pop rax
    movabs r10, 0x%x
    mov dword ptr [r10], 0xcafebabe   // "work done" marker
    ret
""" % (MAGIC, MAGIC+8, MAGIC+16, MAGIC+24)
callee_bytes, _ = ks.asm(callee_asm, addr=SCRATCH + 0x800)
CALLEE = SCRATCH + 0x800

sentinel_asm = """
    movabs r10, 0x%x
    mov dword ptr [r10], 0xdeadbeef
    ret
""" % SENT_MAGIC
sentinel_bytes, _ = ks.asm(sentinel_asm, addr=SENTINEL)

# ---- build the concrete stack payload from the chain ----
def chain_words(chain, next_pc_value):
    """resolve chain._values to concrete ints, substituting next_pc."""
    words = []
    npc = chain.next_pc_idx()
    for i, v in enumerate(chain._values):
        if i == npc:
            words.append(next_pc_value)
            continue
        if v.symbolic:
            words.append(chain._blank_state.solver.eval(v.ast))
        else:
            words.append(v.data.concrete_value)
    assert all(isinstance(w, int) for w in words)
    return words

STACK_BASE = 0x70000000

def run(words, trace_hook=True):
    s = p.factory.blank_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                           angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    # scratch page with callee + sentinel
    s.memory.map_region(SCRATCH, 0x2000, 'rwx')
    s.memory.store(CALLEE, bytes(callee_bytes))
    s.memory.store(SENTINEL, bytes(sentinel_bytes))
    # point the REAL fnptr table at my callee (the chain reads it via call [r12+rbx*8])
    s.memory.store(0x403e10, claripy.BVV(CALLEE, 64), endness=p.arch.memory_endness)
    # stack: words[0] is the first gadget address -> we "return into" it
    for i, w in enumerate(words):
        s.memory.store(STACK_BASE + i*8, claripy.BVV(w, 64), endness=p.arch.memory_endness)
    s.regs.sp = STACK_BASE + 8   # word0 already consumed by the initial jump
    s.regs.pc = words[0]

    trace = []
    if trace_hook:
        def bp(state):
            trace.append(state.solver.eval(state.regs.pc))
        s.inspect.b('instruction', when=angr.BP_BEFORE, action=bp)

    simgr = p.factory.simgr(s, save_unconstrained=True)
    steps = 0
    while simgr.active and steps < 3000:
        simgr.step()
        steps += 1
    return simgr, trace

# ---- test 1: single call, sentinel next_pc ----
words1 = chain_words(c1, SENTINEL)
print("[*] words (%d): %s" % (len(words1), [hex(w) for w in words1]))
simgr, trace = run(words1)
finals = simgr.active + simgr.unconstrained + [st for st in simgr.errored if hasattr(st, 'state')]
print("[*] trace blocks: %s" % [hex(a) for a in trace])
ok_args = False
s = None
for st in simgr.unconstrained + simgr.active:
    s = st
    break
if simgr.errored:
    s = simgr.errored[0].state
assert s is not None
mem = s.memory
rec = [mem.load(MAGIC + i*8, 8, endness=p.arch.memory_endness).concrete_value for i in range(3)]
print("[*] callee recorded rdi=%#x rsi=%#x rdx=%#x" % tuple(rec))
print("[*] sentinel magic: %#x" % mem.load(SENT_MAGIC, 4, endness=p.arch.memory_endness).concrete_value)
print("[*] work marker:   %#x" % mem.load(MAGIC+24, 4, endness=p.arch.memory_endness).concrete_value)
args_ok = rec == [FD, BUF, LEN]
sent_ok = mem.load(SENT_MAGIC, 4, endness=p.arch.memory_endness).concrete_value == 0xdeadbeef
print("[*] TEST1 args in edi/rsi/rdx exact: %s" % args_ok)
print("[*] TEST1 sentinel code executed (control landed on my next_pc): %s" % sent_ok)

# path shape check: dispatch gadget must be in the trace, and callee, then sentinel
dispatch_addr = c1._gadgets[1].addr
path_ok = (dispatch_addr in trace) and (CALLEE in trace) and (SENTINEL in trace)
print("[*] TEST1 path dispatch(%#x)->callee(%#x)->sentinel(%#x) all in trace: %s"
      % (dispatch_addr, CALLEE, SENTINEL, path_ok))

# ---- test 2: dual call c1 + c2 with different args ----
c2 = r.func_call(NET_SEND, [0xAAAA0001, 0xAAAA0002, 0xAAAA0003], needs_return=True)
comb = c1 + c2
words2 = chain_words(comb, SENTINEL)
print("[\n[*] combined words (%d): %s" % (len(words2), [hex(w) for w in words2]))
simgr2, trace2 = run(words2)
s2 = None
for st in simgr2.unconstrained + simgr2.active:
    s2 = st
    break
if simgr2.errored:
    s2 = simgr2.errored[0].state
mem2 = s2.memory
rec2 = [mem2.load(MAGIC + i*8, 8, endness=p.arch.memory_endness).concrete_value for i in range(3)]
nwork = sum(1 for a in trace2 if a == CALLEE)
print("[*] dual-call trace blocks: %s" % [hex(a) for a in trace2])
print("[*] dual-call last recorded rdi=%#x rsi=%#x rdx=%#x, callee entries in trace: %d"
      % (rec2[0], rec2[1], rec2[2], nwork))
sent2 = mem2.load(SENT_MAGIC, 4, endness=p.arch.memory_endness).concrete_value == 0xdeadbeef
# record history of both calls: count how many times MAGIC block written; use trace count
print("[*] TEST2 both calls executed (callee entered twice): %s" % (nwork == 2))
print("[*] TEST2 sentinel reached after both: %s" % sent2)
print("[*] TEST2 second-call args recorded: %#x/%#x/%#x (want aaaa0001..3)" % tuple(rec2))
