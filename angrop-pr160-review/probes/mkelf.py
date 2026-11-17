# Build a minimal synthetic ELF64 (non-PIE, static, no libs) with:
#   0x401000 loader:   pop rbx;rbp;r12;r13;r14;r15; ret
#   0x401010 thunk_jmp: mov rdx,r14; mov rsi,r13; mov edi,r12d; JMP [r15+rbx*8]   (non-csu shape!)
#   0x40101e thunk_call: same moves; CALL [r15+rbx*8]
#   0x40102c custom epilogue: add rsp,8; pop rbx; pop rbp; ret   <-- 3 slots, NOT 7
#   0x401036 fn: ret
#   0x401037 fn2: (used as sentinel target) ret
#   0x401038 _start: exit syscall
#   0x402000 data: table[2] = {fn, fn}
import struct

TEXT = 0x401000
code = bytearray()
def emit(addr, *bs):
    assert addr - TEXT == len(code)
    for b in bs: code.extend(b)
def ins(hexstr): return bytes.fromhex(hexstr.replace(' ', ''))

emit(0x401000, ins('5b') + ins('5d') + ins('41 5c') + ins('41 5d') + ins('41 5e') + ins('41 5f') + ins('c3'))
emit(0x40100b, ins('90')*5)  # pad
emit(0x401010, ins('4c 89 f2') + ins('4c 89 ee') + ins('44 89 e7') + ins('41 ff 24 df'))
emit(0x40101d, ins('90'))  # pad to 0x40101e
emit(0x40101e, ins('4c 89 f2') + ins('4c 89 ee') + ins('44 89 e7') + ins('41 ff 14 df'))
emit(0x40102b, ins('90'))  # pad to 0x40102c
emit(0x40102c, ins('48 83 c4 08') + ins('5b') + ins('5d') + ins('c3'))
emit(0x401033, ins('c3'))                      # fn: plain ret
emit(0x401034, ins('f4'))                      # hlt (pad)
emit(0x401035, ins('f4'))
emit(0x401036, ins('b8 3c 00 00 00') + ins('31 ff') + ins('0f 05'))  # _start: exit(0)

DATA = 0x402000
data = struct.pack('<QQ', 0x401033, 0x401033)

ehsize, phsize = 64, 56
text_off = 0x1000
data_off = 0x2000
filesz_text = len(code)
ehdr = struct.pack('<16sHHIQQQIHHHHHH',
    b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8,
    2, 0x3e, 1, 0x401036, ehsize, 0, 0,
    ehsize, phsize, 2, 64, 0, 0)
def phdr(t, off, vaddr, filesz, memsz, flags):
    return struct.pack('<IIQQQQQQ', t, flags, off, vaddr, vaddr, filesz, memsz, 0x1000)
phdrs = phdr(1, text_off, TEXT, filesz_text, filesz_text, 5) \
      + phdr(1, data_off, DATA, len(data), len(data), 6)
out = bytearray(ehdr) + bytearray(phdr_size := phsize*1)  # 1 phdr each; 2 phdrs total
out = bytearray(ehdr)
out += phdrs
out += b'\x00' * (text_off - len(out))
out += code
out += b'\x00' * (data_off - len(out))
out += data
open('probes/fp_synth', 'wb').write(bytes(out))
print("wrote probes/fp_synth: text %#x..%#x data %#x" % (TEXT, TEXT+filesz_text, DATA))
