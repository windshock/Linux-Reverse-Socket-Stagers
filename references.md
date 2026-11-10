# References

Everything in this repo is a composition of long-published ideas. Grouped by the
part of the technique they cover.

## Socket-reuse / one-way stagers (the direct inspiration)

- Borja Merino — **Windows-One-Way-Stagers** (socket reuse/rebind, OOB & timeout
  based fd discovery): <https://github.com/BorjaMerino/Windows-One-Way-Stagers>
- Reusing an already-connected socket for the stager instead of opening a new
  connection is the core idea, adapted here to a two-way (leak + stage-2) form.

## Staged GOT-leak → ret2libc over a socket (the exploitation skeleton)

- HackTricks — **Leaking libc address with ROP** (the canonical staged template:
  `puts/write(GOT)` leak → resolve libc → second-stage `system`):
  <https://book.hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address/index.html>
- `ropasaurusrex` (PlaidCTF 2013) — the archetypal `write(fd, GOT, len)` leak +
  return-to-vuln + stage-2 ret2libc. A representative modern write-up of the same
  `write(fd, GOT, len)` pattern:
  <https://github.com/jakecraige/ctf/blob/master/csaw-quals-2020/roppity/writeup.md>
- ROP Emporium — **ret2csu** (controlling `%rdx` with no `pop rdx`) and **pivot**
  (`pop rsp` stack pivoting): <https://ropemporium.com/>
- pwntools ROP docs: <https://docs.pwntools.com/en/stable/rop/rop.html>

## Automated ROP chain construction

- angr — [`angrop`](https://github.com/angr/angrop), the upstream gadget finder
  and ROP chain generator used for the lab3 integration experiment.
- Upstream integration PR: [`angr/angrop#160`](https://github.com/angr/angrop/pull/160),
  adding an explicit `ret2csu()` helper for indirect `__libc_csu_init` calls.
- Prototype reference: [`sefcom/ropbot#1`](https://github.com/sefcom/ropbot/pull/1).
- The helper-backed lab3 path is selected with `ROPBOT=1`; the manual path
  remains the default because angr is a heavyweight analysis dependency.

## Malicious server → connecting client (the "reverse" direction)

- Check Point Research — **Reverse RDP Attack: Code Execution on RDP Clients**
  (2019): <https://research.checkpoint.com/2019/reverse-rdp-attack-code-execution-on-rdp-clients/>
- BleepingComputer coverage of the RDP-client class:
  <https://www.bleepingcomputer.com/news/security/rdp-clients-exposed-to-reverse-rdp-attacks-by-major-protocol-issues/>
- The recurring shape — *a server-controlled size field + missing bounds check in
  the client's copy routine* — keeps producing client RCEs (e.g. FreeRDP
  `CVE-2018-8787` integer→heap overflow, and later clipboard-channel overflows).

## Weakness & attack-pattern taxonomy

**CWE** (the weakness class — all pre-existing; nothing here warrants a new one):

- [CWE-130 — Improper Handling of Length Parameter Inconsistency](https://cwe.mitre.org/data/definitions/130.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-805 — Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html)
- [CWE-121 — Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-119 — Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

**CAPEC** (the attack pattern — also pre-existing; cite the chain, don't invent):

- Delivery: [CAPEC-94 — Adversary in the Middle](https://capec.mitre.org/data/definitions/94.html) ·
  [CAPEC-384 — Application API Message Manipulation via MitM](https://capec.mitre.org/data/definitions/384.html) ·
  [CAPEC-194 — Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html) ·
  [CAPEC-148 — Content Spoofing](https://capec.mitre.org/data/definitions/148.html)
- Exploitation: [CAPEC-100 — Overflow Buffers](https://capec.mitre.org/data/definitions/100.html) ·
  [CAPEC-8 — Buffer Overflow in an API Call](https://capec.mitre.org/data/definitions/8.html) ·
  [CAPEC-9 — Buffer Overflow in Local Command-Line Utilities](https://capec.mitre.org/data/definitions/9.html)
