# Linux-Reverse-Socket-Stagers

Functional, self-contained demos of **socket-reuse staging for the "reverse"
direction** — a *malicious/MITM server* corrupting the memory of a *client that
dials out and trusts it*, and driving the whole leak-and-stage-2 flow over the
**one connection that is already open**.

Think of it as the Linux / ret2libc cousin of Borja Merino's
[**Windows-One-Way-Stagers**](https://github.com/BorjaMerino/Windows-One-Way-Stagers):
same core idea — *don't open a new socket, reuse the one you have* — but applied
to server→client memory corruption on non-PIE Linux binaries, where the same
socket carries both the info-leak (outbound) and the second stage (inbound).

> ### ⚠️ Scope & responsible use
> Every target in this repo is **synthetic**: original C written for teaching,
> built to be intentionally vulnerable. There is **no third-party or proprietary
> code**, no real product's binary, no real gadget addresses or protocol. The
> techniques themselves are long-published (see [`references.md`](references.md));
> what's here is a clean, reproducible re-implementation for defenders and
> learners. Use it only against the included lab. See each folder for details.

---

## Why "reverse" and why "one socket"

Most memory-corruption RCE you read about is **client → server** (you connect in
and overflow the listener) or **file → parser** (a booby-trapped media/document).
The under-discussed third shape is **server → client**: the victim is the one who
*connects out* and trusts the response — a legacy update client, a game client, a
payment/licensing SDK, an RDP/VNC client. Content-controlled length fields in
those response parsers turn into stack/heap overflows on the *client*. Check
Point named and popularized this as the
[**Reverse RDP Attack**](https://research.checkpoint.com/2019/reverse-rdp-attack-code-execution-on-rdp-clients/).

Two properties make the exploitation shape distinct from the classic
`ropasaurusrex` server pwn:

1. **You already have exactly one socket** — the connection the victim opened to
   you. It's the natural (and often only) channel both to *exfiltrate a leak* and
   to *deliver stage-2*. That's the "one-way stager" instinct, run in two ways.
2. **A one-shot client re-randomizes ASLR every run.** There is no "leak in
   request A, pwn in request B" — a leak from one process is useless to the next.
   So the leak and the second stage must live **in a single connection, in a
   single ROP chain**, with the chain's own `recv` gadget blocking mid-flight to
   pull stage-2 back over the same socket.

Neither property is novel on its own — this repo is about seeing them **composed
cleanly**, end to end, in something you can build and run.

---

## Techniques

| # | technique | what it shows |
|---|---|---|
| [**01**](01-single-socket-reverse-stager/) | **Single-Socket Reverse Staging** | non-PIE ret2libc where `send(fd, got, 8)` leaks libc over the connected socket and `recv(fd, bss, n)` pulls stage-2 back — all in one chain — then `pop rsp` pivots into it. Full-ASLR `uid=0`. |
| _(planned)_ | ret2dlresolve without a socket round-trip | leak-free stage-2 on non-PIE + Partial RELRO |
| _(planned)_ | PIE as the real boundary | the same bug degraded to remote DoS once PIE is on |

Each folder is standalone: source, build, a one-click `run.sh`, and a writeup.

---

## Quick start

```bash
git clone https://github.com/windshock/Linux-Reverse-Socket-Stagers
cd Linux-Reverse-Socket-Stagers/01-single-socket-reverse-stager
# Apple Silicon: colima start --arch x86_64
./run.sh
```

Runs an isolated x86_64 container, toggles **full ASLR**, and demonstrates
`uid=0` from a single malicious response.

---

## Writeups

The narrative walkthrough (how this connects `ropasaurusrex`, one-way stagers,
and the reverse-RDP direction — and why *PIE*, not ASLR/canary, is the real
boundary) is on the blog:

- 🇰🇷 <https://windshock.github.io/ko/post/2026-08-15-reverse-single-socket-staging/>
- 🇬🇧 <https://windshock.github.io/en/post/2026-08-15-reverse-single-socket-staging/>

## References

Consolidated in [`references.md`](references.md) — CWE/CAPEC mappings, the
staged-leak lineage, the reverse-client-attack class, and socket-reuse stagers.

## License

MIT — see [`LICENSE`](LICENSE). Educational use against the bundled lab only.
