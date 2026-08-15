/*
 * vuln_client.c — SYNTHETIC demo target for "single-socket reverse staging".
 *
 * This is ORIGINAL educational code. It reimplements a *publicly documented*
 * class of exploitation technique: a network client that TRUSTS its server and
 * copies a server-supplied length into a fixed stack buffer without a bounds
 * check -> a "reverse" (malicious-server -> client) stack overflow -> RCE.
 *
 * It contains NO third-party or proprietary code and is not derived from, nor a
 * description of, any specific product. Any resemblance to a real binary's
 * gadget addresses, protocol framing, or symbol names is deliberately avoided.
 * See the folder README for the responsible-disclosure rationale.
 *
 * Intentional bug:
 *   read_server_blob() recv()s a server-controlled length into char buf[2016]
 *   with NO `len <= sizeof(buf)` check.
 *
 * Build (see Makefile) as:  No PIE / No stack canary / NX on / Partial RELRO
 * to mirror a legacy, hardening-free binary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* --------------------------------------------------------------------------
 * Writable landing zone for the received stage-2 chain.
 * A real, initialized global => guaranteed mapped & writable at a FIXED address
 * (this binary is non-PIE). The exploit pivots the stack in here, and leaves
 * room BELOW the pivot for system()'s own frame. This deliberately sidesteps
 * the "landing page not mapped / no room for system frame" foot-guns that make
 * real-world versions of this fiddly.
 * -------------------------------------------------------------------------- */
char stage2_land[0x2000] __attribute__((used)) = { 1 };

/* --------------------------------------------------------------------------
 * PLANTED gadgets (module-level asm, so the exact bytes are guaranteed
 * regardless of compiler/glibc version).
 *
 * Why plant them?  send()/recv() take flags in %rcx (4th arg). A pure-ROP
 * caller must zero %rcx, but a clean `pop rcx ; ret` is often absent, and on
 * modern glibc (>= 2.34) __libc_csu_init is gone, so the classic pop rdi/rsi
 * gadgets may not exist either. Real targets contain equivalent sequences
 * INCIDENTALLY (e.g. a `mov ecx,0 ; call send` inside some send wrapper). We
 * plant labeled equivalents so the *technique* is reproducible against THIS
 * binary without shipping anyone's proprietary code. The writeup covers how the
 * same primitives are recovered from an unmodified target (ret2csu for %rdx,
 * incidental `mov ecx,0 ; call send/recv` sites, etc.).
 * -------------------------------------------------------------------------- */
__asm__(
    ".text\n"
    ".globl g_pop_rdi\n" "g_pop_rdi: pop %rdi; ret\n"
    ".globl g_pop_rsi\n" "g_pop_rsi: pop %rsi; ret\n"
    ".globl g_pop_rdx\n" "g_pop_rdx: pop %rdx; ret\n"
    ".globl g_pop_rsp\n" "g_pop_rsp: pop %rsp; ret\n"
    ".globl g_ret\n"     "g_ret:     ret\n"
    /* send(rdi, rsi, rdx, rcx=0) : the "SEND_ZERO" flags=0 call site */
    ".globl g_send0\n"   "g_send0:   xor %ecx, %ecx; jmp send@plt\n"
    /* recv(rdi, rsi, rdx, rcx=0) : the "RECV_ZERO" flags=0 call site */
    ".globl g_recv0\n"   "g_recv0:   xor %ecx, %ecx; jmp recv@plt\n"
);

static long recv_all(int fd, void *buf, unsigned long n) {
    unsigned long got = 0;
    char *p = (char *)buf;
    while (got < n) {
        long r = recv(fd, p + got, n - got, 0);
        if (r <= 0) break;
        got += (unsigned long)r;
    }
    return (long)got;
}

/* Benign length-prefixed send: [4B big-endian len][payload]. */
static void send_msg(int fd, const char *s) {
    unsigned int n = (unsigned int)strlen(s);
    unsigned char h[4] = {
        (unsigned char)(n >> 24), (unsigned char)(n >> 16),
        (unsigned char)(n >> 8),  (unsigned char)n
    };
    send(fd, h, 4, 0);
    send(fd, s, n, 0);
}

/* *** The vulnerable routine: it trusts the server-supplied length. *** */
static void read_server_blob(int fd) {
    char buf[2016];
    unsigned char hdr[8];
    if (recv_all(fd, hdr, 8) != 8) return;
    /* 8-byte response header: [4B big-endian length][4B reserved] */
    unsigned int len = ((unsigned int)hdr[0] << 24) | ((unsigned int)hdr[1] << 16)
                     | ((unsigned int)hdr[2] << 8)  | ((unsigned int)hdr[3]);
    /* BUG: no `len <= sizeof(buf)` check before filling the stack buffer. */
    recv_all(fd, buf, len);
    printf("[client] processed %u-byte response\n", len);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 13337;

    int fd = socket(AF_INET, SOCK_STREAM, 0);   /* first socket() -> fd 3 */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        perror("connect");
        return 1;
    }

    /* tiny handshake, so send@got / recv@got are resolved before the overflow */
    send_msg(fd, "HELLO");
    char tmp[64];
    recv(fd, tmp, sizeof tmp, 0);       /* server ack */

    read_server_blob(fd);               /* <-- overflow happens here */
    return 0;
}
