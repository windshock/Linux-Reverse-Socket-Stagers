/*
 * vuln_client2.c — SYNTHETIC demo of the "front-load / source-hijack" trick.
 *
 * ORIGINAL educational code, vendor-neutral. It models a real-world wrinkle:
 * sometimes you CANNOT put your ROP chain at the classic return offset, because
 * the vulnerable routine's *output path* copies the FRONT of the received
 * response over the saved return address. Whatever sits at response[0] becomes
 * RIP. The fix is to "front-load": place the chain at payload offset 0.
 *
 * Here read_server_blob():
 *   1. recv()s the response body into buf[] (attacker keeps it short — it does
 *      NOT reach the return address by itself),
 *   2. then an "output formatter" memcpy()s the FRONT of that body over the
 *      saved return slot ([rbp+8]) with a server-controlled slot count.
 *
 * => The only thing that controls RIP is response[0..]. A chain placed at the
 *    classic offset never runs (the formatter overwrites RIP with the padding);
 *    a chain placed at offset 0 runs. That's front-load.
 *
 * Build: No PIE / No canary / no CET / Partial RELRO (see Makefile).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

char stage2_land[0x2000] __attribute__((used)) = { 1 };

/* Same planted gadgets as technique 01 (see its notes on why we plant them). */
__asm__(
    ".text\n"
    ".globl g_pop_rdi\n" "g_pop_rdi: pop %rdi; ret\n"
    ".globl g_pop_rsi\n" "g_pop_rsi: pop %rsi; ret\n"
    ".globl g_pop_rdx\n" "g_pop_rdx: pop %rdx; ret\n"
    ".globl g_pop_rsp\n" "g_pop_rsp: pop %rsp; ret\n"
    ".globl g_ret\n"     "g_ret:     ret\n"
    ".globl g_send0\n"   "g_send0:   xor %ecx, %ecx; jmp send@plt\n"
    ".globl g_recv0\n"   "g_recv0:   xor %ecx, %ecx; jmp recv@plt\n"
);

static long recv_all(int fd, void *buf, unsigned long n) {
    unsigned long got = 0; char *p = (char *)buf;
    while (got < n) {
        long r = recv(fd, p + got, n - got, 0);
        if (r <= 0) break;
        got += (unsigned long)r;
    }
    return (long)got;
}

static void send_msg(int fd, const char *s) {
    unsigned int n = (unsigned int)strlen(s);
    unsigned char h[4] = { (unsigned char)(n>>24),(unsigned char)(n>>16),
                           (unsigned char)(n>>8),(unsigned char)n };
    send(fd, h, 4, 0); send(fd, s, n, 0);
}

/* *** vulnerable: the output formatter source-hijacks the return address. *** */
static void read_server_blob(int fd) {
    char buf[2016];
    unsigned char hdr[8];
    if (recv_all(fd, hdr, 8) != 8) return;
    /* header: [4B big-endian body length][4B big-endian "front" slot count] */
    unsigned int len   = ((unsigned)hdr[0]<<24)|((unsigned)hdr[1]<<16)|((unsigned)hdr[2]<<8)|hdr[3];
    unsigned int front = ((unsigned)hdr[4]<<24)|((unsigned)hdr[5]<<16)|((unsigned)hdr[6]<<8)|hdr[7];
    recv_all(fd, buf, len);                 /* len kept short: no direct RIP overwrite */

    /* "output formatting": copy the FRONT of the response over the saved return
     * address. [rbp+8] is the saved RIP; whatever is at buf[0..] becomes the
     * return address (and the slots above it). This is the source-hijack. */
    void *rbp = __builtin_frame_address(0);
    memcpy((char *)rbp + 8, buf, (size_t)front * 8);
    printf("[client] formatted %u slots\n", front);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 13337;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { perror("connect"); return 1; }
    send_msg(fd, "HELLO");
    char tmp[64]; recv(fd, tmp, sizeof tmp, 0);
    read_server_blob(fd);
    return 0;
}
