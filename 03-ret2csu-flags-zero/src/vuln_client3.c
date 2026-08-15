/*
 * vuln_client3.c — SYNTHETIC demo of the "ret2csu + flags=0" wrinkle.
 *
 * ORIGINAL educational code, vendor-neutral. It models the two obstacles you hit
 * when the leak/stage-2 primitive must call send()/recv() by ROP on a target
 * with a sparse gadget set:
 *
 *   1. send()/recv() take flags in %rcx (4th arg). There is often no clean
 *      `pop rcx`. Real code contains the fix incidentally: a wrapper that calls
 *      send(fd,buf,n, 0). We expose that as net_send()/net_recv() — a proper
 *      function whose body carries the flags=0. We reach it THROUGH a fixed
 *      function-pointer table, exactly the way __libc_csu_init calls init_array
 *      entries.
 *
 *   2. There is no `pop rdx` here, so %rdx (the length) is set with **ret2csu**:
 *      __libc_csu_init's `mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ;
 *      call [r12+rbx*8]` gadget. (This is why the lab builds on glibc 2.31 —
 *      glibc >= 2.34 removed __libc_csu_init.)
 *
 * The "boring" gadgets (pop rdi / pop rsp / ret) used for the final stage-2 are
 * planted, as in 01/02, to keep the focus on ret2csu + the flags=0 call path.
 *
 * Build: No PIE / No canary / no CET / Partial RELRO (see Makefile).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

char stage2_land[0x2000] __attribute__((used)) = { 1 };

/* Real wrappers: the flags=0 lives inside a proper function frame. Reached via
 * ret2csu's `call [r12+rbx*8]` through the pointer table below. */
ssize_t net_send(int fd, const void *buf, size_t n) { return send(fd, buf, n, 0); }
ssize_t net_recv(int fd, void *buf, size_t n)       { return recv(fd, buf, n, 0); }

/* Fixed-address pointer table (non-PIE). csu selects the entry with rbx:
 * rbx=0 -> net_send, rbx=1 -> net_recv. Mirrors __libc_csu_init/init_array. */
void *const fnptr[2] __attribute__((used)) = { (void *)net_send, (void *)net_recv };

/* Boring planted gadgets for the final stage-2 (pivot + set rdi + align). */
__asm__(
    ".text\n"
    ".globl g_pop_rdi\n" "g_pop_rdi: pop %rdi; ret\n"
    ".globl g_pop_rsp\n" "g_pop_rsp: pop %rsp; ret\n"
    ".globl g_ret\n"     "g_ret:     ret\n"
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

static void read_server_blob(int fd) {
    char buf[2016];
    unsigned char hdr[8];
    if (recv_all(fd, hdr, 8) != 8) return;
    unsigned int len = ((unsigned)hdr[0]<<24)|((unsigned)hdr[1]<<16)|((unsigned)hdr[2]<<8)|hdr[3];
    recv_all(fd, buf, len);      /* server-controlled length -> stack overflow */
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
