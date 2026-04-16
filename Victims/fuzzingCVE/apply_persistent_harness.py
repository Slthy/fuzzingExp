#!/usr/bin/env python3
from pathlib import Path
import re
import sys

HARNESS_BLOCK = r'''
#include <sched.h>
#include <linux/sched.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>

static void netIfaceUp(const char *ifacename)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock == -1) {
        perror("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
        _exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, '\0', sizeof(ifr));
    snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifacename);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl(iface='lo', SIOCGIFFLAGS, IFF_UP)");
        _exit(1);
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl(iface='lo', SIOCSIFFLAGS, IFF_UP)");
        _exit(1);
    }

    close(sock);
}

void unsh(void)
{
    unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS);

    if (mount("tmpfs", "/tmp", "tmpfs", 0, "") == -1) {
        perror("tmpfs");
        _exit(1);
    }
    netIfaceUp("lo");
}

static void *GETDATA(void *arg)
{
    (void)arg;
    int BUFSIZE=1024*1024;
    usleep(10000);
    char buf[BUFSIZE+1];
    while (__AFL_LOOP(10000)) {
        memset(buf, 0, BUFSIZE);
        ssize_t read_bytes = read(0, buf, BUFSIZE - 3);
        if (read_bytes <= 0) {
            continue;
        }
        buf[read_bytes] = '\r';
        buf[read_bytes + 1] = '\n';
        buf[read_bytes + 2] = '\0';

        int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (sockfd == -1) {
            perror("socket");
            _exit(1);
        }

        int sz = (1024 * 1024);
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == -1) {
            perror("setsockopt");
            close(sockfd);
            continue;
        }

        struct sockaddr_in saddr;
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(80);
        saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
            perror("connect");
            close(sockfd);
            continue;
        }

        if (send(sockfd, buf, (size_t)read_bytes + 2, MSG_NOSIGNAL) != (ssize_t)((size_t)read_bytes + 2)) {
            perror("send() failed 1");
            close(sockfd);
            continue;
        }

        if (shutdown(sockfd, SHUT_WR) == -1) {
            perror("shutdown");
            close(sockfd);
            continue;
        }

        char b[1024 * 1024];
        while (recv(sockfd, b, sizeof(b), 0) > 0) ;

        close(sockfd);
    }
    usleep(100000);
    _exit(0);
}

static void LAUNCHTHR(void)
{
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024 * 8);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&t, &attr, GETDATA, NULL);
}

int main(int argc, const char *const argv[])
{
    if (getenv("NO_FUZZ") == NULL) {
        unsh();
        LAUNCHTHR();
    }
'''


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: apply_persistent_harness.py <path-to-server/main.c>", file=sys.stderr)
        return 2

    main_c = Path(sys.argv[1])
    if not main_c.exists():
        print(f"error: file not found: {main_c}", file=sys.stderr)
        return 1

    src = main_c.read_text()

    if "static void *GETDATA(void *arg)" in src:
        print("already patched: GETDATA hook exists")
        return 0

    main_sig_pattern = r"int\s+main\s*\(\s*int\s+argc\s*,\s*const\s+char\s*\*\s*const\s+argv\[\]\s*\)\s*\{"
    if not re.search(main_sig_pattern, src):
        print("error: could not find expected int main signature", file=sys.stderr)
        return 1

    src = re.sub(main_sig_pattern, HARNESS_BLOCK.strip(), src, count=1)

    src = src.replace("    process_rec *process;\n", "", 1)

    src = src.replace(
        "    if (rv != OK) {\n        destroy_and_exit_process(process, 1);\n    }\n",
        "    if (rv != OK) {\n        printf(\"[-] Config failed...\\n\");\n        destroy_and_exit_process(process, 1);\n    }\n",
        1,
    )

    src = src.replace(
        "        if (signal_server(&exit_status, pconf) != 0) {\n            destroy_and_exit_process(process, exit_status);\n        }\n",
        "        if (signal_server(&exit_status, pconf) != 0) {\n            printf(\"[-] Server signaled out\\n\");\n            destroy_and_exit_process(process, exit_status);\n        }\n",
        1,
    )

    backup = main_c.with_suffix(main_c.suffix + ".orig")
    backup.write_text(main_c.read_text())
    main_c.write_text(src)
    print(f"patched {main_c}")
    print(f"backup saved to {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
