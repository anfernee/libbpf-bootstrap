#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// htons
#include <arpa/inet.h>

// sockaddr_ll PF_PACKET
// #include <sys/type.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

// if_nametoindex
#include <net/if.h>

#include "sock.skel.h"

static inline int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0)
    {
        printf("cannot create raw socket\n");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        printf("bind to %s: %s\n", name, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int insert_trie_map(struct sock_bpf *skel)
{
    int err;

    union
    {
        uint32_t b32[2];
        uint8_t b8[8];
    } key;
    key.b32[0] = 24;
    key.b8[4] = 192;
    key.b8[5] = 168;
    key.b8[6] = 0;
    key.b8[7] = 0;
    uint64_t value = 11111;

    err = bpf_map_update_elem(bpf_map__fd(skel->maps.trie_map), &key, &value, 0);
    if (err)
    {
        fprintf(stderr, "Failed to update map trie_map!\n");
        return err;
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    struct sock_bpf *skel;
    int err;
    int sock;
    int prog_fd;

    skel = sock_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton!\n");
        return 1;
    }

    err = sock_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton!\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.bpf_prog1);
    printf("bpf program fd is %d\n", prog_fd);

    err = sock_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton!\n");
        goto cleanup;
    }

    sock = open_raw_sock("wlp4s0");
    if (!sock)
    {
        fprintf(stderr, "Failed to open raw socket");
        goto cleanup;
    }

    err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (err)
    {
        fprintf(stderr, "Failed to setsockopt (%d, %s)\n", errno, strerror(errno));
        goto cleanup;
    }

    if (insert_trie_map(skel))
        goto cleanup;

    printf("hello, world.\n");

    while (true)
    {
        sleep(1);
        printf("still running ...\n");
    }

    return 0;

cleanup:
    sock_bpf__destroy(skel);
    return 1;
}
