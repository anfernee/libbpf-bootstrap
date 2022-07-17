#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SERV4_DPORT 8000
#define SERV4_REWRITE_PORT 3000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("cgroup/bind4")
int bind_v4_prog(struct bpf_sock_addr *ctx) {
  bpf_printk("bind IP:PORT %d:%d\n", ctx->user_ip4, bpf_ntohs(ctx->user_port));
  if (ctx->user_port == bpf_htons(SERV4_DPORT)) {
    ctx->user_port = bpf_htons(SERV4_REWRITE_PORT);
    return 1;
  }
  return 1;
}