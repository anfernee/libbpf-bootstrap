
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
// #include "vmlinux.h"

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_LEGACY__
#define __BPF_LEGACY__

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

#endif


char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("socket")
int bpf_prog(struct __sk_buff *skb)
{
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  bpf_printk("protocol %d\n", proto);

  return 0;
}