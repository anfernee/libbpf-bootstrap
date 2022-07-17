// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare

#include <errno.h>
#include <stdbool.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

SEC("sk_skb/stream_parser")
int prog_stream_parser(struct __sk_buff *skb)
{
	bpf_printk("strparser\n");
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int prog_stream_verdict(struct __sk_buff *skb)
{
	__u32 zero = 0;
	bpf_printk("stream verdict\n");
	return bpf_sk_redirect_map(skb, &sock_map, zero, 0);
}

char _license[] SEC("license") = "GPL";
