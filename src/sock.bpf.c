#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sock.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");

/*
ERROR:
libbpf: Error in bpf_create_map_xattr(trie_map):Invalid argument(-22). Retrying without BTF.
libbpf: map 'trie_map': failed to create: Invalid argument(-22)

struct
{
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb4_src_range_key);
	__type(value, long);
	__uint(max_entries, 256);
} trie_map SEC(".maps");
*/

struct
{
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 8);
	__uint(value_size, 8);
	__uint(max_entries, 50);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} trie_map SEC(".maps");

static int __always_inline _lpm_lookup()
{
	union
	{
		u32 b32[2];
		u8 b8[8];
	} key;
	u64 *value;

	key.b32[0] = 32;
	key.b8[4] = 192;
	key.b8[5] = 168;
	key.b8[6] = 0;
	key.b8[7] = 1;

	value = bpf_map_lookup_elem(&trie_map, &key);
	if (value)
	{
		bpf_printk("found value in trie map: %d\n", *value);
	}
	else
	{
		bpf_printk("value not in trie map\n");
	}
	return 0;
}

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	long *value;
	u8 prot;
	u32 key;

	// ERROR: load_byte from example (in bpf_legacy.h)
	// int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	// bpf_printk("index (prot:%d)\n", index);

	// ERROR: “socket filter”, and that such programs are not allowed to do direct packet access..
	// trying to get data, data_end is not valid in "socket filter" typed ebpf.
	// Use bpf_skb_load_bytes/bpf_skb_store_bytes instead
	// See: https://stackoverflow.com/questions/61702223/bpf-verifier-rejects-code-invalid-bpf-context-access
	//
	// bpf_printk("remote:%d, local:%d\n", skb->remote_ip4, skb->local_ip4);

	bpf_printk("skb->protocol :%d\n", skb->protocol);

	if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &prot, sizeof(prot)))
	{
		bpf_printk("failed to load_bytes!\n");
		return 0;
	}
	bpf_printk("iphdr->protocol: %d\n", prot);

	// skb->pkt_type is the first field
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	// Directly updating values in the map
	key = prot;
	value = bpf_map_lookup_elem(&my_map, &key);
	if (value)
	{
		bpf_printk("found value in map %d\n", key);
		__sync_fetch_and_add(value, skb->len); // skb->len works..

		// No need to update
		// bpf_map_update_elem(&my_map, &skb->protocol, &value, 0);
	}

	_lpm_lookup();

	return 0;
}
