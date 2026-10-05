//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} port_config_map SEC(".maps");

SEC("xdp")
int xdp_drop_port(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u32 zero = 0;
	__u32 *blocked_port;
	__u16 dest;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bpf_printk("xdp: pass (not IPv4)\n");
		return XDP_PASS;
	}

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != IPPROTO_TCP) {
		bpf_printk("xdp: pass (not TCP/short)\n");
		return XDP_PASS;
	}

	tcp = (void *)ip + ip->ihl * 4;
	if ((void *)(tcp + 1) > data_end) {
		bpf_printk("xdp: pass (truncated TCP header)\n");
		return XDP_PASS;
	}

	blocked_port = bpf_map_lookup_elem(&port_config_map, &zero);
	if (!blocked_port) {
		bpf_printk("xdp: pass (map lookup failed)\n");
		return XDP_PASS;
	}

	dest = bpf_ntohs(tcp->dest);
	if (dest != *blocked_port) {
		bpf_printk("xdp: pass (dport=%d not blocked=%d)\n", dest, *blocked_port);
		return XDP_PASS;
	}

	bpf_printk("xdp: DROP dport=%d matches blocked port\n", dest);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";