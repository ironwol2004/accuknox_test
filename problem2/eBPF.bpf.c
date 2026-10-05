//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define PROCESS_NAME_LEN 16

struct process_port_config {
	__u32 port;
	char process_name[PROCESS_NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_port_config);
} cfg_map SEC(".maps");

static __always_inline int allow_connection(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct process_port_config *config;
	char current_name[PROCESS_NAME_LEN] = {};
	int is_target_process = 1;

	config = bpf_map_lookup_elem(&cfg_map, &zero);
	if (!config) {
		bpf_printk("cg: allow (cfg_map lookup failed)\n");
		return 1;
	}
	if (bpf_get_current_comm(current_name, sizeof(current_name)) < 0) {
		bpf_printk("cg: allow (get_current_comm failed)\n");
		return 1;
	}

#pragma unroll
	for (int i = 0; i < PROCESS_NAME_LEN; i++) {
		if (current_name[i] != config->process_name[i])
			is_target_process = 0;
	}

	/* Other processes are unaffected; the selected process is port-limited. */
	if (!is_target_process) {
		bpf_printk("cg: allow (comm=%02x%02x%02x%02x not target)\n",
			  current_name[0], current_name[1], current_name[2], current_name[3]);
		return 1;
	}

	if (bpf_ntohs((__u16)ctx->user_port) == config->port) {
		bpf_printk("cg: ALLOW target on configured port %d\n", config->port);
		return 1;
	}

	bpf_printk("cg: DENY target on port %d (only %d allowed)\n",
		  bpf_ntohs((__u16)ctx->user_port), config->port);
	return 0;
}

SEC("cgroup/connect4")
int allow_port_for_proc4(struct bpf_sock_addr *ctx)
{
	return allow_connection(ctx);
}

SEC("cgroup/connect6")
int allow_port_for_proc6(struct bpf_sock_addr *ctx)
{
	return allow_connection(ctx);
}

char LICENSE[] SEC("license") = "GPL";