/*
 * XDP program to redirect packets to AF_XDP socket
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

/* XSK map for AF_XDP sockets */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* Statistics map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 key = 0;
    __u64 *count;

    /* Update packet count */
    count = bpf_map_lookup_elem(&stats_map, &key);
    if (count)
        (*count)++;

    /* Redirect to AF_XDP socket if available */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
