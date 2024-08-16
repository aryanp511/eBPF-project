#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __be32);
    __type(value, unsigned char[ETH_ALEN]);
} ip_mac_map SEC(".maps");

SEC("xdp")
int xdp_ip_mac_binding(struct xdp_md *ctx)
{
    bpf_printk("XDP program started\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    bpf_printk("Ethernet header parsed\n");

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    bpf_printk("IP header parsed\n");

    unsigned char *mac = bpf_map_lookup_elem(&ip_mac_map, &ip->saddr);
    if (mac && __builtin_memcmp(mac, eth->h_source, ETH_ALEN) == 0) {
        bpf_printk("MAC matched\n");
        return XDP_PASS;
    } else {
        bpf_printk("MAC not matched\n");
        return XDP_DROP;
    }
}

char _license[] SEC("license") = "GPL";