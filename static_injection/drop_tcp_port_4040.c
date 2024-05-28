// drop_tcp_port_4040.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include<netinet/in.h>

SEC("xdp")
int drop_tcp_4040(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // Check if packet is long enough to contain Ethernet, IP, and TCP headers
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (void *)ip + sizeof(*ip);

    // Check if packet is long enough to contain TCP header
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Drop packets destined to port 4040
    if (tcp->dest == htons(4040))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
