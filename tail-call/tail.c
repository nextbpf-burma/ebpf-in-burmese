#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} prog_array SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp")
int main_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (data + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_ABORTED;

    int dport = bpf_ntohs(tcph->dest);

    if (dport == 8080) {
        int key = 0;
        bpf_tail_call(ctx, &prog_array, key);
    } else if (dport == 22) {
        int key = 1;
        bpf_tail_call(ctx, &prog_array, key);
    }

    return XDP_PASS;
}

SEC("xdp")
int port8080_prog(struct xdp_md *ctx)
{
    bpf_printk("Packet to port 8080 processed\n");
    return XDP_PASS;
}

SEC("xdp")
int port22_prog(struct xdp_md *ctx)
{
    bpf_printk("Packet to port 22 processed\n");
    return XDP_PASS;
}
