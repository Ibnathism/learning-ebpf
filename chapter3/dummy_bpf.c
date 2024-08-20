#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int dummy_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
