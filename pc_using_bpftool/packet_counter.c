#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/types.h>

struct packet_info_t {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 length;
    __u8 tcp_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} packet_events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int count_packets(struct pt_regs *ctx, struct sock *sk) {
    struct packet_info_t pkt = {};
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    pkt.pid = bpf_get_current_pid_tgid() >> 32;
    pkt.saddr = inet->inet_saddr;
    pkt.daddr = inet->inet_daddr;
    pkt.sport = inet->inet_sport;
    pkt.dport = inet->inet_dport;
    pkt.length = sk->sk_wmem_queued;

    // Get the TCP header
    struct tcphdr *tcp = (struct tcphdr *)(sk->sk_send_head->data);
    bpf_probe_read_kernel(&pkt.tcp_flags, sizeof(pkt.tcp_flags), &tcp->ack_seq);

    bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));
    return 0;
}

char _license[] SEC("license") = "GPL";
