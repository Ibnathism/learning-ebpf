from bcc import BPF
import socket
import time
from datetime import datetime
import ctypes as ct

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/ip.h>

struct packet_info_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 length;
    u8 tcp_flags;
};

BPF_PERF_OUTPUT(packet_events);

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


    packet_events.perf_submit(ctx, &pkt, sizeof(pkt));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="tcp_sendmsg", fn_name="count_packets")

# Define output data structure in Python
class PacketInfo(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("length", ct.c_uint),
        ("tcp_flags", ct.c_ubyte)
    ]

# Open a file for logging
log_file = open("packet_details.log", "a")

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(PacketInfo)).contents
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = "{} - PID {}: {}:{} -> {}:{} length {} flags {}".format(
        current_time,
        event.pid,
        socket.inet_ntoa(ct.c_uint(event.saddr).value.to_bytes(4, byteorder='big')),
        event.sport,
        socket.inet_ntoa(ct.c_uint(event.daddr).value.to_bytes(4, byteorder='big')),
        event.dport,
        event.length,
        event.tcp_flags
    )
    print(log_entry)
    log_file.write(log_entry + "\n")
    log_file.flush()

# Attach to perf output
b["packet_events"].open_perf_buffer(print_event)

print("Tracing... Hit Ctrl-C to end.")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass

log_file.close()
print("Detaching...")
