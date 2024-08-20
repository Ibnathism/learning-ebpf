from bcc import BPF
import time
from datetime import datetime

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(packet_count, u32, u64);

int count_packets(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = packet_count.lookup(&pid);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        packet_count.update(&pid, &init_val);
    }
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)
b.attach_kprobe(event="tcp_sendmsg", fn_name="count_packets")

log_file = open("packet_counts.log", "a")

# Print packet counts every second with a timestamp
print("Tracing... Hit Ctrl-C to end.")
try:
    while True:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_count = b.get_table("packet_count")
        for k, v in packet_count.items():
            log_entry = "{} - PID {}: {} packets".format(current_time, k.value, v.value)
            print(log_entry)
            log_file.write(log_entry + "\n")
        log_file.flush()
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    log_file.close()

print("Detaching...")
