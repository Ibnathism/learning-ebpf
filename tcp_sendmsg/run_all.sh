#!/bin/bash

# Start a new tmux session named 'ebpf-session'
tmux new-session -d -s ebpf-session

# Create a new window and run the eBPF program
tmux new-window -t ebpf-session -n 'eBPF'
tmux send-keys -t ebpf-session:1 'sudo python3 simple_sc.py' C-m

# Attach to the tmux session
tmux attach-session -t ebpf-session
