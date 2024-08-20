TARGET = xdp_prog
BPF_OBJ = $(TARGET:=.bpf.o)
MAP_PATH = /sys/fs/bpf/packet_count_map
PROG_PATH = /sys/fs/bpf/$(TARGET)

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(BPF_OBJ)
	bpftool net detach xdp dev lo
	rm -f $(PROG_PATH)
	rm -f $(MAP_PATH)
	bpftool prog load $(BPF_OBJ) $(PROG_PATH)
	bpftool prog pin $(PROG_PATH) /sys/fs/bpf/$(TARGET)
	bpftool map pin id $(shell bpftool prog show pinned $(PROG_PATH) | grep -oP '(?<=map_ids )\d+') $(MAP_PATH)
	bpftool net attach xdp pinned /sys/fs/bpf/$(TARGET) dev lo

$(BPF_OBJ): %.bpf.o: %.c
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -g -o $@ -c $<

clean:
	- bpftool net detach xdp dev lo
	- rm -f /sys/fs/bpf/$(TARGET)
	- rm -f $(MAP_PATH)
	- rm $(BPF_OBJ)
