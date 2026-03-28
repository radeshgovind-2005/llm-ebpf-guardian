# Makefile — build the eBPF probe and generate vmlinux.h
#
# Run inside the devcontainer (Ubuntu 22.04 with clang + libbpf installed).
# On the host Mac these commands will fail — that's expected.

CLANG     := clang
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -Ikernel

BPF_OBJ := kernel/guardian.bpf.o

.PHONY: all clean vmlinux probe

all: vmlinux probe

# Generate vmlinux.h from the running kernel's BTF data
# This must be run inside the devcontainer on Linux
vmlinux:
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found."; \
		echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y"; \
		exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel/vmlinux.h
	@echo "Done: kernel/vmlinux.h"

# Compile the eBPF C probe to BPF bytecode
probe: kernel/vmlinux.h
	@echo "Compiling eBPF probe..."
	$(CLANG) $(BPF_CFLAGS) -c kernel/guardian.bpf.c -o $(BPF_OBJ)
	@echo "Done: $(BPF_OBJ)"

# Verify the compiled BPF object
verify: $(BPF_OBJ)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/guardian_test && \
	bpftool prog show && \
	rm -f /sys/fs/bpf/guardian_test

clean:
	rm -f kernel/guardian.bpf.o kernel/vmlinux.h