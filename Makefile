CLANG     := clang
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPFTOOL   := /usr/lib/linux-tools-5.15.0-173/bpftool
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -Ikernel

BPF_OBJ := kernel/guardian.bpf.o

.PHONY: all clean vmlinux probe verify

all: vmlinux probe

vmlinux:
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found."; exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kernel/vmlinux.h
	@echo "Done: kernel/vmlinux.h"

probe: kernel/vmlinux.h
	@echo "Compiling eBPF probe..."
	$(CLANG) $(BPF_CFLAGS) -c kernel/guardian.bpf.c -o $(BPF_OBJ)
	@echo "Done: $(BPF_OBJ)"

verify: $(BPF_OBJ)
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/guardian_test && \
	$(BPFTOOL) prog show && \
	rm -f /sys/fs/bpf/guardian_test

clean:
	rm -f kernel/guardian.bpf.o kernel/vmlinux.h

# ── Testing ───────────────────────────────────────────────────────────────────

.PHONY: test test-unit test-integration lint coverage

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	ruff check userspace/ tests/
	black --check userspace/ tests/

coverage:
	pytest tests/ --cov=userspace --cov-report=html --cov-report=term
	@echo "HTML coverage report: htmlcov/index.html"