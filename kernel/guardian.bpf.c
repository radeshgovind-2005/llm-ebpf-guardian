// SPDX-License-Identifier: GPL-2.0
/*
 * guardian.bpf.c — eBPF syscall interception probe
 *
 * Phase 1: intercept the six syscalls defined in guardian.h and emit
 * structured events to a ring buffer that userspace/loader.py reads.
 *
 * Compile with:
 *   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include/x86_64-linux-gnu \
 *         -c kernel/guardian.bpf.c -o kernel/guardian.bpf.o
 *
 * Requires: Linux 5.8+ with BTF (/sys/kernel/btf/vmlinux must exist)
 */

#ifdef __has_include
#if __has_include("vmlinux.h")
#include "vmlinux.h"
#else
#include <linux/types.h>
#include <linux/bpf.h>
#endif
#else
#include "vmlinux.h"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "guardian.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Ring buffer — userspace reads events from here.
 * 256KB is enough for bursts of syscall events without dropping.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Target PID map — userspace writes the PID to monitor here.
 * We only emit events for that PID (and its children).
 * Key 0 = target PID, value 0 = "monitor all" (for testing).
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

/*---------------------------- Helpers ----------------------------*/

static __always_inline int should_monitor(__u32 pid)
{
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0)
        return 1; /* 0 = monitor everything (test mode) */
    return (pid == *tpid);
}

static __always_inline void fill_common(struct guardian_event *e,
                                        enum syscall_id sid)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(pid_tgid);
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)(uid_gid);
    e->syscall = sid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/*---------------------------- execve ----------------------------*/

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_EXECVE);

    /* Read the filename argument (first arg to execve) */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*---------------------------- socket ----------------------------*/

SEC("tracepoint/syscalls/sys_enter_socket")
int tp_socket(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_SOCKET);
    e->socket_family = (__u16)ctx->args[0]; /* domain: AF_INET, AF_UNIX … */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*---------------------------- connect ----------------------------*/

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_CONNECT);

    /* Read the sockaddr to get remote IP and port */
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->socket_family = sa.sin_family;
    e->remote_addr = sa.sin_addr.s_addr;
    e->remote_port = sa.sin_port;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*---------------------------- openat ----------------------------*/

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_OPENAT);

    /* args[1] = pathname */
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path, sizeof(e->path), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*---------------------------- ptrace ----------------------------*/
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_PTRACE);
    /* No extra fields needed — ptrace is always flagged regardless of args */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*---------------------------- mount ----------------------------*/
SEC("tracepoint/syscalls/sys_enter_mount")
int tp_mount(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (!should_monitor(pid))
        return 0;

    struct guardian_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, SYS_MOUNT);

    /* args[0] = source device/path */
    const char *source = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->path, sizeof(e->path), source);

    bpf_ringbuf_submit(e, 0);
    return 0;
}