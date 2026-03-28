#ifndef GUARDIAN_H
#define GUARDIAN_H

/*
 * guardian.h — shared event structs between eBPF probe and userspace loader
 *
 * This header is included by both:
 *   kernel/guardian.bpf.c  (compiled by clang for the kernel)
 *   userspace/loader.py    (parsed via ctypes or libbpf-python)
 *
 * Keep types simple — only fixed-width integers and char arrays.
 * No pointers, no padding surprises.
 */

#define TASK_COMM_LEN 16
#define PATH_LEN      128
#define MAX_ARGS      4

/* Syscall IDs we monitor — keeps the BPF maps type-safe */
enum syscall_id {
    SYS_EXECVE  = 1,
    SYS_SOCKET  = 2,
    SYS_CONNECT = 3,
    SYS_OPENAT  = 4,
    SYS_PTRACE  = 5,
    SYS_MOUNT   = 6,
};

/*
 * guardian_event — emitted to the ring buffer on each intercepted syscall.
 *
 * Sized to stay under 512 bytes so it fits in a single ring buffer slot
 * without fragmentation.
 */
struct guardian_event {
    __u64 timestamp_ns;             /* ktime_get_ns() at intercept time    */
    __u32 pid;                      /* process ID of the calling process   */
    __u32 tgid;                     /* thread group ID (= PID for main)    */
    __u32 uid;                      /* user ID                             */
    enum syscall_id syscall;        /* which syscall was intercepted       */
    char comm[TASK_COMM_LEN];       /* process name (e.g. "python3")       */
    char path[PATH_LEN];            /* for openat: file path being opened  */
    __u16 socket_family;            /* for socket/connect: AF_INET etc.    */
    __u32 remote_addr;              /* for connect: remote IPv4 (network order) */
    __u16 remote_port;              /* for connect: remote port            */
    __u32 ret;                      /* syscall return value (where useful) */
};

/* Sent to the policy engine when anomaly threshold is breached */
struct guardian_verdict {
    __u32 pid;
    __u32 anomaly_score;
    enum syscall_id triggering_syscall;
    char comm[TASK_COMM_LEN];
};

#endif /* GUARDIAN_H */