// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The top-tcp-gadget Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET 2
#define AF_INET6 10

enum direction_t {
  DIRECTION_SEND = 0,
  DIRECTION_RECV = 1,
};

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  gadget_pid pid;
  gadget_comm comm[TASK_COMM_LEN];
  struct gadget_l4endpoint_t src;
  struct gadget_l4endpoint_t dst;
  gadget_bytes bytes;
  enum direction_t direction;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(tcp, events, event);

static __always_inline int
probe_tcp(void *ctx, bool receiving, struct sock *sk, size_t size)
{
  __u16 family;
  __u64 pid_tgid;
  struct event *e;

  family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET && family != AF_INET6)
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  e = gadget_reserve_buf(&events, sizeof(*e));
  if (!e)
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();

  e->timestamp = bpf_ktime_get_boot_ns();
  e->mntns_id = gadget_get_current_mntns_id();
  e->pid = pid_tgid >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  e->src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
  e->dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  e->src.proto_raw = e->dst.proto_raw = IPPROTO_TCP;

  if (family == AF_INET) {
    e->src.version = e->dst.version = 4;
    bpf_probe_read_kernel(&e->src.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_rcv_saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->dst.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_daddr),
                          &sk->__sk_common.skc_daddr);
  } else {
    e->src.version = e->dst.version = 6;
    bpf_probe_read_kernel(
      &e->src.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(
      &e->dst.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }

  e->bytes = size;
  e->direction = receiving ? DIRECTION_RECV : DIRECTION_SEND;

  gadget_submit_buf(ctx, &events, e, sizeof(*e));

  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_tcp_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t size)
{
  return probe_tcp(ctx, false, sk, size);
}

/*
 * tcp_cleanup_rbuf() is used instead of tcp_recvmsg() because:
 * - tcp_recvmsg() requires tracing both entry and exit to obtain the socket
 *   and the number of bytes received
 * - tcp_cleanup_rbuf() also captures tcp_read_sock() traffic
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
  if (copied <= 0)
    return 0;

  return probe_tcp(ctx, true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
