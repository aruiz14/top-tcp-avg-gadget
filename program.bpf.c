// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The top-tcp-gadget Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

/* Taken from kernel include/linux/socket.h. */
#define AF_INET 2
#define AF_INET6 10

const volatile int target_family = -1;
GADGET_PARAM(target_family);

struct ip_key_t {
  gadget_mntns_id mntns_id;
  gadget_pid pid;
  gadget_tid tid;
  struct gadget_l4endpoint_t src;
  struct gadget_l4endpoint_t dst;
  gadget_comm comm[TASK_COMM_LEN];
};

struct traffic_t {
  gadget_bytes sent_raw;
  gadget_bytes received_raw;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct ip_key_t);
  __type(value, struct traffic_t);
} ip_map SEC(".maps");

GADGET_MAPITER(tcp, ip_map);

static __always_inline int
probe_ip(bool receiving, struct sock *sk, size_t size)
{
  struct ip_key_t ip_key = {};
  struct traffic_t *trafficp;
  __u16 family;
  __u64 pid_tgid;

  family = BPF_CORE_READ(sk, __sk_common.skc_family);

  if (target_family != -1 && ((target_family == 4 && family != AF_INET) ||
                               (target_family == 6 && family != AF_INET6)))
    return 0;

  if (family != AF_INET && family != AF_INET6)
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();

  ip_key.mntns_id = gadget_get_current_mntns_id();
  ip_key.pid = pid_tgid >> 32;
  ip_key.tid = (__u32)pid_tgid;
  bpf_get_current_comm(&ip_key.comm, sizeof(ip_key.comm));

  ip_key.src.port = BPF_CORE_READ(sk, __sk_common.skc_num);
  ip_key.dst.port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  ip_key.src.proto_raw = ip_key.dst.proto_raw = IPPROTO_TCP;

  if (family == AF_INET) {
    ip_key.src.version = ip_key.dst.version = 4;
    bpf_probe_read_kernel(&ip_key.src.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_rcv_saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&ip_key.dst.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_daddr),
                          &sk->__sk_common.skc_daddr);
  } else {
    ip_key.src.version = ip_key.dst.version = 6;
    bpf_probe_read_kernel(
      &ip_key.src.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(
      &ip_key.dst.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }

  trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
  if (!trafficp) {
    struct traffic_t zero = {};

    if (receiving)
      zero.received_raw = size;
    else
      zero.sent_raw = size;

    /* BPF_NOEXIST avoids overwriting a concurrent insert; if it races and
     * fails, fall through to the atomic add on the now-existing entry. */
    if (bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST) == 0)
      return 0;

    trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
    if (!trafficp)
      return 0;
  }

  if (receiving)
    __sync_fetch_and_add(&trafficp->received_raw, size);
  else
    __sync_fetch_and_add(&trafficp->sent_raw, size);

  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_toptcp_sdmsg, struct sock *sk, struct msghdr *msg,
               size_t size)
{
  return probe_ip(false, sk, size);
}

/*
 * tcp_cleanup_rbuf() is used instead of tcp_recvmsg() because:
 * - tcp_recvmsg() requires tracing both entry and exit to obtain the socket
 *   and the number of bytes received
 * - tcp_cleanup_rbuf() also captures tcp_read_sock() traffic
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_toptcp_clean, struct sock *sk, int copied)
{
  if (copied <= 0)
    return 0;

  return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
