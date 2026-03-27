// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 The top-tcp-avg Authors */

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
  gadget_mntns_id _mntns_id;
  gadget_pid _pid;
  struct gadget_l3endpoint_t _src;
  struct gadget_l3endpoint_t _dst;
  gadget_comm _comm[TASK_COMM_LEN];
};

struct traffic_t {
  __u64 _ts;
  __u64 _sent_raw;
  __u64 _recv_raw;
};

/* A single map to catch the interval's deltas */
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
  __u16 family;
  __u64 pid_tgid;
  struct ip_key_t ip_key;
  __builtin_memset(&ip_key, 0, sizeof(ip_key)); // Force 100% zeroed memory!
  struct traffic_t *trafficp;

  family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET && family != AF_INET6)
    return 0;

  if (target_family != -1 && ((target_family == 4 && family != AF_INET) ||
                              (target_family == 6 && family != AF_INET6)))
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  pid_tgid = bpf_get_current_pid_tgid();

  ip_key._mntns_id = gadget_get_current_mntns_id();
  ip_key._pid = pid_tgid >> 32;
  bpf_get_current_comm(&ip_key._comm, sizeof(ip_key._comm));

  if (family == AF_INET) {
    ip_key._src.version = ip_key._dst.version = 4;
    bpf_probe_read_kernel(&ip_key._src.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_rcv_saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&ip_key._dst.addr_raw.v4,
                          sizeof(sk->__sk_common.skc_daddr),
                          &sk->__sk_common.skc_daddr);
  } else {
    ip_key._src.version = ip_key._dst.version = 6;
    bpf_probe_read_kernel(
      &ip_key._src.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(
      &ip_key._dst.addr_raw.v6,
      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }

  trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
  if (!trafficp) {
    struct traffic_t zero;
    __builtin_memset(&zero, 0, sizeof(zero)); // Force 100% zeroed memory!
    zero._ts = bpf_ktime_get_boot_ns();

    bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);

    trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
    if (!trafficp)
      return 0;
  }

  if (receiving)
    __sync_fetch_and_add(&trafficp->_recv_raw, size);
  else
    __sync_fetch_and_add(&trafficp->_sent_raw, size);

  return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ig_toptcp_sdmsg, struct sock *sk, struct msghdr *msg,
               size_t size)
{
  return probe_ip(false, sk, size);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ig_toptcp_clean, struct sock *sk, int copied)
{
  if (copied <= 0)
    return 0;

  return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
