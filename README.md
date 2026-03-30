# top-tcp-avg

`top-tcp-avg` is a leaderboard-style [Inspektor Gadget](https://inspektor-gadget.io/) module designed to identify the most active network connections and bandwidth hogs across your system or Kubernetes cluster.

Instead of just showing raw packets, this gadget uses an embedded WebAssembly (WASM) module to maintain the state of every connection over time. It continuously aggregates TCP send/receive activity by process and IP endpoints, calculating lifetime average bandwidth rates, tracking total data transferred, and projecting 24-hour data usage.

The UI automatically sorts by the highest projected usage, keeping the heaviest hitters pinned to the top of your terminal.

## Features

* **Leaderboard View:** Automatically clears the screen and sorts connections by maximum 24h projected data usage.
* **Smart Aggregation:** Groups traffic by Process (PID/Comm) and L3 Endpoints (Source/Destination IPs).
* **Stateful Metrics:** Calculates accurate lifetime average rates (`Sent/s`, `Recv/s`) and total bytes transferred, even for connections that intermittently go idle.
* **Kubernetes Native:** Automatically enriches connections with `k8s.namespace` and `k8s.podName` metadata when run in a cluster.

> [!NOTE]
> Aggregated data is only calculated during the duration of the gadget execution.

## How to use

Inspektor Gadget checks the signature of the gadget images. In order to run this gadget, you need to either disable this verification or provide the correct public keys:
Download the public key to verify the gadget's authenticity, then run it:

```bash
wget https://raw.githubusercontent.com/aruiz14/top-tcp-avg-gadget/main/cosign.pub -O top-tcp-avg.pub
```
You can also disable verification by using `--verify-image=false`.

### Run it locally using the `ig` CLI:
```bash
sudo ig run ghcr.io/aruiz14/top-tcp-avg:latest --public-keys="$(cat top-tcp-avg.pub)"
```
`ig` will look for the container runtime socket in the default paths for augmenting the data. Some Kubernetes runtimes use a non-default path for those.
For example, to make it work on a k3s node, you may specify the correct path with `--containerd-socketpath`:
```bash
sudo ig run ghcr.io/aruiz14/top-tcp-avg:latest \
  --public-keys="$(cat top-tcp-avg.pub)" \
  --containerd-socketpath /run/k3s/containerd/containerd.sock
```

### Run it using [kubectl node debug](https://github.com/inspektor-gadget/inspektor-gadget#kubectl-node-debug):
```bash
kubectl debug --profile=sysadmin node/NODE_NAME -ti --image=ghcr.io/inspektor-gadget/ig:latest -- \
  ig run ghcr.io/aruiz14/top-tcp-avg:latest \
    --public-keys="$(cat top-tcp-avg.pub)" \
    --containerd-socketpath /run/k3s/containerd/containerd.sock
```
> [!NOTE]
> The node's filesystem is them mounted at `/host`, which is automatically handled by `ig`.

### Useful `ig` options

#### Filter by src/dst IPs to omit localhost and internal cluster traffic
```bash
kubectl debug --profile=sysadmin node/NODE_NAME -ti --image=ghcr.io/inspektor-gadget/ig:latest -- \
  ig run ghcr.io/aruiz14/top-tcp-avg:latest \
    --public-keys="$(cat top-tcp-avg.pub)" \
    --containerd-socketpath /run/k3s/containerd/containerd.sock \
    --filter.tcp 'src!=127.0.0.1,dst!~10\.(42|43)\.'
```

#### Include traffic from all process, not only Kubernetes
```bash
kubectl debug --profile=sysadmin node/NODE_NAME -ti --image=ghcr.io/inspektor-gadget/ig:latest -- \
  ig run ghcr.io/aruiz14/top-tcp-avg:latest \
    --public-keys="$(cat top-tcp-avg.pub)" \
    --containerd-socketpath /run/k3s/containerd/containerd.sock \
    --host
```

## Requirements
 - `ig` v0.50.1 or later (Tested on 0.50.1, relies on recent WASM and Operator pipeline features)
 - Linux v5.15 or later (Requires modern eBPF features)

## License
The user space components are licensed under the [Apache License, Version 2.0](./LICENSE).
The BPF code templates are licensed under the [General Public License, Version 2.0, with the Linux-syscall-note](./LICENSE-bpf.txt).
