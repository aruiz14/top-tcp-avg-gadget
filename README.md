# top-tcp-gadget

top-tcp-gadget is a [gadget from Inspektor
Gadget](https://inspektor-gadget.io/). It monitors TCP send and receive
activity per connection, reporting the process, endpoint addresses/ports, bytes
transferred, and direction (send/receive) for each TCP event.

## How to use

```bash
$ sudo ig run ghcr.io/aruiz14/top-tcp-gadget:latest
```

## Requirements

- ig v0.26.0 or later
- Linux v5.15 or later

## License

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
