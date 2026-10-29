# Native Linux VM handoff

This branch contains a reusable **experiment**, not a production replacement.
The command is `cmd/wg-quic-kernel-experiment`; the forwarding and kernel
observation implementation is `internal/kernelrelay`. Read [README.md](README.md)
for the authentication boundary and complete JSON contract.

The tested local implementation commit was
`31852aa939b13734c6f67bd3b74ec8e7dcaba600`, based on
`c1c02231f5298d72458eb9c5bd944e57edccee34`, with tree
`26c096a245a10ef18b4ce7810d448e30b80f0f52`. Publishing through a Git data API
can change commit metadata and SHA; compare trees to establish code equality.
This handoff adds documentation only. No new VM run was performed for it.

## Prerequisites and build

Use a disposable Linux VM with the actual WireGuard kernel interface, TUN,
network namespaces, `iproute2`, `wireguard-tools`, Python 3, and root privileges
inside that VM for interface/netns configuration and WireGuard netlink reads.
Run the Linux guest directly under hardware virtualization; QEMU TCG is not
needed. Keep all test traffic on an internal link. No hypervisor SSH access or
production configuration is needed by the program.

The cloud experiment used Go 1.26.3. From this repository's root:

```sh
mkdir -p build/kernel-experiment
CGO_ENABLED=0 go build -buildvcs=false \
  -o build/kernel-experiment/wg-quic-kernel-experiment \
  ./cmd/wg-quic-kernel-experiment
CGO_ENABLED=0 go build -buildvcs=false \
  -o build/kernel-experiment/wg-quic-baseline ./cmd/wg-quic
```

Build on the VM's architecture, or set `GOOS=linux GOARCH=amd64` for an x86 VM.
The command also cross-builds with `GOOS=linux GOARCH=arm64`; that is not an
ARM runtime or performance test. `-buildvcs=false` only omits VCS stamping.

For a comparison retaining the pre-6.2 TUN UDP-offload path, generate a build
overlay without changing the repository's TUN source:

```sh
python3 - <<'PY'
import json, pathlib
root = pathlib.Path.cwd()
out = root / 'build/kernel-experiment/oldtun'
out.mkdir(parents=True, exist_ok=True)
source = root / 'third_party/wireguard-go/tun/tun_linux.go'
text = source.read_text()
needle = 'tun.udpGSO = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil'
assert text.count(needle) == 1
target = out / 'tun_linux.go'
target.write_text(text.replace(needle, 'tun.udpGSO = false'))
(out / 'overlay.json').write_text(json.dumps({'Replace': {str(source): str(target)}}))
PY
CGO_ENABLED=0 go build -buildvcs=false \
  -overlay=build/kernel-experiment/oldtun/overlay.json \
  -o build/kernel-experiment/wg-quic-baseline-oldtun ./cmd/wg-quic
```

This keeps TUN checksum/TCP offloads and the unchanged outer GSO/FEC guard.
It controls one capability; it does not turn a newer Linux VM into Linux 5.4.

## Minimal topology and runtime inputs

One VM with two isolated network namespaces is sufficient for initial reuse:

```text
namespace a                                      namespace b
inner application                               inner application
10.66.0.1/32 wgqa                                10.66.0.2/32 wgqb
kernel WG UDP 127.0.0.1:51820                     kernel WG UDP 127.0.0.1:51820
loopback relay                                  loopback relay
QUIC 10.77.0.1:40001 ---- private veth ---- QUIC 10.77.0.2:40002
```

Use veth addresses `10.77.0.1/30` and `10.77.0.2/30`, MTU 1500, and raise
loopback in both namespaces. Kernel WG interfaces also use MTU 1500, with a
host route to the other inner address. There is no forwarding/NAT/default-route
change outside these two namespaces.

Runtime files for the kernel candidate are:

- the compiled relay binary;
- fresh `a.key`, `b.key`, and shared `psk.key` files, owner-only permissions;
- `a.json` and `b.json` using the schema in README.md;
- two freshly configured kernel WG interfaces, with exactly one reciprocal
  peer and the matching inner /32 AllowedIPs.

Generate keys at runtime in a new private test directory:

```sh
umask 077
wg genkey > a.key
wg genkey > b.key
wg genpsk > psk.key
wg pubkey < a.key > a.pub
wg pubkey < b.key > b.pub
```

Configure kernel A's peer endpoint as `127.0.0.1:51821`; leave B's kernel peer
endpoint unset. Both kernel interfaces listen on 51820. For each relay set
`bootstrap_listen` to `127.0.0.1:51821`, `kernel_endpoint` to
`127.0.0.1:51820`, the reciprocal QUIC address/port from the diagram, its own
test private-key file, the same PSK file, and the other peer's public key.
Keep `fec_mode: "auto"` and `obfs_mode: "salamander"`.

Start one relay in each namespace, using absolute local paths, for example:

```sh
ip netns exec a env GOMAXPROCS=1 GOMEMLIMIT=192MiB \
  /absolute/path/wg-quic-kernel-experiment \
  -config /absolute/path/a.json -stats-interval 1s
```

Use a separate process with namespace `b` and `b.json` for B. Generate inner
traffic only after both relay processes are ready. Require a nonzero kernel
handshake, `stats.authenticated=true` at both relays, and verified inner packet
delivery. A `ready` event or outer QUIC connection alone is not authentication.
Do not preconfigure the relay's ephemeral ingress address into WireGuard.
Stop both relays before discarding the test interfaces/namespaces and keys.

For the userspace baseline, use the two ordinary `.conf` profiles described
in README.md and run `wg-quic-baseline-oldtun run ... --name wgqa` / `wgqb`
inside the corresponding namespaces. The command creates the TUN; configure
the same inner addresses, host routes and MTU. Use fresh namespaces for each
trial so the kernel and userspace variants cannot overlap. The distinct names
also isolate their management sockets in the VM's shared filesystem.

## Measurement handoff and known boundaries

The prior ordinary tests, whole-module race tests, new-package vet, and Linux
amd64/arm64 builds passed. Real kernel interoperability, wrong-key rejection,
and lossy/reordered packet delivery were exercised in a Debian 6.12 TCG guest.
No native Linux VM performance benefit has yet been established.

The next comparison should retain the same QUIC DATAGRAM/FEC/Salamander and
transport policy. Fix VM resources and record guest/host versions, CPU
placement/limits, hypervisor scheduling contention and unrelated load. Start
with a short functional run, then alternate both implementations at 20 Mbps,
1200/1424-byte UDP payloads, and 1 ms/16.667 ms sending intervals. Separate
warmup, PMTU/FEC convergence, steady measurement and drain; do not extend an
overloaded run into an invalid equal-throughput comparison.

Count verified goodput, loss, p99, per-process user/system CPU, guest-wide
CPU/softirq, memory, generator/receiver overhead and hypervisor overhead. Do
not add process CPU back to already aggregated guest CPU. Validate CPU
accounting before deriving CPU seconds per delivered byte: in the earlier
TCG runs, guest task and global CPU accounting did not reconcile. Lower relay
RSS does not include kernel WireGuard/slab memory. For timed runs use
`-stats-interval 0` symmetrically with the original measurement setup.

The archived cloud harness (`traffic/main.go`, `vm/experiment.sh`, plans,
analysis scripts and raw measurements) is separate from this source branch.
Its controller uses fixed initramfs paths (`/bin/...`, `/test`, `/results`,
`/plan.tsv`) and BusyBox `usleep`; adapt those paths and waits before native-VM
reuse. Its `vm/init` powers off a guest, and `run_vm.py` launches QEMU TCG:
neither is a native-VM entry point. This document is a handoff specification,
not a newly executed native-VM benchmark controller.

Each relay admits exactly one fixed peer/session. Outer endpoint changes,
replacement sessions, roaming, reconnect, multiple peers, concurrent WG
configuration writers and production lifecycle management are unsupported.
Mixed kernel/userspace endpoints and long-running deployment are not yet
validated. The kernel remains responsible for WG authentication, encryption
and replay rejection; the relay does not bypass those checks.

The API choices do not require io_uring, TUN UDP USO >=6.2 or ARM64 getrandom
vDSO >=6.12. A compatible WireGuard module must actually exist in the target
kernel/firmware. An x86 hardware-virtualized VM result still cannot be scaled
directly into CPU savings on an ARM router.
