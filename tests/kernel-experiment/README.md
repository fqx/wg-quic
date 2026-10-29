# Kernel WireGuard + unchanged wg-quic carrier experiment

This is a cloud-only architecture prototype based on
`c1c02231f5298d72458eb9c5bd944e57edccee34`. The ordinary `wg-quic` executable,
Bind, QUIC DATAGRAM transport, WGQ1 fragmentation, automatic FEC, congestion
policy, Salamander and outer GSO/FEC guard are unchanged. No second-round salt
cache or send batching experiment is included.

`cmd/wg-quic-kernel-experiment` replaces the userspace WireGuard engine and
TUN crossing with a local UDP relay to a real kernel WireGuard interface.
It does not implement a WireGuard cipher or decrypt inner packets. A separate
stock `wg-quic run` process using a real TUN is the architecture baseline.

## Security and scope

Use only disposable interfaces and freshly generated experiment keys, inside
an isolated guest or test network namespaces. The prototype supports exactly
one peer and one fixed QUIC session per process. There must be no concurrent
configuration writer or untrusted process in either local network namespace.
This is not a production peer manager and is not ready to replace `wg-quic`.

Each endpoint has two connected IPv4 loopback UDP sockets:

1. A fixed **bootstrap** socket receives locally generated WG initiation
   packets and sends them to the configured QUIC peer. Configure only the
   initiating kernel peer with this endpoint; leave the responder endpoint
   unset to prevent simultaneous independent dials.
2. A new ephemeral **ingress** socket forwards reassembled encrypted WG
   datagrams to the kernel listen port. Never configure this port in WireGuard.
   It is unique to the pinned QUIC session and stays open until shutdown.
   Kernel replies received there return through that same QUIC session.

Outer TLS establishment, Salamander key possession, packet shape, receiving
a UDP reply, and a recent handshake timestamp alone do not prove WG peer
authentication. The relay calls `AssociateSessionPeer` only after a read-only
WireGuard generic-netlink dump confirms all of:

- the sole kernel peer has the configured public key;
- its endpoint changed to the fresh, never-configured ingress socket;
- its RX byte count advanced past the startup observation;
- a datagram was actually forwarded from the pinned QUIC session.

The kernel WG receive path authenticates initiation/response before updating
the peer endpoint. Transport packets must pass AEAD and replay checks before
updating that endpoint; cookies do not update the peer endpoint/RX counter.
RX accounting for inner IP data additionally follows AllowedIPs checks.
Endpoint and counter netlink reads are not an atomic per-packet snapshot, so
the observer tolerates delayed RX progress and polls again before admission.
After confirmation it stops polling; the fixed configuration is a prerequisite.
References: Linux [receive.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/wireguard/receive.c),
[netlink.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/wireguard/netlink.c),
and [WireGuard UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/wireguard.h).

The GET dump necessarily contains private-key/PSK attributes. The reader skips
them without decoding, never returns or logs them, and clears its receive
buffer. Therefore it must be pointed only at the newly provisioned test device.
The separate explicit test key file is used solely for the existing Salamander
key derivation. It must be a regular file with no group/other permissions.

Unknown sessions, outer endpoint changes and replacement sessions are rejected.
Do not use the prototype to claim roaming, reconnection, multi-peer admission,
configuration reload or authenticated generation-barrier equivalence. A new
experiment run must create fresh devices and restart the relay. An anonymous
first session from the fixed remote address can occupy the single candidate
slot until the normal Bind authentication timeout; this bounded denial of
service limitation is another reason not to deploy it.

WG packet type/length checks are only boundary checks. Each accepted datagram
is forwarded intact. A 65536-byte local receive buffer exceeds all IPv4 UDP
payloads; over-limit/invalid packets are discarded whole. Connected UDP sockets
accept only the configured kernel source address/port. No local UDP GRO or USO
is enabled; local per-packet syscall/copy costs remain part of the experiment.

## Build and tests

With a Go toolchain satisfying `go.mod`, from the repository root:

```sh
go test -count=1 ./internal/kernelrelay ./cmd/wg-quic-kernel-experiment
go test -race -count=1 ./internal/kernelrelay ./cmd/wg-quic-kernel-experiment
go build -buildvcs=false -o wg-quic-baseline ./cmd/wg-quic
go build -buildvcs=false -o wg-quic-kernel-experiment ./cmd/wg-quic-kernel-experiment
GOOS=linux GOARCH=arm64 go build -buildvcs=false ./cmd/wg-quic-kernel-experiment
```

The measured baseline additionally uses an **overlay-only no-UDP-USO path**:
replace the `tun.udpGSO = unix.IoctlSetInt(...,
tunTCPOffloads|tunUDPOffloads) == nil` assignment in `tun_linux.go` with
`tun.udpGSO = false`. This preserves the earlier `TUN_F_CSUM`, TCP offloads,
vnet header and all outer transport settings. It does not set
`WG_QUIC_DISABLE_TUN_OFFLOAD`, which would also remove checksum support valid
on old kernels. The overlay source, JSON mapping and rebuilding script are
retained in the result bundle under `wrapper/oldtun/`. Compile it with:

```sh
python3 RESULTS/wrapper/oldtun/make-overlay.py "$PWD" RESULTS/wrapper/oldtun
go build -buildvcs=false -overlay=RESULTS/wrapper/oldtun/overlay.json \
  -o wg-quic-baseline-oldtun ./cmd/wg-quic
```

This controls one newer TUN capability, rather than emulating Linux 5.4.

`-buildvcs=false` only avoids stamping a managed-worktree VCS discovery result.
It does not change packet handling. Unit tests use an explicitly fake UDP
kernel fixture/observer to check the relay state machine, intact datagrams,
reply paths, source filtering, admission evidence, session pinning, netlink
bounds/multipart parsing and key-file permissions. They do not establish real
kernel WG cryptographic interoperability. That needs the isolated guest tests.

## CLI contract

The wrapper takes `-config /test/a.json` and `-stats-interval 1s` (or `0` for
start/final snapshots). It emits JSON lines to stdout and errors to stderr;
SIGTERM/SIGINT closes all sockets/workers. No key is included in telemetry.

Example JSON, with newly generated key files and the actual numeric peer key:

```json
{
  "interface": "wgk0",
  "kernel_endpoint": "127.0.0.1:51820",
  "bootstrap_listen": "127.0.0.1:51821",
  "peer_quic_endpoint": "192.0.2.2:40002",
  "quic_listen_port": 40001,
  "peer_public_key": "REPLACE_WITH_FRESH_BASE64_PEER_PUBLIC_KEY",
  "test_private_key_file": "/test/a.key",
  "test_preshared_key_file": "/test/psk.key",
  "fec_mode": "auto",
  "obfs_mode": "salamander"
}
```

Set the test kernel interface to listen on 51820 and install only the one
reciprocal peer/AllowedIPs. Set A's peer endpoint to `127.0.0.1:51821`; leave B's
unset. Start both relays before producing inner traffic. The JSON `ready`
event reports bootstrap/ingress addresses and the PID. Wait for
`stats.authenticated=true` on both peers and useful inner packet delivery;
`ready` alone is not successful authentication. Use the same GOMAXPROCS and
memory limits for both architectures.

The baseline uses the unmodified command:

```sh
GOMAXPROCS=1 GOMEMLIMIT=192MiB ./wg-quic-baseline run /test/a.conf --name wgq0
GOMAXPROCS=1 GOMEMLIMIT=192MiB ./wg-quic-kernel-experiment -config /test/a.json
```

Baseline profile shape:

```ini
[Interface]
PrivateKey = FRESH_A_PRIVATE_KEY
ListenPort = 40001
MTU = 1500
# wg-quic: congestion=model
# wg-quic: fec=auto
# wg-quic: obfs=salamander

[Peer]
PublicKey = FRESH_B_PUBLIC_KEY
PresharedKey = FRESH_SHARED_PSK
AllowedIPs = 10.60.0.2/32
Endpoint = 192.0.2.2:40002
```

For B reverse keys/IPs/port and omit `Endpoint`. `wg-quic run` creates the TUN;
the test controller must assign addresses, raise the link and install the
single peer route itself. Apply the same addresses, MTU 1500 and routes to the
kernel WG interfaces. Generate keys into owner-only files with
`wg-quic-baseline genkey` and derive public keys with its `pubkey` command;
never reuse production configuration. Create the PSK with a CSPRNG.

If the two namespaces share a filesystem, give the two baseline processes
different interface/instance names (for example `--name wgqa` and
`--name wgqb`), because their local management sockets and locks share
`/run/wg-quic`. Network namespaces alone do not isolate those paths.

Payload 1424 bytes plus IPv4/UDP headers is 1452 bytes, fitting MTU 1500.
WireGuard padding/encryption produces a larger complete WG datagram; existing
WGQ1/QUIC fragmentation handles the transport budget identically in both
architectures. Record inner payload length separately from encrypted packet
and outer wire lengths.

## Measurement and compatibility boundaries

Measure actual inner goodput, packet integrity/loss, p99 and queue drops with
separate generator and receiver processes. Endpoint process CPU alone cannot
compare these architectures: kernel WG work may move into system/softirq or
kernel threads. Record endpoint user/system time, generator/receiver time,
whole-guest `/proc/stat` user/system/irq/softirq and host QEMU CPU separately.
Use warmup, fixed offered load and paired repeated steady windows; successful
handshakes or a brief pilot are not maximum-throughput evidence.

No ChannelTUN, container mock or userspace replacement counts as kernel WG.
QEMU TCG can exercise genuine guest kernel WG, but its CPU/throughput figures
describe emulation and cannot establish native kernel savings or MT3000
performance. The target device is aarch64 Linux 5.4.211/OpenWrt21.02-SNAPSHOT;
no actual device access is part of this task. The prototype uses established
generic-netlink and ordinary UDP APIs and needs neither TUN UDP USO >=6.2 nor
ARM getrandom vDSO >=6.12. Availability of a compatible WireGuard module on
that specific firmware is unverified. A newer guest's baseline TUN offloads
also differ from a 5.4 device and must be reported separately.
