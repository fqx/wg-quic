# Transport structure and resilience validation — 2026-10-20

This change keeps the WireGuard and wg-quic wire protocols, public bind API,
default FEC/congestion policies, and production connection timeouts unchanged.
It concentrates on the bind layer, where connection policy, worker lifetimes,
framing, statistics and event retention previously shared a 2,529-line file.

## Responsibilities and ownership

| File | Responsibility |
| --- | --- |
| `internal/bind/bind.go` | WireGuard bind entry points, carrier open/close, endpoint parsing and datagram admission |
| `config.go` | Configuration defaults and normalization |
| `session.go` | Session registration, dial/accept, worker lifetime and close |
| `session_send.go`, `session_receive.go` | The existing per-session send/receive algorithms |
| `reconnect.go` | Endpoint retirement, redial, retry scheduling and backoff |
| `endpoint_policy.go` | Endpoint key leases and FEC policy |
| `admission.go` | Connection budgets, authentication and untrusted receive reservations |
| `telemetry.go` | Counters and session observations |
| `event_log.go` | Bounded event retention and cursor pagination |

The main bind file is now approximately 480 lines. The split keeps concrete
types in one package; it adds no dependency-injection framework, generic
repository layer or new public interfaces. In particular, event retention now
owns its mutex and ring independently of live session management.

Existing lock ownership is preserved: `Bind.mu` protects instance state,
`runState.mu` protects registration/admission, `Endpoint.mu` protects retry and
selected-session state, and `session.mu` protects connection metadata. Paths
taking both registration and endpoint locks retain the state→endpoint order.
Event-log operations do not call back into connection management.

An AST comparison against the original bind file found only six changed
function bodies: construction, observation identity, event append/read,
reconnect scheduling and the typed admission error. The packet send/receive,
FEC and session-close algorithms were moved without behavioral edits.

## Fixes with evidence

**Admission pressure could stop maintenance permanently.** A scheduled retry
that reached the global session cap returned without creating a session.
There was consequently no session close to schedule its next retry. After
capacity was released, recovery required fresh application traffic.
`TestReconnectResumesAfterAdmissionPressure` fails on the old implementation
and passes after retries are explicitly retained with bounded backoff.

Completed retry workers now cancel their child context, releasing the parent
context's registration instead of retaining it until bind shutdown.
Configuration normalization also keeps maximum backoff at least as large as
an explicitly configured minimum.

**Full event history imposed linear work on every append.** The old slice
copied up to 4,096 observations for each new event after reaching capacity.
A fixed-capacity ring now overwrites one slot; chronological ordering,
sequence numbers, dropped counts, stream epochs and bounded pagination remain
unchanged. Tests cover multiple complete wraps and pagination across the
physical end of the ring.

## Measurements

Raw results and methodology are in
[`benchmarks/2026-10-structure`](benchmarks/2026-10-structure/manifest.json).
Measurements used Linux/amd64, Go 1.26.3 and an Intel Xeon CPU Max 9470C host.

| Measurement | Before | After |
| --- | ---: | ---: |
| Full event-history append, median of three runs | 9,707 ns | 36.40 ns |
| Event append allocation | 0 B/op | 0 B/op |
| WireGuard+QUIC loopback, Salamander, median of three 3-second runs | 1,149 Mbit/s | 1,169 Mbit/s |
| WireGuard+QUIC loopback, plain, same method | 1,349 Mbit/s | 1,337 Mbit/s |

The approximately 267× improvement applies to the event-log operation, not
whole-tunnel throughput. The loopback differences are small relative to the
sample spread and do not establish a throughput improvement.

Concurrent cold transport tests delivered checked request/reply datagrams
across 1, 32 and 128 QUIC connections in approximately 5.3, 15.5 and 34.3 ms.
Closing all 128 clients and the listener took approximately 1.6 ms and left
no registered sessions. These are loopback transport tests with the pending
authentication cap raised for the fixture, **not** a measurement of 128
authenticated WireGuard peers, kernel TUN startup or Internet latency.
Allocation benchmarks additionally exercise 1/32/256/1024 session lifetimes.

Before/after real-TUN trials cover LAN, fiber, cable, DSL, Wi-Fi, cellular,
satellite and lossy Wi-Fi, each with TCP capacity traffic and 1 Mbit/s UDP.
Endpoints are limited to one CPU with `GOMAXPROCS=2`. All 32 trials completed.
These are single five-second trials with unpinned CPUs and stochastic loss;
the changes in individual profile throughput are not statistically reliable.
The saturated after-change LAN TCP sample also recorded 108 QUIC receive-queue
drops. This change does not establish elimination of overload or universal
performance gains.

## Expanded correctness and recovery coverage

`make test-robustness` includes:

- Cold start through clean, 10% random loss, 25% reverse loss, burst/reordered,
  jittered and approximately 600 ms RTT paths, each with FEC off and auto.
- An initially unavailable peer, short outages, outages longer than the test
  idle timeout, forward/reverse blackholes and repeated flapping.
- Mixed IPv4/IPv6 payloads, outer fragmentation, exact content verification and
  rejection of duplicate plaintext under loss and reordering.
- Concurrent connection establishment, routing isolation, shutdown, admission
  pressure recovery, and event-history wrapping.

The Go tests use real WireGuard/QUIC and an in-memory TUN behind a seeded UDP
fault proxy. Some recovery tests shorten local timeouts to keep CI bounded.
Their timings must not be substituted for production-timeout measurements.
Extended fault tests honor `-short`; the ordinary full suite executes them.

`make benchmark-robustness` adds real-TUN saturated TCP scenarios for reverse
ACK starvation, burst loss, short and long outages, both one-way outages,
repeated capacity drops and flapping. It requires at least 30 seconds per
trial to include the final restoration. Iperf completion and average goodput
alone do not prove that every intermediate recovery succeeded.
All eight added 35-second trials completed successfully; the raw rows are in
[`robustness.csv`](benchmarks/2026-10-structure/robustness.csv).

`make test-recovery` supplies that stronger gate. It runs for 180 seconds
without restarting the tunnel, using production timeouts, one CPU and 512 MiB
per endpoint, and a 192 MiB Go soft memory limit. The echo client compares
every byte in both directions, allowing application sockets to reconnect.
The analyzer requires new verified delivery in every clean interval after a
fault, rather than only at the end. It records actual fault timestamps,
pre-replacement qdisc counters, status samples and executable hashes.

The final run verified **23,068,672 bytes per direction**. Its recovery upper
bounds, sampled once per second, were:

| Fault cleared | Verified-delivery recovery upper bound |
| --- | ---: |
| Burst loss | 1.917 s |
| 20-second forward blackhole | 7.205 s |
| 20-second reverse blackhole | 1.484 s |
| 1→50 Mbit/s restoration | 0.649 s |
| 20-second bidirectional blackhole | 0.851 s |

The longest delivery gap, including an intentional outage, was 27.49 seconds.
There were 34 expected application socket errors and five application TCP
connections. A successful QUIC connection is never used as a substitute for
verified inner-packet delivery.

## Validation and limits

Passed: full `go test ./...`, full `go test -race ./...`, independent Rust
protocol interoperability, existing privileged container interoperability
(including IPv4/IPv6, MTU, DNS/routes, NAT rebinding, peer restart and runtime
peer changes), dependency-boundary checks, bind vet checks, ShellCheck and
recovery-analyzer unit tests. Windows/amd64 and FreeBSD/amd64 bind test
binaries cross-compile; this session did not run those operating systems.

The Linux CI container job now runs checked recovery and uploads its evidence.
Separate result/config directories and configurable outer subnets allow
fixtures to avoid collisions with existing Docker networks.

These finite runs do not establish multi-day leak freedom or a maximum
supported peer count. Asymmetric outages can still take several seconds to
recover under production timers. A peer coming online after an initial
failure can also wait roughly five seconds for WireGuard handshake retry.
Neither behavior is hidden by changing default timeout or encryption policy.
