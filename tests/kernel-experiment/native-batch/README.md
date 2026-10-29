# Kernel UDP batch experiment

Run these tools only in an isolated Linux guest with iproute2, WireGuard, Python 3,
Go and root access. The scripts create two named network namespaces; never run
concurrently or reuse those names for other workloads. M4 is management/transfer only.

Copy this directory's scripts into /root/wg-quic-batch-experiment. The fixed root
keeps paths explicit. Binaries in its bin/ directory:
A-baseline (c1c02231..., TUN UDP USO disabled using the preserved oldtun overlay),
B-kernel-original (166d7e7...), C-kernel-batch (d570954... source),
and traffic (go build -o bin/traffic traffic.go). Reuse one identical toolchain,
GOMAXPROCS=1 and GOMEMLIMIT=192MiB for both endpoints of every arm.

C uses x/net ipv4.ReadBatch/WriteBatch with flags=0 on connected UDP sockets.
Go netpoll handles EAGAIN; recvmmsg drains ready packets without filling a batch.
Local batch maximum is 32. Successful partial send prefixes are never replayed.
Kernel buffers remain owned until synchronous Bind.Send has copied them.

Build C from the repository root:
CGO_ENABLED=0 go build -o /root/wg-quic-batch-experiment/bin/C-kernel-batch ./cmd/wg-quic-kernel-experiment

Ordinary and race checks:
go test -p 2 ./...
go test -race -p 2 ./internal/kernelrelay ./internal/bind ./cmd/wg-quic-kernel-experiment

Native checks (run from the experiment root):
python3 run_three.py --arch C --duration 8 --warmup 3 --label preflight
python3 run_three.py --arch C --badkey --label wrong-public-key
python3 run_three.py --arch C --badpsk --label wrong-psk
python3 run_three.py --arch C --impair --mbps 2 --duration 12 --warmup 5 --label loss-reorder

Important existing limitation: wrong PSK prevents a complete kernel handshake
and inner delivery, but the responder may set the prototype's authenticated
metric after a cryptographically valid initiation. That metric is not a full
handshake proof. Require nonzero kernel latest-handshake AND valid inner traffic
for all positive native trials. This batching patch deliberately preserves the
same authentication criterion as B; do not deploy as a general multiparty relay.

Trace only separate runs:
python3 run_three.py --arch B --trace --duration 6 --label syscall-proof
python3 run_three.py --arch C --trace --duration 6 --label syscall-proof

Trace uses raw arguments and attaches after keys are loaded; payload/private-key
bytes are not decoded. Match socket inodes from trace-fd-map.json to connected
127.0.0.1:51820 FDs. Include read/write as well as explicit UDP socket syscalls:
B uses connected-socket read/write; the first B trace omitted them and is invalid
for local syscall counts. Strace perturbs scheduling/loss; never use its CPU
numbers for performance conclusions. Relay batch telemetry counts successful API
batches, while syscall totals also include EAGAIN probes.

For formal runs, wait for explicit completion of host maintenance, record kernel,
binary hashes, guest resources and stable host background; remove the PAUSE
marker only after that condition is confirmed. Start a fresh bounded ESXi monitor
to host-metrics-batch-post.csv and run:
python3 suite.py
This executes 36 balanced trials, 10-second warmup + 60-second steady phases,
then all three arms at 180 seconds for 1424-byte / 16.667-ms confirmation.
SIGTERM/SIGINT unwinds trial cleanup. PAUSE stops between trials. --resume skips
only completed identical labels; environment changes require a fresh epoch/labels.

Copy the host CSV into the experiment root, then:
python3 analyze_three.py --phase post

Host % Used and % Run per delivered MB are the primary total-VM counters.
Guest schedstat runtime, context switches, process user/system/RSS and loss/latency
are corroborating data. Guest procstat CPU has known accounting discrepancies;
never use its percentages as a saving claim. Keep all failed/negative samples,
clock/window uncertainty and ESXi ready/background load.

Outputs remain in results/; secrets are owner-only files in /run and removed in
finally cleanup. The matrix interrupted for maintenance is historical pre-data,
not part of the new post-maintenance formal set. After final verification stop
monitors, remove temporary test processes/netns/keys and normally power off only
the dedicated test VM. Do not delete its source, disk or results.

## Final evidence collection

The 36 formal trials are followed by the planned 1424-byte burst confirmation.
A true negative 1200-byte burst sample was retained and independently confirmed
with one additional fixed-configuration B/C/A set of 180-second runs:
python3 additional_confirmation.py

Only after all CPU measurements finish, run four separate intrusive syscall checks:
python3 run_syscall_proofs.py
python3 analyze_syscalls.py

The analyzer verifies local connected-UDP FDs by inode and includes EAGAIN probes.
Instrumented tracing can increase batching and cause delivery loss; those runs
prove actual syscall use and are excluded from CPU comparisons. Normal batch
coverage comes from untraced formal relay counters.

The final host analysis also checks per-vCPU Run for sustained saturation, ready,
CoStop and swap. Analysis errors are preserved explicitly rather than silently
omitting trials. Raw source scripts and all negative samples remain in the
experiment evidence archive. No kernel or Go implementation changes were made
after the tested d570954 source commit.
