#!/usr/bin/env bash
set -euo pipefail

# Real TUN, production timeout policy, and byte-checked traffic across multiple
# failures in one process lifetime. All network changes are inside owned containers.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
benchmark_dir="$repo_dir/tests/benchmark"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-wgq-recovery-$$}
export WGQ_BENCH_SUBNET=${WGQ_BENCH_SUBNET:-172.40.0.0/24}
export WGQ_BENCH_OUTER_A=${WGQ_BENCH_OUTER_A:-172.40.0.2}
export WGQ_BENCH_OUTER_B=${WGQ_BENCH_OUTER_B:-172.40.0.3}
export WGQ_BENCH_CPUS=${WGQ_BENCH_CPUS:-1}
export WGQ_BENCH_MEMORY=${WGQ_BENCH_MEMORY:-512m}
export WGQ_BENCH_GOMAXPROCS=${WGQ_BENCH_GOMAXPROCS:-2}
export WGQ_BENCH_GOMEMLIMIT=${WGQ_BENCH_GOMEMLIMIT:-192MiB}
export WGQ_BENCH_DISABLE_OFFLOADS=1
export RESULTS_DIR=${RESULTS_DIR:-"$benchmark_dir/results"}
export RUN_ID=${RUN_ID:-"recovery-$(date -u +%Y%m%dT%H%M%SZ)"}
result_dir="$RESULTS_DIR/$RUN_ID"
export WGQ_BENCH_CONFIG_DIR=${WGQ_BENCH_CONFIG_DIR:-"$result_dir/config"}
compose=(docker compose -p "$COMPOSE_PROJECT_NAME" -f "$benchmark_dir/compose.yaml")
client_pid=
sampler_pid=

cleanup() {
	local code=$?
	trap - EXIT INT TERM
	for pid in "$client_pid" "$sampler_pid"; do
		if [[ -n $pid ]]; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
	"${compose[@]}" logs >"$result_dir/containers.log" 2>&1 || true
	"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	if ((code != 0)); then
		printf 'exit=%s\n' "$code" >"$result_dir/INCOMPLETE"
	fi
	exit "$code"
}

if [[ -e $result_dir ]]; then
	echo "choose a fresh RUN_ID; results already exist: $result_dir" >&2
	exit 1
fi
mkdir -p "$result_dir"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Reuse configuration, packaging and readiness checks from the throughput fixture.
MODE=fec-obfs WORKLOAD=tcp LINK_PROFILE=lan DURATION=1 DISABLE_OFFLOADS=1 \
	MEASURE_OUTER=0 "$benchmark_dir/run.sh" trial >"$result_dir/setup.log" 2>&1
CGO_ENABLED=0 go build -trimpath -o "$result_dir/soak-probe" "$repo_dir/tests/network/soak-probe"
for peer in a b; do
	"${compose[@]}" cp "$result_dir/soak-probe" "$peer:/tmp/soak-probe"
	"${compose[@]}" exec -T "$peer" wg-quic show wg0 --json >"$result_dir/status-$peer-before.json"
done
sha256sum "$benchmark_dir/build/wg-quic" "$benchmark_dir/build/wg-quic-quick" \
	"$result_dir/soak-probe" >"$result_dir/SHA256SUMS"
"${compose[@]}" exec -d b /tmp/soak-probe -listen 10.88.0.2:5202
for _ in $(seq 1 50); do
	if "${compose[@]}" exec -T b sh -c 'ss -H -ltn "sport = :5202" | grep -q LISTEN'; then
		break
	fi
	sleep 0.1
done
"${compose[@]}" exec -T b sh -c 'ss -H -ltn "sport = :5202" | grep -q LISTEN'

(
	while :; do
		for peer in a b; do
			"${compose[@]}" exec -T "$peer" wg-quic show wg0 --json |
				jq -c --arg utc "$(date -u +%FT%TZ)" '. + {sample_utc: $utc}' >>"$result_dir/status-$peer.ndjson"
		done
		sleep 2
	done
) >"$result_dir/sampler.log" 2>&1 &
sampler_pid=$!

"${compose[@]}" exec -T a /tmp/soak-probe -connect 10.88.0.2:5202 \
	-duration 180s -bytes-per-second 262144 >"$result_dir/traffic.ndjson" 2>"$result_dir/traffic-errors.log" &
client_pid=$!
started=$SECONDS
printf '%s\n' 'elapsed_s,utc,phase' >"$result_dir/phases.csv"

phase() {
	local at=$1 name=$2
	local remaining=$((at - (SECONDS - started)))
	if ((remaining > 0)); then sleep "$remaining"; fi
	# Capture counters BEFORE replacing the qdisc; replacement resets them.
	for peer in a b; do
		"${compose[@]}" exec -T "$peer" tc -s qdisc show dev eth0 >"$result_dir/tc-$at-$peer.txt"
	done
	case "$name" in
	clean)
		for peer in a b; do
			"${compose[@]}" exec -T "$peer" tc qdisc replace dev eth0 root netem delay 10ms rate 50mbit limit 128
		done
		;;
	burst)
		for peer in a b; do
			"${compose[@]}" exec -T "$peer" tc qdisc replace dev eth0 root netem delay 20ms 8ms \
				loss gemodel 0.6579% 12.5% 100% 0% rate 50mbit limit 128
		done
		;;
	forward-blackhole)
		"${compose[@]}" exec -T a tc qdisc replace dev eth0 root netem loss 100%
		;;
	reverse-blackhole)
		"${compose[@]}" exec -T b tc qdisc replace dev eth0 root netem loss 100%
		;;
	slow)
		for peer in a b; do
			"${compose[@]}" exec -T "$peer" tc qdisc replace dev eth0 root netem delay 20ms rate 1mbit limit 32
		done
		;;
	blackhole)
		for peer in a b; do
			"${compose[@]}" exec -T "$peer" tc qdisc replace dev eth0 root netem loss 100%
		done
		;;
	esac
	printf '%s,%s,%s\n' "$((SECONDS - started))" "$(date -u +%FT%T.%NZ)" "$name" >>"$result_dir/phases.csv"
}

phase 0 clean
phase 10 burst
phase 25 clean
phase 35 forward-blackhole
phase 55 clean
phase 70 reverse-blackhole
phase 90 clean
phase 105 slow
phase 120 clean
phase 135 blackhole
phase 155 clean
wait "$client_pid"
client_pid=
for peer in a b; do
	"${compose[@]}" exec -T "$peer" wg-quic show wg0 --json >"$result_dir/status-$peer-after.json"
done
python3 "$script_dir/analyze-recovery.py" "$result_dir"
touch "$result_dir/COMPLETE"
echo "checked recovery results: $result_dir"
