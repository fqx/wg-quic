#!/usr/bin/env python3
"""Validate every clean interval against receiver-verified traffic samples."""

import argparse
import csv
import datetime
import json
from pathlib import Path


def timestamp(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def analyze(phases, samples):
    if not phases or not samples or samples[-1].get("final") is not True:
        raise ValueError("missing phases or final traffic sample")
    times = [timestamp(row["utc"]) for row in samples]
    counters = [int(row["verified_bytes_per_direction"]) for row in samples]
    if any(b < a for a, b in zip(times, times[1:])):
        raise ValueError("traffic sample timestamps moved backwards")
    if any(b < a for a, b in zip(counters, counters[1:])):
        raise ValueError("verified byte counter reset during the trial")
    if counters[-1] == 0:
        raise ValueError("no verified traffic")
    if samples[-1]["seconds_since_delivery"] > 5:
        raise ValueError("no delivery in the final five seconds")
    results = []
    for i, phase in enumerate(phases):
        if phase["phase"] != "clean":
            continue
        start = timestamp(phase["utc"])
        end = timestamp(phases[i + 1]["utc"]) if i + 1 < len(phases) else times[-1]
        previous = 0
        for when, count in zip(times, counters):
            if when <= start:
                previous = count
        delivery = next(
            ((when, count) for when, count in zip(times, counters)
             if start < when <= end and count > previous),
            None,
        )
        if delivery is None:
            raise ValueError(f"no verified recovery after phase {i}: {phases[max(0, i-1)]['phase']}")
        results.append({
            "after": "startup" if i == 0 else phases[i - 1]["phase"],
            # One-second sampling gives an upper bound, not packet resolution.
            "recovery_upper_bound_seconds": round(delivery[0] - start, 3),
        })
    if not results:
        raise ValueError("no clean recovery interval was recorded")
    return {
        "verified_bytes_per_direction": counters[-1],
        "longest_delivery_gap_seconds": samples[-1]["longest_delivery_gap_seconds"],
        "application_connections": samples[-1]["connections"],
        "application_socket_errors": samples[-1]["socket_errors"],
        "recoveries": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    with (args.directory / "phases.csv").open() as source:
        phases = list(csv.DictReader(source))
    with (args.directory / "traffic.ndjson").open() as source:
        samples = [json.loads(line) for line in source if line.strip()]
    result = analyze(phases, samples)
    (args.directory / "recovery.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
