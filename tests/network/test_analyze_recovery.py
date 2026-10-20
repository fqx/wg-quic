import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "recovery", Path(__file__).with_name("analyze-recovery.py")
)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def sample(second, count, final=False):
    return {
        "utc": f"2026-10-20T00:00:{second:02d}Z",
        "verified_bytes_per_direction": count, "final": final,
        "seconds_since_delivery": 0, "longest_delivery_gap_seconds": 3,
        "connections": 2, "socket_errors": 1,
    }


def phase(second, name):
    return {"utc": sample(second, 0)["utc"], "phase": name}


class RecoveryAnalysisTests(unittest.TestCase):
    def test_measures_delivery_after_each_fault(self):
        result = recovery.analyze(
            [phase(0, "clean"), phase(2, "blackhole"), phase(5, "clean")],
            [sample(1, 100), sample(3, 100), sample(6, 200), sample(8, 300, True)],
        )
        self.assertEqual(
            result["recoveries"],
            [{"after": "startup", "recovery_upper_bound_seconds": 1},
             {"after": "blackhole", "recovery_upper_bound_seconds": 1}],
        )

    def test_final_recovery_cannot_hide_failed_earlier_recovery(self):
        with self.assertRaisesRegex(ValueError, "no verified recovery"):
            recovery.analyze(
                [phase(0, "clean"), phase(2, "blackhole"), phase(4, "clean"),
                 phase(7, "blackhole"), phase(9, "clean")],
                [sample(1, 100), sample(5, 100), sample(6, 100), sample(10, 200, True)],
            )

    def test_rejects_partial_output_and_counter_resets(self):
        with self.assertRaisesRegex(ValueError, "final"):
            recovery.analyze([phase(0, "clean")], [sample(1, 100)])
        with self.assertRaisesRegex(ValueError, "counter reset"):
            recovery.analyze([phase(0, "clean")], [sample(1, 100), sample(2, 20, True)])


if __name__ == "__main__":
    unittest.main()
