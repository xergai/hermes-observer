"""Gate assertion self-tests, not a substitute for actual pinned dispatch."""

import importlib.util
import unittest
from pathlib import Path


path = Path(__file__).resolve().parents[3] / "scripts/acceptance/hermes_dispatcher_assertions.py"
spec = importlib.util.spec_from_file_location("hermes_dispatcher_assertions_test", path)
assertions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assertions)


class DispatcherHarnessTest(unittest.TestCase):
    def test_reports_ledger_drop_deltas_not_absent_health_counters(self):
        events = [
            {"event_type": "ledger-status", "phase": "dropped-events", "dropped_event_count": 2},
            {"event_type": "ledger-status", "phase": "dropped-events", "dropped_event_count": 3},
            {"schema": "xerg.hermes.observer-health.v1", "state": "stopped", "dropped_event_count": 99},
            {"event_type": "lifecycle", "phase": "session-start", "dropped_event_count": 99},
        ]
        self.assertEqual(assertions.reported_writer_drops(events), 5)
        self.assertEqual(assertions.reported_writer_drops([]), 0)

    def test_all_ten_and_both_request_boundaries_remain_required(self):
        complete = {"subagent-start": 10, "subagent-stop": 10, "session-start": 10,
                    "subagent-running": 10, "api-request-start": 40, "api-request-end": 40}
        assertions.assert_lifecycle_delivery(complete)
        for phase in complete:
            with self.subTest(phase=phase), self.assertRaises(AssertionError):
                assertions.assert_lifecycle_delivery({**complete, phase: complete[phase] - 1})

    def test_missing_delivery_is_not_replaced_by_zero_or_a_matching_total(self):
        missing = {"subagent-start": 10, "subagent-stop": 10, "session-start": 0,
                   "subagent-running": 0, "api-request-start": 40, "api-request-end": 40}
        with self.assertRaisesRegex(AssertionError, "absence is not zero queue wait"):
            assertions.assert_lifecycle_delivery(missing)
