"""Accounting and impossible-target regressions; runnable without application dependencies."""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("evaluation_metrics", ROOT / "scripts/evaluation_metrics.py")
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


class EvaluationMetricsTests(unittest.TestCase):
    def test_recorded_baseline(self):
        result = evaluation.metrics({"TP": 7, "FP": 2, "TN": 7, "FN": 2})
        self.assertAlmostEqual(result["accuracy"], 14 / 18)
        self.assertAlmostEqual(result["false_positive_rate"], 2 / 9)
        self.assertFalse(evaluation.target_status(result)["met"])

    def test_strict_boundaries(self):
        result = dict(precision=0.90, recall=0.90, accuracy=0.90, false_positive_rate=0.05)
        self.assertFalse(any(evaluation.target_status(result)["checks"].values()))
        result.update(precision=0.91, recall=0.91, accuracy=0.91, false_positive_rate=0.049)
        self.assertTrue(evaluation.target_status(result)["met"])

    def test_undefined_metrics_cannot_pass(self):
        result = evaluation.metrics(dict(TP=0, FP=0, TN=0, FN=0))
        self.assertTrue(all(value is None for value in result.values()))
        self.assertFalse(evaluation.target_status(result)["met"])
        self.assertIsNone(evaluation.metrics(dict(TP=0, FP=0, TN=9, FN=9))["precision"])

    def test_invalid_counts(self):
        for value in (-1, 0.5, True):
            with self.assertRaises(ValueError):
                evaluation.metrics(dict(TP=value, FP=0, TN=0, FN=0))

    def test_current_corpus_conflicts(self):
        scenarios = json.loads((ROOT / "data/evaluation.json").read_text())
        audit = evaluation.input_conflicts(scenarios)
        self.assertEqual(audit["unavoidable_errors"], 3)
        self.assertEqual(len(audit["conflicting_groups"]), 3)
        self.assertAlmostEqual(audit["accuracy_upper_bound"], 15 / 18)

    def test_key_order_does_not_hide_conflict(self):
        scenarios = [
            dict(id="a", suspicious=True, events=[dict(x=1, y=2)]),
            dict(id="b", suspicious=False, events=[dict(y=2, x=1)]),
        ]
        self.assertEqual(evaluation.input_conflicts(scenarios)["unavoidable_errors"], 1)
        self.assertIsNone(evaluation.input_conflicts([])["accuracy_upper_bound"])


if __name__ == "__main__":
    unittest.main()
