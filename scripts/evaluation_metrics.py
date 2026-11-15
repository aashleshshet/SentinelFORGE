"""Pure evaluation accounting; targets are goals, never substituted for observations."""

import json
from collections import defaultdict


def metrics(counts):
    tp, fp, tn, fn = (counts[k] for k in ("TP", "FP", "TN", "FN"))
    if any(type(value) is not int or value < 0 for value in (tp, fp, tn, fn)):
        raise ValueError("confusion counts must be nonnegative integers")

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return {
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "accuracy": ratio(tp + tn, tp + fp + tn + fn),
        "false_positive_rate": ratio(fp, fp + tn),
    }


def target_status(values):
    checks = {
        name: values[name] is not None and values[name] > 0.90 for name in ("precision", "recall", "accuracy")
    }
    fpr = values["false_positive_rate"]
    checks["false_positive_rate"] = fpr is not None and fpr < 0.05
    return {
        "criteria": "precision, recall, accuracy > 0.90; FPR < 0.05",
        "checks": checks,
        "met": all(checks.values()),
    }


def input_conflicts(scenarios):
    """Bound a deterministic classifier using only the submitted event sequences."""
    groups = defaultdict(list)
    for scenario in scenarios:
        groups[json.dumps(scenario["events"], sort_keys=True)].append(scenario)
    conflicts, unavoidable_errors = [], 0
    for group in groups.values():
        positive = [s["id"] for s in group if s["suspicious"]]
        negative = [s["id"] for s in group if not s["suspicious"]]
        if positive and negative:
            unavoidable_errors += min(len(positive), len(negative))
            conflicts.append({"suspicious": positive, "benign": negative})
    return {
        "scope": "deterministic prediction from submitted events only, with identical initial state",
        "conflicting_groups": conflicts,
        "unavoidable_errors": unavoidable_errors,
        "accuracy_upper_bound": (len(scenarios) - unavoidable_errors) / len(scenarios) if scenarios else None,
    }
