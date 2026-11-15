"""Pure measurement helpers: labels are used here, never as detector inputs."""

import hashlib
import json
import math
from collections import defaultdict

METRICS = ("precision", "recall", "accuracy", "false_positive_rate")


def classify(label, predicted):
    if type(label) is not bool or type(predicted) is not bool:
        return "ERROR"
    return ("TP" if predicted else "FN") if label else ("FP" if predicted else "TN")


def wilson_interval(successes, trials):
    """Two-sided nominal 95% Wilson score interval, not a population guarantee."""
    result = {
        "method": "Wilson score, two-sided 95%",
        "successes": successes,
        "trials": trials,
        "lower": None,
        "upper": None,
    }
    if not trials:
        return result
    if not 0 <= successes <= trials:
        raise ValueError("binomial successes must be between zero and trials")
    z = 1.959963984540054
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    result.update(
        lower=0.0 if successes == 0 else max(0.0, center - half),
        upper=1.0 if successes == trials else min(1.0, center + half),
    )
    return result


def summarize(outcomes):
    """Keep unclassifiable observations in denominators and invalidate headline metrics."""
    categories = [classify(o.get("label"), o.get("alerted")) for o in outcomes]
    counts = {key: categories.count(key) for key in ("TP", "FP", "TN", "FN")}
    tp, fp, tn, fn = (counts[key] for key in ("TP", "FP", "TN", "FN"))
    errors = categories.count("ERROR")
    total = len(outcomes)
    positive = sum(o.get("label") is True for o in outcomes)
    negative = sum(o.get("label") is False for o in outcomes)
    fractions = {
        "precision": (tp, tp + fp),
        "recall": (tp, positive),
        "accuracy": (tp + tn, total),
        "false_positive_rate": (fp, negative),
    }
    result = {
        "confusion_matrix": counts,
        "denominators": {
            "total": total,
            "positive": positive,
            "negative": negative,
            "predicted_positive": tp + fp,
            "classified": total - errors,
            "errors": errors,
        },
        "prevalence": positive / total if total else None,
        "classification_coverage": (total - errors) / total if total else None,
    }
    result.update({name: n / d if d and not errors else None for name, (n, d) in fractions.items()})
    result["uncertainty"] = {
        "interpretation": "Nominal binomial intervals describe this experiment only. Synthetic template variants "
        "are not independent population samples; no deployment efficacy or population FPR claim follows.",
        "intervals": {
            name: wilson_interval(n, d)
            if not errors
            else {
                "method": "Wilson score, two-sided 95%",
                "successes": n,
                "trials": d,
                "lower": None,
                "upper": None,
                "unavailable_reason": "unclassified/error observations",
            }
            for name, (n, d) in fractions.items()
        },
    }
    return result


def target_status(report):
    def available(value):
        return type(value) in (float, int) and math.isfinite(value)

    checks = {}
    for metric in METRICS:
        value = report.get(metric)
        less = metric == "false_positive_rate"
        threshold = 0.05 if less else 0.90
        checks[metric] = {
            "value": value if available(value) else None,
            "operator": "<" if less else ">",
            "threshold": threshold,
            "passed": available(value) and (value < threshold if less else value > threshold),
        }
    return {
        "passed": all(check["passed"] for check in checks.values()),
        "checks": checks,
        "basis": "Unrounded point estimates; separate from uncertainty and external validity",
    }


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def input_audit(scenarios):
    """Audit identical submitted sequences plus explicitly provisioned operator context.

    Scenario metadata, labels and expected rules are deliberately absent from the key.
    Ordering within an event sequence matters; each scenario starts with identical fresh state.
    """
    groups = defaultdict(list)
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict) or type(scenario.get("suspicious")) is not bool:
            continue
        key = canonical_hash({"events": scenario.get("events"), "context": scenario.get("context", {})})
        groups[key].append({"id": scenario.get("id", f"row-{index}"), "label": scenario["suspicious"]})
    duplicates, contradictions = [], []
    unavoidable = 0
    for key, members in sorted(groups.items()):
        if len(members) > 1:
            group = {"input_sha256": key, "members": members}
            duplicates.append(group)
            positives = sum(member["label"] for member in members)
            negatives = len(members) - positives
            if positives and negatives:
                errors = min(positives, negatives)
                unavoidable += errors
                contradictions.append({**group, "minimum_errors": errors})
    return {
        "input_key": "Canonical submitted event sequence and operator context, excluding scenario metadata",
        "duplicate_groups": duplicates,
        "contradictions": contradictions,
        "minimum_unavoidable_errors": unavoidable,
        "accuracy_upper_bound": (len(scenarios) - unavoidable) / len(scenarios) if scenarios else None,
        "assumptions": "Deterministic detector, identical initial state and fixed processing clock; upper bound only",
    }
