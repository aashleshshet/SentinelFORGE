"""Fail-closed evaluator for a deliberately bounded Sigma field/condition subset."""

import fnmatch
import re
from pathlib import Path
from uuid import UUID

import yaml

FIELDS = {
    "kind",
    "source",
    "outcome",
    "process",
    "command",
    "parent",
    "user",
    "host",
    "src_ip",
    "dst_ip",
    "dst_port",
}
MODIFIERS = {"contains", "startswith", "endswith", "all"}


def field_value(event, field):
    if field.startswith("fields."):
        return event.get("fields", {}).get(field[7:])
    return event.get(field)


def selection_match(selection, event):
    for expression, expected in selection.items():
        field, *modifiers = expression.split("|")
        actual = field_value(event, field)
        values = expected if isinstance(expected, list) else [expected]
        results = []
        for value in values:
            if value is None or actual is None:
                result = value is None and actual is None
            elif "contains" in modifiers:
                result = str(value).casefold() in str(actual).casefold()
            elif "startswith" in modifiers:
                result = str(actual).casefold().startswith(str(value).casefold())
            elif "endswith" in modifiers:
                result = str(actual).casefold().endswith(str(value).casefold())
            else:
                # Only * and ? wildcards are accepted; square bracket syntax is rejected at load.
                result = fnmatch.fnmatchcase(str(actual).casefold(), str(value).casefold())
            results.append(result)
        if not (all(results) if "all" in modifiers else any(results)):
            return False
    return True


class Condition:
    def __init__(self, expression, names):
        if not isinstance(expression, str) or not re.fullmatch(r"[A-Za-z0-9_()\s]+", expression):
            raise ValueError("unsupported Sigma condition syntax")
        self.tokens = re.findall(r"\w+|[()]", expression)
        self.pos, self.names = 0, names
        self.tree = self.parse_or()
        if self.pos != len(self.tokens):
            raise ValueError("unsupported trailing Sigma condition")

    def accept(self, token):
        if self.pos < len(self.tokens) and self.tokens[self.pos] == token:
            self.pos += 1
            return True
        return False

    def parse_or(self):
        node = self.parse_and()
        while self.accept("or"):
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.atom()
        while self.accept("and"):
            node = ("and", node, self.atom())
        return node

    def atom(self):
        if self.accept("not"):
            return ("not", self.atom())
        if self.accept("("):
            node = self.parse_or()
            if not self.accept(")"):
                raise ValueError("unclosed Sigma condition")
            return node
        if self.pos >= len(self.tokens) or self.tokens[self.pos] not in self.names:
            raise ValueError("unknown selection in Sigma condition")
        name = self.tokens[self.pos]
        self.pos += 1
        return ("selection", name)

    def matches(self, selections):
        def visit(node):
            match node[0]:
                case "selection":
                    return selections[node[1]]
                case "not":
                    return not visit(node[1])
                case "and":
                    return visit(node[1]) and visit(node[2])
                case "or":
                    return visit(node[1]) or visit(node[2])

        return visit(self.tree)


class Rule:
    def __init__(self, data):
        if not isinstance(data, dict):
            raise ValueError("rule must be a mapping")
        self.meta = data
        for key in (
            "id",
            "title",
            "status",
            "logsource",
            "detection",
            "level",
            "tags",
            "falsepositives",
            "x-sentinelforge",
        ):
            if key not in data:
                raise ValueError(f"rule missing {key}")
        if data["level"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("unsupported severity")
        try:
            UUID(data["id"])
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("rule ID must be a UUID") from error
        if not isinstance(data["detection"], dict) or "condition" not in data["detection"]:
            raise ValueError("rule detection must include a condition")
        self.selections = {k: v for k, v in data["detection"].items() if k != "condition"}
        for selection in self.selections.values():
            if not isinstance(selection, dict) or not selection:
                raise ValueError("only nonempty Sigma dictionary selections are supported")
            for expression, value in selection.items():
                field, *mods = expression.split("|")
                if field not in FIELDS and not re.fullmatch(r"fields\.[a-zA-Z_]+", field):
                    raise ValueError(f"unsupported field {field}")
                if set(mods) - MODIFIERS or len(set(mods) & {"contains", "startswith", "endswith"}) > 1:
                    raise ValueError(f"unsupported modifier in {expression}")
                values = value if isinstance(value, list) else [value]
                if not values or any(isinstance(v, (dict, list)) for v in values):
                    raise ValueError("invalid selection value")
                if any(isinstance(v, str) and ("[" in v or "]" in v) for v in values) and not mods:
                    raise ValueError("bracket wildcard expressions are unsupported")
        self.condition = Condition(data["detection"]["condition"], set(self.selections))
        self.id = data["id"]
        self.techniques = [
            tag.removeprefix("attack.").upper()
            for tag in data["tags"]
            if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag)
        ]
        self.extension = data["x-sentinelforge"]
        required = {"slug", "confidence", "required_telemetry", "validation", "explanation"}
        if not isinstance(self.extension, dict) or not required <= self.extension.keys():
            raise ValueError("missing required rule extension fields")
        if self.extension.keys() - required - {"aggregate"}:
            raise ValueError("unsupported rule extension")
        confidence = self.extension["confidence"]
        if type(confidence) is not int or not 0 <= confidence <= 100:
            raise ValueError("confidence must be an integer from 0 to 100")
        telemetry = self.extension["required_telemetry"]
        if (
            not isinstance(telemetry, list)
            or not telemetry
            or not all(isinstance(v, str) and v for v in telemetry)
        ):
            raise ValueError("required_telemetry must be a nonempty string list")
        if not self.techniques:
            raise ValueError("at least one valid ATT&CK technique is required")
        for key in ("slug", "validation", "explanation"):
            if not isinstance(self.extension[key], str) or not self.extension[key].strip():
                raise ValueError("rule extension strings must be nonempty")
        aggregate = self.extension.get("aggregate")
        if "aggregate" in self.extension and aggregate != {
            "count": 5,
            "seconds": 300,
            "group_by": ["host", "src_ip"],
        }:
            raise ValueError("only the documented SSH aggregation is supported")

    def matches(self, event):
        return self.condition.matches(
            {name: selection_match(value, event) for name, value in self.selections.items()}
        )


def load_rules(path: Path):
    rules = [Rule(yaml.safe_load(file.read_text())) for file in sorted(path.glob("*.yml"))]
    if not rules or len({r.id for r in rules}) != len(rules):
        raise ValueError("rules must be nonempty with unique IDs")
    return rules
