from copy import deepcopy

import pytest
import yaml
from sentinelforge.config import ROOT
from sentinelforge.rules import Condition, Rule, selection_match


@pytest.mark.parametrize(
    "expression",
    [
        "selection or missing",
        "1 of selection*",
        "selection | count() > 5",
        "selection and (selection",
        "__import__(os)",
    ],
)
def test_fail_closed_conditions(expression):
    with pytest.raises(ValueError):
        Condition(expression, {"selection"})


def test_boolean_precedence_and_modifiers():
    condition = Condition("a and not b or (c and b)", {"a", "b", "c"})
    assert condition.matches({"a": True, "b": False, "c": False})
    assert not condition.matches({"a": True, "b": True, "c": False})
    assert selection_match({"command|contains|all": ["ONE", "two"]}, {"command": "one and two"})
    assert not selection_match({"command|contains|all": ["one", "two"]}, {"command": "one"})
    assert selection_match({"process|endswith": "\\PowerShell.exe"}, {"process": "C:\\powershell.exe"})
    assert selection_match({"user": None}, {"user": None})


def test_unsupported_modifier_is_rejected():
    rule = deepcopy(yaml.safe_load((ROOT / "rules/scheduled-task.yml").read_text()))
    rule["detection"]["selection"] = {"command|re": ".*"}
    with pytest.raises(ValueError, match="modifier"):
        Rule(rule)
