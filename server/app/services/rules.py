from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RulePack


def _get_nested(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _matches_operator(actual: Any, operator: str, expected: Any) -> bool:
    actual_text = "" if actual is None else str(actual)
    if operator == "eq":
        if isinstance(expected, list):
            return actual in expected
        return actual == expected
    if operator == "contains":
        return str(expected).lower() in actual_text.lower()
    if operator == "startswith":
        return actual_text.lower().startswith(str(expected).lower())
    if operator == "endswith":
        return actual_text.lower().endswith(str(expected).lower())
    if operator == "in":
        if isinstance(expected, list):
            return actual in expected or actual_text in [str(item) for item in expected]
        return actual_text == str(expected)
    if operator == "regex":
        return bool(re.search(str(expected), actual_text, re.IGNORECASE))
    raise ValueError(f"Unsupported operator: {operator}")


def _matches_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        if "|" in raw_key:
            key, operator = raw_key.split("|", 1)
        else:
            key, operator = raw_key, "eq"
        if not _matches_operator(_get_nested(event, key), operator, expected):
            return False
    return True


def _eval_condition(condition: str, states: dict[str, bool]) -> bool:
    expression = condition
    for name in sorted(states, key=len, reverse=True):
        expression = re.sub(rf"\b{re.escape(name)}\b", str(states[name]), expression)
    return bool(eval(expression, {"__builtins__": {}}, {}))


@dataclass
class RuleMatch:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: dict[str, Any]
    recommended_actions: list[str]


class RuleEngine:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self.rules: list[dict[str, Any]] = []

    def load_files(self) -> list[dict[str, Any]]:
        self.rules = []
        for path in sorted(self.rules_path.glob("*.yml")):
            with path.open("r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle)
            if parsed:
                self.rules.append(parsed)
        return self.rules

    def sync_rulepacks(self, db: Session) -> None:
        loaded = {rule["id"]: rule for rule in self.load_files()}
        existing = {pack.pack_id: pack for pack in db.scalars(select(RulePack)).all()}
        for rule_id, rule in loaded.items():
            pack = existing.get(rule_id)
            if pack:
                pack.version = rule.get("version", "1.0.0")
                pack.title = rule["title"]
                pack.status = rule.get("status", "stable")
                pack.content = rule
                pack.enabled = True
            else:
                db.add(
                    RulePack(
                        pack_id=rule_id,
                        version=rule.get("version", "1.0.0"),
                        title=rule["title"],
                        status=rule.get("status", "stable"),
                        content=rule,
                        enabled=True,
                    )
                )
        db.commit()
        self.rules = [
            pack.content for pack in db.scalars(select(RulePack).where(RulePack.enabled == True)).all()
        ]

    def evaluate(self, event: dict[str, Any]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            logsource = rule.get("logsource", {})
            if logsource.get("product") and logsource["product"] != event.get("platform"):
                continue
            if logsource.get("service") and logsource["service"] != event.get("source"):
                continue
            detection = rule.get("detection", {})
            states = {
                key: _matches_selection(event, value)
                for key, value in detection.items()
                if key != "condition"
            }
            condition = detection.get("condition")
            matched = bool(condition and _eval_condition(condition, states)) if condition else all(states.values())
            if matched:
                matches.append(
                    RuleMatch(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule.get("level", "medium"),
                        description=rule.get("description", ""),
                        evidence={
                            "event_type": event.get("event_type"),
                            "source": event.get("source"),
                            "process": event.get("process", {}),
                            "file": event.get("file", {}),
                            "network": event.get("network", {}),
                        },
                        recommended_actions=rule.get("responses", []),
                    )
                )
        return matches
