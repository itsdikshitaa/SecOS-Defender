from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RulePack


logger = logging.getLogger(__name__)


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


def _tokenize_condition(expression: str) -> list[str]:
    """Tokenize a boolean expression into tokens."""
    tokens: list[str] = []
    i = 0
    while i < len(expression):
        char = expression[i]
        if char.isspace():
            i += 1
            continue
        if char in "()":
            tokens.append(char)
            i += 1
            continue
        # Match multi-character tokens
        if expression[i:].startswith("True"):
            tokens.append("True")
            i += 4
        elif expression[i:].startswith("False"):
            tokens.append("False")
            i += 5
        elif expression[i:].startswith("and"):
            tokens.append("and")
            i += 3
        elif expression[i:].startswith("or"):
            tokens.append("or")
            i += 2
        elif expression[i:].startswith("not"):
            tokens.append("not")
            i += 3
        else:
            raise ValueError(f"Unexpected character in condition: {expression[i:]}")
    return tokens


def _parse_or(tokens: list[str], pos: int) -> tuple[bool, int]:
    """Parse OR expression (lowest precedence)."""
    left, pos = _parse_and(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "or":
        right, pos = _parse_and(tokens, pos + 1)
        left = left or right
    return left, pos


def _parse_and(tokens: list[str], pos: int) -> tuple[bool, int]:
    """Parse AND expression (medium precedence)."""
    left, pos = _parse_not(tokens, pos)
    while pos < len(tokens) and tokens[pos] == "and":
        right, pos = _parse_not(tokens, pos + 1)
        left = left and right
    return left, pos


def _parse_not(tokens: list[str], pos: int) -> tuple[bool, int]:
    """Parse NOT expression (highest precedence)."""
    if pos < len(tokens) and tokens[pos] == "not":
        value, pos = _parse_not(tokens, pos + 1)
        return not value, pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens: list[str], pos: int) -> tuple[bool, int]:
    """Parse an atomic value: True, False, or a parenthesized expression."""
    if pos >= len(tokens):
        raise ValueError("Unexpected end of condition")
    token = tokens[pos]
    if token == "True":
        return True, pos + 1
    if token == "False":
        return False, pos + 1
    if token == "(":
        value, pos = _parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ValueError("Missing closing parenthesis")
        return value, pos + 1
    raise ValueError(f"Unexpected token: {token}")


def _eval_condition(condition: str, states: dict[str, bool]) -> bool:
    """
    Safely evaluate a boolean condition string against provided states.
    Uses a recursive descent parser instead of eval() to avoid RCE vulnerabilities.
    """
    # Replace state names with boolean string representations
    expression = condition
    for name in sorted(states, key=len, reverse=True):
        expression = re.sub(rf"\b{re.escape(name)}\b", str(states[name]), expression)

    # Tokenize and parse the expression safely
    try:
        tokens = _tokenize_condition(expression)
        result, pos = _parse_or(tokens, 0)
        if pos != len(tokens):
            raise ValueError(f"Unexpected tokens after expression: {tokens[pos:]}")
        return result
    except ValueError as e:
        raise ValueError(f"Invalid condition '{condition}': {e}")


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
            try:
                with path.open("r", encoding="utf-8") as handle:
                    parsed = yaml.safe_load(handle)
                if parsed is None:
                    logger.warning("Skipping empty rule file: %s", path)
                elif not isinstance(parsed, dict):
                    logger.warning("Skipping malformed rule file (not a mapping): %s", path)
                else:
                    self.rules.append(parsed)
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
                logger.error("Failed to load rule file %s: %s", path, e)
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
            pack.content for pack in db.scalars(select(RulePack).where(RulePack.enabled)).all()
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
