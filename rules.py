import json
import os
import re
import subprocess
import tempfile

from models import (
    ACTIONS,
    DURATIONS,
    OPERANDS,
    OPERATOR_TYPES,
    RULECTL,
    Operator,
    Rule,
    RuleMatch,
)

SUDOERS_HINT = (
    f"Reading the rules needs one sudoers line:\n"
    f"  <user> ALL=(root) NOPASSWD: {RULECTL} dump\n"
    f"Install it as /etc/sudoers.d/opensnitch-rulectl and check it with visudo -c."
)


class RulectlError(Exception):
    pass


def _run(argv: list[str], env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)
    if result.returncode != 0:
        raise RulectlError((result.stderr or result.stdout).strip())
    return result.stdout


def _parse_operator(raw: dict) -> Operator:
    return Operator(
        operand=str(raw.get("operand", "")),
        type=str(raw.get("type", "")),
        data=str(raw.get("data", "")),
        sensitive=bool(raw.get("sensitive", False)),
        sub=[_parse_operator(s) for s in raw.get("list") or []],
    )


def _parse_rule(raw: dict) -> Rule:
    return Rule(
        name=str(raw.get("name", raw.get("file", ""))),
        action=str(raw.get("action", "")),
        duration=str(raw.get("duration", "")),
        enabled=bool(raw.get("enabled", True)),
        precedence=bool(raw.get("precedence", False)),
        operator=_parse_operator(raw.get("operator") or {}),
        description=str(raw.get("description", "")),
    )


def dump() -> tuple[dict, list[Rule]]:
    try:
        raw = json.loads(_run(["sudo", "-n", RULECTL, "dump"]))
    except RulectlError as error:
        raise RulectlError(f"{error}\n\n{SUDOERS_HINT}") from error
    return raw.get("config", {}), [_parse_rule(r) for r in raw.get("rules", [])]


def matches(operator: Operator, value: str) -> bool:
    data = operator.data
    if not operator.sensitive:
        data = data.lower()
        value = value.lower()
    if operator.type == "simple":
        return data == value
    if operator.type == "regexp":
        try:
            return re.search(data, value) is not None
        except re.error:
            return False
    return False


def match_path(rules: list[Rule], path: str) -> list[RuleMatch]:
    found = []
    for rule in rules:
        if not rule.enabled:
            continue
        operator = rule.operator
        if operator.operand == "process.path" and matches(operator, path):
            found.append(RuleMatch(rule=rule, matched_on="process.path"))
            continue
        for sub in operator.sub:
            if sub.operand == "process.path" and matches(sub, path):
                found.append(RuleMatch(rule=rule, matched_on="process.path (one condition of a list rule; the other conditions still have to hold)"))
                break
    return found


def build(
    name: str,
    action: str,
    operand: str,
    data: str,
    operator_type: str,
    duration: str,
    description: str,
    precedence: bool,
) -> dict:
    if action not in ACTIONS:
        raise RulectlError(f"action must be one of {list(ACTIONS)}")
    if duration not in DURATIONS:
        raise RulectlError(f"duration must be one of {list(DURATIONS)}")
    if operator_type not in OPERATOR_TYPES:
        raise RulectlError(f"operator type must be one of {list(OPERATOR_TYPES)}")
    if operand not in OPERANDS and not operand.startswith("process.env."):
        raise RulectlError(f"unknown operand {operand!r}; expected one of {list(OPERANDS)}")
    if operator_type == "regexp":
        try:
            re.compile(data)
        except re.error as error:
            raise RulectlError(f"{data!r} is not a valid regular expression: {error}") from error
    return {
        "name": name,
        "description": description,
        "action": action,
        "duration": duration,
        "enabled": True,
        "precedence": precedence,
        "nolog": False,
        "operator": {
            "operand": operand,
            "type": operator_type,
            "data": data,
            "list": [],
            "sensitive": False,
        },
    }


def install(rule: dict, force: bool) -> str:
    env = dict(os.environ)
    env.setdefault("SUDO_ASKPASS", "/usr/local/bin/claude-askpass")
    handle, temp = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(handle, "w") as out:
            json.dump(rule, out)
        os.chmod(temp, 0o644)
        argv = ["sudo", "-A", RULECTL, "add", temp]
        if force:
            argv.append("--force")
        return _run(argv, env=env).strip()
    finally:
        os.unlink(temp)
