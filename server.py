#!/usr/bin/env python3
import subprocess
from dataclasses import asdict
from typing import Annotated

from fastmcp import FastMCP

import rules
import stats
from models import ACTIONS, DURATIONS, OPERANDS, OPERATOR_TYPES

mcp = FastMCP(
    "opensnitch",
    instructions=(
        "OpenSnitch is an application firewall that denies outbound connections "
        "by default. When a network call fails, hangs or resolves nothing, call "
        "recent_denies and check_process BEFORE debugging the code: a process "
        "with no rule is blocked silently. add_rule asks the user for their "
        "password, so never call it without telling them first."
    ),
)


def _tail(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


@mcp.tool()
def opensnitch_status() -> dict:
    daemon = _tail(["systemctl", "is-active", "opensnitchd"])
    ui_running = bool(_tail(["pgrep", "-f", "opensnitch-ui"]))
    database = stats.database_path()
    answer: dict = {
        "daemon": daemon,
        "ui_running": ui_running,
        "stats_database": str(database),
        "stats_database_present": database.exists(),
    }
    if not answer["stats_database_present"]:
        answer["stats_hint"] = stats.ENABLE_HINT
    try:
        config, ruleset = rules.dump()
    except rules.RulectlError as error:
        answer["rules_error"] = str(error)
        return answer
    answer["default_action"] = config.get("DefaultAction")
    answer["default_duration"] = config.get("DefaultDuration")
    answer["log_level"] = config.get("LogLevel")
    answer["rule_count"] = len(ruleset)
    answer["disabled_rules"] = sum(1 for rule in ruleset if not rule.enabled)
    return answer


@mcp.tool()
def list_rules(
    filter: Annotated[str, "Substring matched against the rule name, operand and data"] = "",
) -> dict:
    _, ruleset = rules.dump()
    needle = filter.lower()
    found = [
        asdict(rule)
        for rule in ruleset
        if not needle
        or needle in rule.name.lower()
        or needle in rule.operator.data.lower()
        or needle in rule.operator.operand.lower()
    ]
    return {"count": len(found), "rules": found}


@mcp.tool()
def check_process(
    path: Annotated[str, "Absolute path of the executable, as in /usr/bin/curl"],
) -> dict:
    config, ruleset = rules.dump()
    found = rules.match_path(ruleset, path)
    answer: dict = {
        "path": path,
        "matches": [
            {"matched_on": match.matched_on, **asdict(match.rule)} for match in found
        ],
    }
    if not found:
        answer["verdict"] = config.get("DefaultAction", "deny")
        answer["explanation"] = (
            "No rule covers this path, so DefaultAction applies. The daemon asks "
            "the UI, the popup times out after 20 seconds and the connection is "
            "dropped. This looks like a network error to the program."
        )
        return answer
    denies = [m for m in found if m.rule.action in ("deny", "reject")]
    precedence = [m for m in found if m.rule.precedence]
    if precedence:
        answer["verdict"] = precedence[0].rule.action
        answer["explanation"] = "A rule with precedence set wins over the others."
    elif denies:
        answer["verdict"] = denies[0].rule.action
        answer["explanation"] = "A deny rule matches, so the connection is dropped."
    else:
        answer["verdict"] = "allow"
    return answer


@mcp.tool()
def recent_denies(
    limit: Annotated[int, "How many connections to return, newest first"] = 20,
    process: Annotated[str, "Optional substring of the process path"] = "",
) -> dict:
    try:
        found = stats.denied(limit, process or None)
    except stats.StatsUnavailable as error:
        return {"available": False, "hint": str(error)}
    return {
        "available": True,
        "count": len(found),
        "connections": [asdict(connection) for connection in found],
    }


@mcp.tool()
def add_rule(
    name: Annotated[str, "File name of the rule, lowercase letters, digits, dot, dash, underscore"],
    action: Annotated[str, f"One of {list(ACTIONS)}"],
    data: Annotated[str, "Value to match, for example /usr/bin/curl or a regular expression"],
    operand: Annotated[str, f"What to match on, one of {list(OPERANDS)}"] = "process.path",
    operator_type: Annotated[str, f"One of {list(OPERATOR_TYPES)}"] = "simple",
    duration: Annotated[str, f"One of {list(DURATIONS)}"] = "always",
    description: Annotated[str, "Why the rule exists"] = "",
    precedence: Annotated[bool, "Check this rule before the others"] = False,
    force: Annotated[bool, "Replace a rule that already has this name"] = False,
) -> dict:
    try:
        rule = rules.build(
            name=name,
            action=action,
            operand=operand,
            data=data,
            operator_type=operator_type,
            duration=duration,
            description=description,
            precedence=precedence,
        )
        written = rules.install(rule, force)
    except rules.RulectlError as error:
        return {"installed": False, "error": str(error)}
    return {
        "installed": True,
        "file": written,
        "note": "The daemon watches the rules directory and reloads on its own.",
    }


if __name__ == "__main__":
    mcp.run()
