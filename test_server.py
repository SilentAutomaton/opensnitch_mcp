#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import rules
import stats
from models import Operator, Rule

HELPER = str(Path(__file__).parent / "opensnitch-rulectl")

TELEGRAM_RE = r"^/tmp/\.mount_telegr[a-z0-9]+/telegram$"


def rule(data: str, kind: str = "simple", sensitive: bool = False, **kwargs) -> Rule:
    return Rule(
        name=kwargs.get("name", "test"),
        action=kwargs.get("action", "allow"),
        duration="always",
        enabled=kwargs.get("enabled", True),
        precedence=kwargs.get("precedence", False),
        operator=Operator(operand="process.path", type=kind, data=data, sensitive=sensitive),
    )


def test_simple_matching() -> None:
    assert rules.matches(rule("/usr/bin/curl").operator, "/usr/bin/curl")
    assert rules.matches(rule("/opt/telegram/Telegram").operator, "/opt/telegram/telegram")
    assert not rules.matches(rule("/opt/telegram/Telegram", sensitive=True).operator, "/opt/telegram/telegram")
    assert not rules.matches(rule("/usr/bin/curl").operator, "/usr/bin/curl-wrapper")


def test_telegram_regexp() -> None:
    live = rule(TELEGRAM_RE, kind="regexp").operator
    assert rules.matches(live, "/tmp/.mount_telegremp112366525293743553/Telegram")
    assert rules.matches(live, "/tmp/.mount_telegremp8031436331828175100/Telegram")
    assert not rules.matches(live, "/opt/telegram/telegram")

    broken = rule(r"^/tmp/\.mount_telegr[0-9a-za-z]{6,7}\/.*telegram$", kind="regexp").operator
    assert not rules.matches(broken, "/tmp/.mount_telegremp112366525293743553/Telegram")


def test_disabled_rule_never_matches() -> None:
    ruleset = [rule("/usr/bin/curl", enabled=False)]
    assert rules.match_path(ruleset, "/usr/bin/curl") == []


def test_list_rule_matches_one_condition() -> None:
    listed = rule("", kind="list")
    listed.operator.sub = [
        Operator(operand="process.path", type="simple", data="/usr/bin/curl"),
        Operator(operand="dest.port", type="simple", data="443"),
    ]
    found = rules.match_path([listed], "/usr/bin/curl")
    assert len(found) == 1
    assert "one condition" in found[0].matched_on


def test_build_rejects_bad_input() -> None:
    for bad in (
        dict(action="drop"),
        dict(duration="forever"),
        dict(operand="process.parent"),
        dict(operator_type="regexp", data="["),
    ):
        argument = dict(
            name="t", action="allow", operand="process.path", data="/usr/bin/curl",
            operator_type="simple", duration="always", description="", precedence=False,
        )
        argument.update(bad)
        try:
            rules.build(**argument)
        except rules.RulectlError:
            continue
        raise AssertionError(f"build accepted {bad}")


def run_helper(rule_body: dict) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(rule_body, handle)
    return subprocess.run([sys.executable, HELPER, "add", handle.name], capture_output=True, text=True)


def test_helper_rejects_traversal_and_unknown_operand() -> None:
    body = {
        "name": "../../etc/cron.d/evil",
        "action": "allow",
        "duration": "always",
        "operator": {"operand": "process.path", "type": "simple", "data": "/usr/bin/curl"},
    }
    assert run_helper(body).returncode == 1

    body["name"] = "fine-name"
    body["operator"]["operand"] = "process.parent"
    assert run_helper(body).returncode == 1


def test_stats_path_override() -> None:
    os.environ["OPENSNITCH_STATS_DB"] = "/tmp/does-not-exist.db"
    assert str(stats.database_path()) == "/tmp/does-not-exist.db"
    del os.environ["OPENSNITCH_STATS_DB"]
    assert stats.database_path().name == "stats.db"


for name, test in sorted(globals().items()):
    if name.startswith("test_"):
        test()
        print(f"ok {name}")
