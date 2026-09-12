import os
import sqlite3
from pathlib import Path

from models import Connection

ENABLE_HINT = (
    "The OpenSnitch UI keeps its statistics in memory, so blocked connections "
    "cannot be read from outside it. Quit opensnitch-ui, set in the [database] "
    "section of ~/.config/opensnitch/settings.conf:\n"
    "  type=1\n"
    "  file=<home>/.cache/opensnitch/stats.db\n"
    "  max_days=7\n"
    "then start opensnitch-ui again."
)

COLUMNS = (
    "time, action, process, process_args, protocol, "
    "dst_host, dst_ip, dst_port, pid, rule"
)


class StatsUnavailable(Exception):
    pass


def database_path() -> Path:
    override = os.environ.get("OPENSNITCH_STATS_DB")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "opensnitch" / "stats.db"


def _query(where: str, params: list[object], limit: int) -> list[Connection]:
    path = database_path()
    if not path.exists():
        raise StatsUnavailable(ENABLE_HINT)
    uri = f"file:{path}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        rows = db.execute(
            f"SELECT {COLUMNS} FROM connections WHERE {where} ORDER BY time DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
    return [Connection(*row) for row in rows]


def denied(limit: int, process: str | None) -> list[Connection]:
    where = "action IN ('deny', 'reject')"
    params: list[object] = []
    if process:
        where += " AND process LIKE ?"
        params.append(f"%{process}%")
    return _query(where, params, limit)


def for_process(process: str, limit: int) -> list[Connection]:
    return _query("process LIKE ?", [f"%{process}%"], limit)
