[Русская версия](README.ru.md)

# opensnitch_mcp

An MCP server that lets a coding agent see the OpenSnitch application firewall.

OpenSnitch can deny every outbound connection that no rule allows. A program
without a rule then fails with what looks like an ordinary network error: a
timeout, a refused connection, a name that does not resolve. An agent that sees
this starts debugging code that works. This server gives the agent a way to check
the firewall first.

## Tools

| Tool | Answers |
|---|---|
| `opensnitch_status` | Is the daemon running, what is the default action, how many rules are loaded |
| `list_rules` | The rules whose name, operand or value contains a string |
| `check_process` | Which rules cover an executable, and what happens to its connections |
| `recent_denies` | The latest blocked connections, optionally for one process |
| `add_rule` | Installs a rule after the user enters their password |

The server also sends the agent a short instruction: when a network call fails,
call `recent_denies` and `check_process` before touching the code, and never call
`add_rule` without telling the user.

## How it reaches the firewall

The rules live in `/etc/opensnitchd/rules`, which only root can read. A small
helper, `opensnitch-rulectl`, runs as root and does two things:

- `dump` prints the daemon configuration and every rule as JSON. One sudoers line
  allows it without a password.
- installing a rule goes through `sudo -A`, so the user sees a password dialog for
  every change to the firewall.

The helper is a single file that imports nothing from this directory, because the
user can write here and the helper runs as root. It validates every field against
its own whitelist of actions, durations, operands and operator types.

Blocked connections come from the OpenSnitch UI statistics database. By default
the UI keeps them in memory; `recent_denies` explains how to switch it to a file
when the database is missing.

## Install

Requirements: Linux with OpenSnitch, Python 3.10 or newer, the `fastmcp` package,
and `SUDO_ASKPASS` set to a graphical password helper.

```sh
pip install fastmcp
sudo -A bash install.sh
```

`install.sh` installs the helper to `/usr/local/bin`, adds the sudoers line, and
writes a few rules for programs whose path changes on every start or update
(AppImages, Claude Code, GE-Proton). Read it and remove what you do not use.

Register the server with your MCP client, for example in Claude Code:

```sh
claude mcp add opensnitch -- python3 /path/to/opensnitch_mcp/server.py
```

The statistics database path can be overridden with `OPENSNITCH_STATS_DB`.

## Tests

```sh
python3 test_server.py
```

## License

MIT
