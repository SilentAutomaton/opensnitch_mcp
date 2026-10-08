# Working on opensnitch_mcp

Tier: 1

## What it is

An MCP server that lets a coding agent see the OpenSnitch application firewall.
OpenSnitch denies outbound connections by default, so a process without a rule
fails to reach the network and reports an ordinary timeout. The agent then
debugs code that is not broken. This server answers three questions — is the
daemon running, what rule covers this executable, what was blocked recently —
and installs a rule when the user approves it.

Reading goes through `opensnitch-rulectl dump`, which one sudoers line allows
without a password. Writing goes through `sudo -A`, so the user confirms every
change to the firewall.

## Installing it

```
sudo -A bash install.sh
```

Installs the root helper, the sudoers line, and rules for Telegram and Claude
Code, whose paths change on every start or update.

## Running it

```
python3 server.py
```

An MCP client, Claude Code for one, starts it as the `opensnitch` MCP server.

## Checking it

```
python3 test_server.py
```

## Code

[`codestyle.md`](codestyle.md), the same standard at every
tier. This project has more than one module, so the modularity rules apply.

`models.py` holds the contracts: the dataclasses that cross module boundaries
and the lists of valid actions, durations, operands and operator types.

## Rules

1. `opensnitch-rulectl` runs as root and stays one self-contained file. It never
   imports from this directory, which the calling user can write. Its whitelists
   are deliberately a second copy of the ones in `models.py`: the copy in the
   helper is the trust boundary, the copy in `models.py` only gives a better
   error before the password dialog appears.
2. Nothing personal is committed. No keys, no home paths, no dumps. The
   repository ships `*.example` files only.

## Commits

One step, one commit. A single line of plain English describing what the code
now does. No tool names, no attribution trailers.
