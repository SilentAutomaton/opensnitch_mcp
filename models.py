from dataclasses import dataclass, field

RULES_DIR = "/etc/opensnitchd/rules"
DAEMON_CONFIG = "/etc/opensnitchd/default-config.json"
RULECTL = "/usr/local/bin/opensnitch-rulectl"

ACTIONS = ("allow", "deny", "reject")
DURATIONS = ("once", "30s", "5m", "15m", "30m", "1h", "12h", "until restart", "always")
OPERATOR_TYPES = ("simple", "regexp", "network", "list", "lists")
OPERANDS = (
    "process.id",
    "process.path",
    "process.command",
    "process.hash.md5",
    "process.hash.sha1",
    "user.id",
    "iface.out",
    "iface.in",
    "source.ip",
    "source.port",
    "source.network",
    "dest.ip",
    "dest.host",
    "dest.port",
    "dest.network",
    "protocol",
    "lists.domains",
    "lists.domains_regexp",
    "lists.ips",
    "lists.nets",
)


@dataclass
class Operator:
    operand: str
    type: str
    data: str
    sensitive: bool = False
    sub: list["Operator"] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    action: str
    duration: str
    enabled: bool
    precedence: bool
    operator: Operator
    description: str = ""


@dataclass
class RuleMatch:
    rule: Rule
    matched_on: str


@dataclass
class Connection:
    time: str
    action: str
    process: str
    process_args: str
    protocol: str
    dst_host: str
    dst_ip: str
    dst_port: str
    pid: str
    rule: str
