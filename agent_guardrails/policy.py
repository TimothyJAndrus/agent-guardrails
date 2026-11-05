"""Action policy: allow, deny, or require approval for every tool call.

A policy is a list of rules. A rule matches a tool call when its tool pattern,
agent list, and every condition match. When several rules match, the most
restrictive effect wins (deny > approve > allow). When none match, the default
applies (deny unless the policy says otherwise).

Decisions depend only on WHO is calling (agent), WHAT tool, and the tool's
ARGUMENTS. Free text such as a justification or the model's reasoning is never
read by the policy: if text could change a decision, a prompt injection could.

Conditions fail closed. If an argument is missing, has the wrong type, or looks
like path traversal, the condition evaluates to "error": deny rules treat that
as a match, allow and approve rules as a non-match.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EFFECTS = ("allow", "approve", "deny")
RANK = {"allow": 0, "approve": 1, "deny": 2}
ERROR = object()  # tri-state condition result: True, False, or ERROR

_NAME = re.compile(r"^[A-Za-z0-9_.:*?\-\[\]]{1,128}$")


class PolicyError(ValueError):
    """The policy document is invalid. Raised at load time, never at decision time."""


def _num(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError("not a number")
    return v


def _str(v):
    if not isinstance(v, str):
        raise TypeError("not a string")
    return v


def _path(v):
    """A string that is safe to compare by prefix: no '..' segment, no NUL, no backslash."""
    s = _str(v)
    if "\x00" in s or "\\" in s or ".." in s.split("/") or posixpath.normpath(s).startswith(".."):
        raise ValueError("path traversal")
    return s


def _domain(v):
    s = _str(v).strip().lower()
    if s.count("@") != 1:
        raise ValueError("not an email address")
    d = s.rsplit("@", 1)[1]
    if not d or any(c in d for c in " <>,;\"'"):
        raise ValueError("bad domain")
    return d


OPERATORS = {
    "equals": lambda v, x: v == x,
    "not_equals": lambda v, x: v != x,
    "in": lambda v, x: v in x,
    "not_in": lambda v, x: v not in x,
    "starts_with": lambda v, x: _path(v).startswith(x),
    "not_starts_with": lambda v, x: not _path(v).startswith(x),
    "glob": lambda v, x: fnmatch.fnmatchcase(_path(v), x),
    "lt": lambda v, x: _num(v) < x,
    "lte": lambda v, x: _num(v) <= x,
    "gt": lambda v, x: _num(v) > x,
    "gte": lambda v, x: _num(v) >= x,
    "domain_in": lambda v, x: _domain(v) in [d.lower() for d in x],
    "domain_not_in": lambda v, x: _domain(v) not in [d.lower() for d in x],
    "max_length": lambda v, x: len(_str(v)) <= x,
}
LIST_OPERATORS = {"in", "not_in", "domain_in", "domain_not_in"}
NUMBER_OPERATORS = {"lt", "lte", "gt", "gte", "max_length"}


def _lookup(args: dict, dotted: str):
    cur: Any = args
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ERROR
        cur = cur[part]
    return cur


@dataclass(frozen=True)
class Condition:
    arg: str
    op: str
    value: Any

    def evaluate(self, args: dict):
        v = _lookup(args, self.arg)
        if self.op == "exists":
            return (v is not ERROR) == bool(self.value)
        if v is ERROR:
            return ERROR
        try:
            return bool(OPERATORS[self.op](v, self.value))
        except (TypeError, ValueError):
            return ERROR

    def __str__(self):
        return f"{self.arg} {self.op} {json.dumps(self.value)}"


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str
    effect: str
    conditions: tuple[Condition, ...] = ()
    agents: tuple[str, ...] = ()  # empty = any agent
    max_per_run: int | None = None
    expires_in: int | None = None  # approval window, seconds
    description: str = ""

    def matches(self, agent: str, tool: str, args: dict) -> bool:
        if not fnmatch.fnmatchcase(tool, self.tool):
            return False
        if self.agents and not any(fnmatch.fnmatchcase(agent, a) for a in self.agents):
            return False
        for c in self.conditions:
            r = c.evaluate(args)
            if r is ERROR:
                return self.effect == "deny"  # fail closed
            if not r:
                return False
        return True


@dataclass(frozen=True)
class Decision:
    effect: str  # allow | approve | deny
    rule: str  # rule id, or "default" / "limit:<rule>"
    reason: str
    expires_in: int = 900

    def to_dict(self):
        return {"effect": self.effect, "rule": self.rule, "reason": self.reason, "expires_in": self.expires_in}


@dataclass
class Policy:
    rules: list[Rule]
    default: str = "deny"
    approval_expires_in: int = 900
    approvers: dict = field(default_factory=dict)  # {"emails": [...], "slack_user_ids": [...]}
    max_calls_per_run: int | None = None
    source: dict = field(default_factory=dict)

    def evaluate(self, agent: str, tool: str, args: dict, counts: dict | None = None) -> Decision:
        """Decide one tool call. `counts` maps rule id -> calls already allowed in this run."""
        if not isinstance(args, dict):
            return Decision("deny", "invalid", "arguments must be an object")
        if not _NAME.match(tool or ""):
            return Decision("deny", "invalid", "invalid tool name")
        counts = counts or {}
        if self.max_calls_per_run is not None and counts.get("*", 0) >= self.max_calls_per_run:
            return Decision("deny", "limit:run", f"run reached max_calls_per_run={self.max_calls_per_run}")
        matched = [r for r in self.rules if r.matches(agent, tool, args)]
        if not matched:
            return Decision(self.default, "default", f"no rule matched {tool}; default is {self.default}",
                            self.approval_expires_in)
        top = max(matched, key=lambda r: RANK[r.effect])
        for r in matched:
            if r.max_per_run is not None and r.effect != "deny" and counts.get(r.id, 0) >= r.max_per_run:
                return Decision("deny", f"limit:{r.id}", f"rule {r.id} allows {r.max_per_run} call(s) per run")
        why = top.description or (" and ".join(str(c) for c in top.conditions) or f"tool matches {top.tool}")
        return Decision(top.effect, top.id, why, top.expires_in or self.approval_expires_in)

    def to_dict(self):
        return self.source


def _condition(arg: str, spec: Any, where: str) -> list[Condition]:
    if not isinstance(spec, dict):
        spec = {"equals": spec}
    out = []
    for op, value in spec.items():
        if op not in OPERATORS and op != "exists":
            raise PolicyError(f"{where}: unknown operator '{op}' (known: {', '.join(sorted(OPERATORS))}, exists)")
        if op in LIST_OPERATORS and not isinstance(value, list):
            raise PolicyError(f"{where}: '{op}' needs a list")
        if op in NUMBER_OPERATORS and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise PolicyError(f"{where}: '{op}' needs a number")
        if op in ("starts_with", "not_starts_with", "glob") and not isinstance(value, str):
            raise PolicyError(f"{where}: '{op}' needs a string")
        out.append(Condition(arg, op, value))
    return out


def parse(doc: dict) -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a mapping")
    if doc.get("version", 1) != 1:
        raise PolicyError("unsupported policy version")
    default = doc.get("default", "deny")
    if default not in EFFECTS:
        raise PolicyError(f"default must be one of {EFFECTS}")
    approval = doc.get("approval") or {}
    rules, seen = [], set()
    for i, raw in enumerate(doc.get("rules") or []):
        where = f"rules[{i}]"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where}: must be a mapping")
        unknown = set(raw) - {"id", "tool", "effect", "when", "agents", "max_per_run", "expires_in", "description"}
        if unknown:
            raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
        rid = str(raw.get("id") or "")
        if not rid or rid in seen:
            raise PolicyError(f"{where}: id missing or duplicated")
        seen.add(rid)
        if raw.get("effect") not in EFFECTS:
            raise PolicyError(f"{where} ({rid}): effect must be one of {EFFECTS}")
        tool = raw.get("tool")
        if not isinstance(tool, str) or not _NAME.match(tool):
            raise PolicyError(f"{where} ({rid}): tool must be a name or glob")
        conds = []
        for arg, spec in (raw.get("when") or {}).items():
            conds += _condition(str(arg), spec, f"{where} ({rid}).when.{arg}")
        agents = raw.get("agents") or []
        if isinstance(agents, str):
            agents = [agents]
        mpr = raw.get("max_per_run")
        if mpr is not None and (not isinstance(mpr, int) or mpr < 0):
            raise PolicyError(f"{where} ({rid}): max_per_run must be a non-negative integer")
        rules.append(Rule(rid, tool, raw["effect"], tuple(conds), tuple(str(a) for a in agents), mpr,
                          raw.get("expires_in"), str(raw.get("description") or "")))
    exp = int(approval.get("expires_in", 900))
    if not 30 <= exp <= 7 * 86400:
        raise PolicyError("approval.expires_in must be between 30 seconds and 7 days")
    return Policy(rules, default, exp, dict(approval.get("approvers") or {}),
                  (doc.get("limits") or {}).get("max_calls_per_run"), doc)


def load(path: str | Path) -> Policy:
    text = Path(path).read_text()
    if str(path).endswith(".json"):
        return parse(json.loads(text))
    import yaml  # only needed for YAML policies; Lambda gets JSON

    return parse(yaml.safe_load(text))
