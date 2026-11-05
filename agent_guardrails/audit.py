"""Audit events: one JSON object per step, hash-chained per run.

Every event carries `prev` (the previous event's hash in the same run) and
`hash` (sha256 over prev + the canonical event body). Editing, deleting, or
reordering an event breaks the chain from that point on, and `verify` reports
the first broken sequence number.

Tamper-evident, not tamper-proof: someone with write access to the store could
rewrite a whole run. The run head hash is also printed to CloudWatch Logs on
every write, so a rewrite would have to forge both.
"""

from __future__ import annotations

import hashlib
import json
import time

GENESIS = "0" * 64
HASHED = ("run", "seq", "ts", "step", "agent", "tool", "data")


def canonical(body: dict) -> str:
    return json.dumps({k: body.get(k) for k in HASHED}, sort_keys=True, separators=(",", ":"), default=str)


def digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + "\n" + canonical(body)).encode()).hexdigest()


def make_event(run: str, seq: int, prev: str, step: str, agent: str = "", tool: str = "", data=None, ts=None) -> dict:
    ev = {"run": run, "seq": seq, "ts": round(ts if ts is not None else time.time(), 3), "step": step,
          "agent": agent, "tool": tool, "data": data or {}}
    ev["prev"] = prev
    ev["hash"] = digest(prev, ev)
    return ev


def verify(events: list[dict]) -> dict:
    """Check a run's chain. Events must be sorted by seq."""
    prev = GENESIS
    for i, ev in enumerate(events):
        if ev.get("seq") != i:
            return {"ok": False, "count": len(events), "broken_at": i, "why": "missing or reordered event"}
        if ev.get("prev") != prev or ev.get("hash") != digest(prev, ev):
            return {"ok": False, "count": len(events), "broken_at": i, "why": "hash mismatch"}
        prev = ev["hash"]
    return {"ok": True, "count": len(events), "head": prev}


class MemoryAudit:
    """In-process audit chain for local mode and tests."""

    def __init__(self, echo: bool = False):
        self.runs: dict[str, list[dict]] = {}
        self.echo = echo

    def write(self, run: str, step: str, agent: str = "", tool: str = "", **data) -> dict:
        chain = self.runs.setdefault(run, [])
        ev = make_event(run, len(chain), chain[-1]["hash"] if chain else GENESIS, step, agent, tool, data)
        chain.append(ev)
        if self.echo:
            print(json.dumps({"audit": True, **ev}, default=str))
        return ev

    def events(self, run: str) -> list[dict]:
        return list(self.runs.get(run, []))
