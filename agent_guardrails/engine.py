"""The action gate: one engine shared by local mode and the deployed service.

Lifecycle of a tool call:

    check()  ->  allowed  ---------------------------> consume() -> record_result()
             ->  denied   (terminal)
             ->  pending  -> decide(approve) -> approved -> consume() -> record_result()
                          -> decide(reject)  -> rejected (terminal)
                          -> (window passes) -> expired  (terminal)

`consume()` succeeds exactly once per call, and only when the arguments match
the ones that were checked (and, for approvals, the ones the human saw). That
is what stops "approve a $20 refund, execute a $2,000 one".

The engine never mints credentials. A tool that needs AWS access should get a
scoped credential from agent-credential-broker inside the executor.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from .policy import Policy

TERMINAL = {"denied", "rejected", "expired", "executed"}


class GateError(Exception):
    status = 400

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        if status:
            self.status = status


def args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


@dataclass
class Approver:
    channel: str  # dashboard | slack | email | local | api
    id: str
    name: str = ""

    def to_dict(self):
        return {"channel": self.channel, "id": self.id, "name": self.name or self.id}


class Gate:
    def __init__(self, policy: Policy, store, notifiers=(), clock=time.time, task_callback=None):
        self.policy = policy
        self.store = store
        self.notifiers = list(notifiers)
        self.clock = clock
        self.task_callback = task_callback  # fn(token, output: dict) for Step Functions

    # ---------- runs ----------
    def start_run(self, agent: str, task: str = "", meta: dict | None = None, run_id: str | None = None) -> dict:
        run = {"id": run_id or new_id("run"), "agent": agent, "task": str(task)[:2000], "status": "running",
               "started": self.clock(), "meta": meta or {}}
        if not self.store.put_run(run):
            raise GateError("run id already exists", 409)
        self._audit(run["id"], "run.started", agent, task=run["task"], meta=run["meta"])
        return run

    def end_run(self, run_id: str, agent: str, status: str = "finished", answer: str = "") -> dict:
        run = self._own_run(run_id, agent)
        self.store.update_run(run_id, {"status": status, "ended": self.clock()})
        self._audit(run_id, "run.ended", agent, status=status, answer=str(answer)[:4000])
        return {**run, "status": status}

    def _own_run(self, run_id: str, agent: str) -> dict:
        run = self.store.get_run(run_id)
        if not run or run["agent"] != agent:
            raise GateError("no such run", 404)
        return run

    # ---------- calls ----------
    def check(self, run_id: str, agent: str, tool: str, args: dict, context: str = "") -> dict:
        """Decide one tool call. `context` (e.g. the model's stated reason) is recorded, never evaluated."""
        run = self._own_run(run_id, agent)
        if run["status"] != "running":
            raise GateError(f"run is {run['status']}", 409)
        if not isinstance(args, dict):
            raise GateError("args must be an object")
        d = self.policy.evaluate(agent, tool, args, self.store.get_counts(run_id))
        if d.effect != "deny":
            limit = next((r.max_per_run for r in self.policy.rules if r.id == d.rule), None)
            if not self.store.incr_count(run_id, d.rule, limit):
                d = type(d)("deny", f"limit:{d.rule}", f"rule {d.rule} allows {limit} call(s) per run")
            elif not self.store.incr_count(run_id, "*", self.policy.max_calls_per_run):
                d = type(d)("deny", "limit:run", f"run reached max_calls_per_run={self.policy.max_calls_per_run}")
        now = self.clock()
        state = {"allow": "allowed", "deny": "denied", "approve": "pending"}[d.effect]
        call = {"id": new_id("call"), "run": run_id, "agent": agent, "tool": tool, "args": args,
                "args_hash": args_hash(args), "effect": d.effect, "rule": d.rule, "reason": d.reason,
                "state": state, "created": now, "context": str(context)[:1000],
                "expires_at": now + d.expires_in if state == "pending" else None}
        self.store.put_call(call)
        step = {"allowed": "call.allowed", "denied": "call.denied", "pending": "approval.requested"}[state]
        self._audit(run_id, step, agent, tool, call=call["id"], args=args, rule=d.rule, reason=d.reason,
                    context=call["context"], args_hash=call["args_hash"],
                    **({"expires_at": call["expires_at"]} if state == "pending" else {}))
        if state == "pending":
            for n in self.notifiers:
                try:
                    sent = n.notify(call)
                    self._audit(run_id, "approval.notified", agent, tool, call=call["id"], channel=n.channel,
                                **(sent or {}))
                except Exception as e:  # a broken channel must not hide the request; dashboard still shows it
                    self._audit(run_id, "approval.notify_failed", agent, tool, call=call["id"], channel=n.channel,
                                error=f"{type(e).__name__}: {e}"[:300])
        return self.view(call)

    def get_call(self, call_id: str, agent: str | None = None) -> dict:
        call = self.store.get_call(call_id)
        if not call or (agent is not None and call["agent"] != agent):
            raise GateError("no such call", 404)
        return self._expire_if_due(call)

    def _expire_if_due(self, call: dict) -> dict:
        if call["state"] == "pending" and call.get("expires_at") and self.clock() > call["expires_at"]:
            if self.store.transition_call(call["id"], {"pending"}, {"state": "expired", "decided_at": self.clock()}):
                self._audit(call["run"], "approval.expired", call["agent"], call["tool"], call=call["id"])
                self._callback(call, {"decision": "expired", "call": call["id"]})
            call = self.store.get_call(call["id"])
        return call

    def decide(self, call_id: str, decision: str, approver: Approver, note: str = "",
               allowed_approvers: set | None = None) -> dict:
        if decision not in ("approve", "reject"):
            raise GateError("decision must be approve or reject")
        call = self.get_call(call_id)
        if call["state"] != "pending":
            status = 410 if call["state"] == "expired" else 409
            raise GateError(f"call is {call['state']}, not pending", status)
        if approver.id == call["agent"] or approver.channel == "agent":
            raise GateError("an agent cannot approve a call", 403)
        if allowed_approvers is not None and approver.id not in allowed_approvers:
            self._audit(call["run"], "approval.unauthorized", call["agent"], call["tool"], call=call_id,
                        approver=approver.to_dict())
            raise GateError("not an approver for this policy", 403)
        new = "approved" if decision == "approve" else "rejected"
        upd = {"state": new, "decided_at": self.clock(), "approver": approver.to_dict(), "note": str(note)[:500]}
        if not self.store.transition_call(call_id, {"pending"}, upd):
            raise GateError("call was decided concurrently", 409)
        self._audit(call["run"], "approval.decided", call["agent"], call["tool"], call=call_id, decision=new,
                    approver=approver.to_dict(), note=upd["note"], args_hash=call["args_hash"])
        call = self.store.get_call(call_id)
        self._callback(call, {"decision": decision, "call": call_id, "approver": approver.to_dict(),
                              "decided_at": int(upd["decided_at"])})
        return self.view(call)

    def attach_task_token(self, call_id: str, agent: str, token: str) -> dict:
        """Step Functions waitForTaskToken: resume the workflow when this call is decided."""
        call = self.get_call(call_id, agent)
        self.store.update_call(call_id, {"task_token": token})
        if call["state"] != "pending":  # decided before the workflow got here
            self._callback({**call, "task_token": token}, {"decision": _decision_word(call["state"]),
                                                           "call": call_id, "approver": call.get("approver")})
        return self.view(call)

    def consume(self, call_id: str, principal: str, args: dict | None = None, may_execute_for=None) -> dict:
        """Start executing a call. Succeeds once. Returns the args to execute (the approved ones)."""
        call = self.store.get_call(call_id)
        if not call or not (principal == call["agent"] or (may_execute_for and call["agent"] in may_execute_for)):
            raise GateError("no such call", 404)
        call = self._expire_if_due(call)
        if args is not None and args_hash(args) != call["args_hash"]:
            self._audit(call["run"], "call.args_mismatch", call["agent"], call["tool"], call=call_id,
                        principal=principal, presented_hash=args_hash(args), approved_hash=call["args_hash"])
            raise GateError("arguments differ from the ones that were checked/approved", 409)
        if call["state"] == "executed":
            self._audit(call["run"], "call.replay_blocked", call["agent"], call["tool"], call=call_id,
                        principal=principal)
            raise GateError("call was already executed", 409)
        if call["state"] not in ("allowed", "approved"):
            raise GateError(f"call is {call['state']}", 403 if call["state"] in TERMINAL else 409)
        if not self.store.transition_call(call_id, {"allowed", "approved"},
                                          {"state": "executed", "executed_at": self.clock(), "executor": principal}):
            raise GateError("call was executed concurrently", 409)
        self._audit(call["run"], "call.executing", call["agent"], call["tool"], call=call_id, principal=principal)
        return {**self.view(call), "state": "executed", "args": call["args"]}

    def record_result(self, call_id: str, principal: str, ok: bool, result=None, may_execute_for=None) -> dict:
        call = self.store.get_call(call_id)
        if not call or not (principal == call["agent"] or (may_execute_for and call["agent"] in may_execute_for)):
            raise GateError("no such call", 404)
        if call["state"] != "executed" or call.get("result_recorded"):
            raise GateError("result can be recorded once, after execution", 409)
        self.store.update_call(call_id, {"result_recorded": True, "ok": bool(ok)})
        summary = json.dumps(result, default=str)[:2000] if result is not None else ""
        self._audit(call["run"], "call.result", call["agent"], call["tool"], call=call_id, ok=bool(ok),
                    result=summary, principal=principal)
        return {"ok": True}

    # ---------- reads for the dashboard ----------
    def pending(self, limit: int = 50) -> list[dict]:
        return [self.view(c) for c in (self._expire_if_due(c) for c in self.store.calls_by_state("pending", limit))
                if c["state"] == "pending"]

    def denials(self, limit: int = 50) -> list[dict]:
        return [self.view(c) for c in self.store.calls_by_state("denied", limit)]

    def runs(self, limit: int = 50) -> list[dict]:
        return self.store.list_runs(limit)

    def replay(self, run_id: str) -> dict:
        from .audit import verify

        run = self.store.get_run(run_id)
        if not run:
            raise GateError("no such run", 404)
        events = self.store.events(run_id)
        return {"run": run, "events": events, "chain": verify(events),
                "calls": [self.view(c) for c in self.store.calls_for_run(run_id)]}

    # ---------- helpers ----------
    @staticmethod
    def view(call: dict) -> dict:
        hidden = {"task_token", "email_token_hash", "result_recorded"}
        return {k: v for k, v in call.items() if k not in hidden}

    def _audit(self, run, step, agent="", tool="", **data):
        return self.store.append_event(run, step, agent, tool, data)

    def _callback(self, call, output):
        if call.get("task_token") and self.task_callback:
            try:
                self.task_callback(call["task_token"], output)
                self._audit(call["run"], "workflow.resumed", call["agent"], call["tool"], call=call["id"],
                            decision=output.get("decision"))
            except Exception as e:
                self._audit(call["run"], "workflow.resume_failed", call["agent"], call["tool"], call=call["id"],
                            error=f"{type(e).__name__}: {e}"[:300])


def _decision_word(state):
    return {"approved": "approve", "rejected": "reject", "expired": "expired"}.get(state, state)
