"""Agent-side SDK: gate every tool call with a decorator.

    from agent_guardrails import Guard

    guard = Guard.local("policy.yaml", agent="support-bot")       # in-process, for dev and tests
    guard = Guard.remote(api_url, agent="support-bot")             # deployed service, SigV4 with the agent's role

    @guard.tool()
    def issue_refund(order_id: str, amount_usd: float) -> dict: ...

    with guard.run("handle ticket 1042"):
        issue_refund(order_id="1042", amount_usd=249)

A gated call is checked before the function body runs:

- allowed          -> runs, result recorded
- denied           -> raises Denied (the body never runs)
- needs approval   -> on_pending="wait": blocks until a human decides (Rejected / Expired if not approved)
                      on_pending="raise": raises ApprovalPending(call_id) so a workflow can pause
                      and later call guard.execute(call_id)

For model tool-use loops, `guard.call_tool(name, args)` returns a dict the model can read
instead of raising, so a denial becomes an observation, not a crash.
"""

from __future__ import annotations

import functools
import inspect
import json
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from contextvars import ContextVar

from .engine import Approver, Gate, GateError
from .policy import Policy, load
from .store import MemoryStore


class GuardError(Exception):
    def __init__(self, message: str, call: dict | None = None):
        super().__init__(message)
        self.call = call or {}

    @property
    def call_id(self):
        return self.call.get("id")


class Denied(GuardError):
    pass


class ApprovalPending(GuardError):
    pass


class Rejected(GuardError):
    pass


class Expired(GuardError):
    pass


# ---------------- clients ----------------
class LocalClient:
    """Talks to an in-process Gate. Approvals come from `approve()` / `reject()` or an approver callback."""

    def __init__(self, gate: Gate):
        self.gate = gate

    def start_run(self, agent, task, meta=None):
        return self.gate.start_run(agent, task, meta)

    def end_run(self, run_id, agent, status, answer=""):
        return self.gate.end_run(run_id, agent, status, answer)

    def check(self, run_id, agent, tool, args, context=""):
        return self.gate.check(run_id, agent, tool, args, context)

    def get_call(self, call_id, agent):
        return self.gate.get_call(call_id, agent)

    def consume(self, call_id, agent, args):
        return self.gate.consume(call_id, agent, args)

    def record_result(self, call_id, agent, ok, result):
        return self.gate.record_result(call_id, agent, ok, result)

    def approve(self, call_id, approver="local-human", note=""):
        return self.gate.decide(call_id, "approve", Approver("local", approver), note)

    def reject(self, call_id, approver="local-human", note=""):
        return self.gate.decide(call_id, "reject", Approver("local", approver), note)


class HttpClient:
    """Talks to the deployed API. Signs requests with SigV4 (execute-api) using the caller's AWS credentials."""

    def __init__(self, base_url: str, session=None, region: str | None = None, timeout: float = 10):
        import boto3

        if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
            raise ValueError("api_url must be https://")
        self.base = base_url.rstrip("/")
        self.session = session or boto3.Session()
        self.region = region or self.session.region_name or "us-west-2"
        self.timeout = timeout

    def _req(self, method, path, body=None):
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest

        data = json.dumps(body).encode() if body is not None else None
        req = AWSRequest(method=method, url=self.base + path, data=data,
                         headers={"Content-Type": "application/json"} if data else {})
        SigV4Auth(self.session.get_credentials().get_frozen_credentials(), "execute-api", self.region).add_auth(req)
        r = urllib.request.Request(self.base + path, data=data, method=method,  # noqa: S310 (scheme checked)
                                   headers=dict(req.headers.items()))
        try:
            with urllib.request.urlopen(r, timeout=self.timeout) as resp:  # noqa: S310 (scheme checked)
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error", str(e))
            except ValueError:
                msg = str(e)
            raise GateError(msg, e.code) from None

    def start_run(self, agent, task, meta=None):
        return self._req("POST", "/v1/runs", {"task": task, "meta": meta or {}})

    def end_run(self, run_id, agent, status, answer=""):
        return self._req("POST", f"/v1/runs/{run_id}/end", {"status": status, "answer": answer})

    def check(self, run_id, agent, tool, args, context=""):
        return self._req("POST", f"/v1/runs/{run_id}/calls", {"tool": tool, "args": args, "context": context})

    def get_call(self, call_id, agent):
        return self._req("GET", f"/v1/calls/{call_id}")

    def consume(self, call_id, agent, args):
        return self._req("POST", f"/v1/calls/{call_id}/consume", {"args": args})

    def record_result(self, call_id, agent, ok, result):
        return self._req("POST", f"/v1/calls/{call_id}/result", {"ok": ok, "result": result})


# ---------------- the guard ----------------
_current_run: ContextVar[str | None] = ContextVar("agent_guardrails_run", default=None)


class Guard:
    def __init__(self, client, agent: str, on_pending: str = "wait", wait_timeout: float = 900,
                 poll_interval: float = 2.0):
        if on_pending not in ("wait", "raise"):
            raise ValueError("on_pending must be 'wait' or 'raise'")
        self.client, self.agent = client, agent
        self.on_pending, self.wait_timeout, self.poll_interval = on_pending, wait_timeout, poll_interval
        self.tools: dict[str, dict] = {}
        self._local_approver = None

    @classmethod
    def local(cls, policy: str | Policy, agent: str, **kw):
        pol = policy if isinstance(policy, Policy) else load(policy)
        approver = kw.pop("approver", None)  # fn(call) -> "approve" | "reject" | None, for scripted local runs
        guard = cls(LocalClient(Gate(pol, MemoryStore())), agent, **kw)
        guard._local_approver = approver
        return guard

    @classmethod
    def remote(cls, api_url: str, agent: str, session=None, **kw):
        return cls(HttpClient(api_url, session=session), agent, **kw)

    # ----- runs -----
    @contextmanager
    def run(self, task: str = "", meta: dict | None = None, run_id: str | None = None):
        if run_id:
            token = _current_run.set(run_id)
            try:
                yield {"id": run_id}
            finally:
                _current_run.reset(token)
            return
        run = self.client.start_run(self.agent, task, meta)
        token = _current_run.set(run["id"])
        status = "finished"
        try:
            yield run
        except BaseException:
            status = "failed"
            raise
        finally:
            _current_run.reset(token)
            try:
                self.client.end_run(run["id"], self.agent, status)
            except Exception:
                if status == "finished":
                    raise  # otherwise keep the original exception visible

    def _run_id(self):
        rid = _current_run.get()
        if not rid:
            raise GuardError("gated tools must be called inside `with guard.run(...)`")
        return rid

    # ----- decorator -----
    def tool(self, name: str | None = None, credentials=None, description: str = ""):
        """Gate a function. `credentials`, if given, is called with the approved args AFTER the gate
        allows the call, and its return value is passed to the function as `credentials=`. Use it to
        fetch a scoped, short-lived credential from agent-credential-broker for exactly this call."""

        def wrap(fn):
            tool_name = name or fn.__name__
            sig = inspect.signature(fn)
            self.tools[tool_name] = {"fn": fn, "credentials": credentials, "description": description or
                                     (fn.__doc__ or "").strip()}

            @functools.wraps(fn)
            def gated(*a, **kw):
                bound = sig.bind_partial(*a, **kw)
                args = {k: v for k, v in bound.arguments.items() if k != "credentials"}
                return self._invoke(tool_name, args)

            gated.tool_name = tool_name
            return gated

        return wrap

    def _invoke(self, tool, args, context=""):
        call = self.client.check(self._run_id(), self.agent, tool, args, context)
        if call["state"] == "denied":
            raise Denied(f"{tool} denied by {call['rule']}: {call['reason']}", call)
        if call["state"] == "pending":
            call = self._await(call)
        return self._execute(call, args)

    def _await(self, call):
        approver = getattr(self, "_local_approver", None)
        if approver and isinstance(self.client, LocalClient):
            verdict = approver(call)
            if verdict == "approve":
                self.client.approve(call["id"])
            elif verdict == "reject":
                self.client.reject(call["id"])
        if self.on_pending == "raise":
            call = self.client.get_call(call["id"], self.agent)
            if call["state"] == "pending":
                raise ApprovalPending(f"{call['tool']} needs approval (call {call['id']})", call)
        deadline = time.time() + self.wait_timeout
        while True:
            call = self.client.get_call(call["id"], self.agent)
            if call["state"] != "pending":
                break
            if time.time() > deadline:
                raise ApprovalPending(f"still waiting for approval of {call['id']}", call)
            time.sleep(self.poll_interval)
        if call["state"] == "rejected":
            raise Rejected(f"{call['tool']} was rejected by {call.get('approver', {}).get('name', 'a human')}", call)
        if call["state"] == "expired":
            raise Expired(f"approval for {call['tool']} expired", call)
        return call

    def _execute(self, call, args):
        spec = self.tools.get(call["tool"])
        if not spec:
            raise GuardError(f"no local implementation for {call['tool']}", call)
        granted = self.client.consume(call["id"], self.agent, args)
        kwargs = dict(granted["args"])
        if spec["credentials"]:
            kwargs["credentials"] = spec["credentials"](dict(granted["args"]))
        try:
            out = spec["fn"](**kwargs)
        except Exception as e:
            self.client.record_result(call["id"], self.agent, False, f"{type(e).__name__}: {e}")
            raise
        self.client.record_result(call["id"], self.agent, True, out)
        return out

    def execute(self, call_id: str, args: dict):
        """Execute a call that was approved after ApprovalPending was raised (e.g. after a workflow resumed)."""
        call = self.client.get_call(call_id, self.agent)
        if call["state"] == "pending":
            raise ApprovalPending("still pending", call)
        if call["state"] in ("rejected", "expired", "denied"):
            raise {"rejected": Rejected, "expired": Expired, "denied": Denied}[call["state"]](call["state"], call)
        return self._execute(call, args)

    # ----- for model tool-use loops -----
    def call_tool(self, tool: str, args: dict, context: str = "", execute: bool = True) -> dict:
        """Like calling the decorated function, but returns a dict for the model instead of raising.

        execute=False checks the call without running it: use it when a separate executor (with
        permissions the agent doesn't have) runs approved calls later. Pending calls never block here.
        """
        if not execute:
            try:
                call = self.client.check(self._run_id(), self.agent, tool, args, context)
            except GateError as e:
                return {"status": "error", "error": str(e)}
            if call["state"] == "denied":
                return {"status": "denied", "error": f"{tool} denied by {call['rule']}: {call['reason']}",
                        "call": call["id"]}
            if call["state"] == "pending":
                return {"status": "pending_approval", "message": "queued for human approval; it has NOT run yet",
                        "call": call["id"]}
            return {"status": "allowed", "message": "allowed; a separate executor will run it", "call": call["id"]}
        try:
            return {"status": "ok", "result": self._invoke(tool, args, context)}
        except Denied as e:
            return {"status": "denied", "error": str(e), "call": e.call_id}
        except ApprovalPending as e:
            return {"status": "pending_approval", "message": "queued for human approval; it has NOT run yet",
                    "call": e.call_id}
        except (Rejected, Expired) as e:
            return {"status": "not_approved", "error": str(e), "call": e.call_id}
        except (GateError, GuardError) as e:
            return {"status": "error", "error": str(e)}
