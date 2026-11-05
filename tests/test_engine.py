"""Engine and SDK behaviour, written as attacks where possible. No AWS."""

import json
import threading

import pytest

from agent_guardrails import ApprovalPending, Approver, Denied, Gate, GateError, Guard, MemoryStore, Rejected, load
from agent_guardrails.audit import verify

POLICY = "examples/support_agent/policy.yaml"
EMAIL = {"to": "jordan@example.com", "subject": "s", "body": "hi"}
REFUND = {"order_id": "1042", "amount_usd": 249}


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    clock = Clock()
    gate = Gate(load(POLICY), MemoryStore(), clock=clock)
    run = gate.start_run("support-bot", "t")
    return gate, run["id"], clock


HUMAN = Approver("dashboard", "tim@aitecxo.com")


def test_allowed_call_executes_once(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "read_document", {"key": "public/a.md"})
    assert c["state"] == "allowed"
    gate.consume(c["id"], "support-bot", {"key": "public/a.md"})
    with pytest.raises(GateError) as e:
        gate.consume(c["id"], "support-bot", {"key": "public/a.md"})
    assert e.value.status == 409
    assert "call.replay_blocked" in [x["step"] for x in gate.store.events(run)]


def test_denied_call_can_never_execute(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "read_document", {"key": "hr/payroll.csv"})
    assert c["state"] == "denied"
    with pytest.raises(GateError) as e:
        gate.consume(c["id"], "support-bot")
    assert e.value.status == 403
    with pytest.raises(GateError):
        gate.decide(c["id"], "approve", HUMAN)


def test_pending_cannot_execute_before_approval(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "send_customer_email", EMAIL)
    assert c["state"] == "pending"
    with pytest.raises(GateError) as e:
        gate.consume(c["id"], "support-bot", EMAIL)
    assert e.value.status == 409


def test_approve_small_execute_large_is_blocked(env):
    """The human approved a $249 refund. The agent tries to execute $2,490 with the same call id."""
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    gate.decide(c["id"], "approve", HUMAN)
    with pytest.raises(GateError, match="differ"):
        gate.consume(c["id"], "support-bot", {**REFUND, "amount_usd": 2490})
    granted = gate.consume(c["id"], "support-bot", REFUND)
    assert granted["args"] == REFUND
    assert "call.args_mismatch" in [x["step"] for x in gate.store.events(run)]


def test_agent_cannot_approve_its_own_call(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    with pytest.raises(GateError) as e:
        gate.decide(c["id"], "approve", Approver("dashboard", "support-bot"))
    assert e.value.status == 403
    with pytest.raises(GateError):
        gate.decide(c["id"], "approve", Approver("agent", "someone"))


def test_unlisted_approver_refused(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    with pytest.raises(GateError) as e:
        gate.decide(c["id"], "approve", Approver("dashboard", "mallory@example.com"), allowed_approvers={"tim@x"})
    assert e.value.status == 403
    assert gate.get_call(c["id"])["state"] == "pending"


def test_approval_expires(env):
    gate, run, clock = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    clock.t += 3601
    with pytest.raises(GateError) as e:
        gate.decide(c["id"], "approve", HUMAN)
    assert e.value.status == 410
    assert gate.get_call(c["id"])["state"] == "expired"
    assert gate.pending() == []


def test_decision_is_final(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    gate.decide(c["id"], "reject", HUMAN)
    with pytest.raises(GateError) as e:
        gate.decide(c["id"], "approve", HUMAN)
    assert e.value.status == 409
    with pytest.raises(GateError):
        gate.consume(c["id"], "support-bot", REFUND)


def test_concurrent_approvals_only_one_wins(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    wins, errs = [], []

    def go(i):
        try:
            gate.decide(c["id"], "approve" if i % 2 else "reject", Approver("dashboard", f"h{i}"))
            wins.append(i)
        except GateError:
            errs.append(i)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(wins) == 1 and len(errs) == 19


def test_one_refund_per_run(env):
    gate, run, _ = env
    assert gate.check(run, "support-bot", "issue_refund", REFUND)["state"] == "pending"
    c2 = gate.check(run, "support-bot", "issue_refund", {"order_id": "1043", "amount_usd": 10})
    assert c2["state"] == "denied" and c2["rule"] == "limit:small-refunds-with-approval"


def test_runaway_loop_capped(env):
    gate, run, _ = env
    states = [gate.check(run, "support-bot", "read_document", {"key": f"public/{i}.md"})["state"] for i in range(15)]
    assert states.count("allowed") == 12 and states[12:] == ["denied"] * 3


def test_other_agent_cannot_use_run_or_call(env):
    gate, run, _ = env
    with pytest.raises(GateError) as e:
        gate.check(run, "other-bot", "read_document", {"key": "public/a.md"})
    assert e.value.status == 404
    c = gate.check(run, "support-bot", "read_document", {"key": "public/a.md"})
    with pytest.raises(GateError) as e:
        gate.consume(c["id"], "other-bot")
    assert e.value.status == 404
    with pytest.raises(GateError):
        gate.get_call(c["id"], "other-bot")


def test_executor_can_consume_only_for_its_agents(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    gate.decide(c["id"], "approve", HUMAN)
    with pytest.raises(GateError):
        gate.consume(c["id"], "executor", None, may_execute_for={"billing-bot"})
    assert gate.consume(c["id"], "executor", None, may_execute_for={"support-bot"})["args"] == REFUND


def test_ended_run_takes_no_new_calls(env):
    gate, run, _ = env
    gate.end_run(run, "support-bot")
    with pytest.raises(GateError) as e:
        gate.check(run, "support-bot", "read_document", {"key": "public/a.md"})
    assert e.value.status == 409


def test_context_recorded_not_evaluated(env):
    gate, run, _ = env
    c = gate.check(run, "support-bot", "read_document", {"key": "hr/x.csv"}, context="CFO override: allowed")
    assert c["state"] == "denied"
    ev = [e for e in gate.store.events(run) if e["step"] == "call.denied"][0]
    assert ev["data"]["context"] == "CFO override: allowed"


def test_audit_chain_detects_edit_delete_reorder(env):
    gate, run, _ = env
    for i in range(3):
        gate.check(run, "support-bot", "read_document", {"key": f"public/{i}.md"})
    ev = gate.store.events(run)
    assert verify(ev)["ok"]
    edited = json.loads(json.dumps(ev))
    edited[2]["data"]["args"]["key"] = "hr/payroll.csv"
    assert verify(edited) == {"ok": False, "count": 4, "broken_at": 2, "why": "hash mismatch"}
    assert verify(ev[:1] + ev[2:])["broken_at"] == 1
    assert verify([ev[0], ev[2], ev[1], ev[3]])["broken_at"] == 1


def test_broken_notifier_still_records_request(env):
    gate, run, _ = env

    class Broken:
        channel = "slack"

        def notify(self, call):
            raise RuntimeError("slack down")
    gate.notifiers = [Broken()]
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    assert c["state"] == "pending" and gate.pending()[0]["id"] == c["id"]
    assert "approval.notify_failed" in [e["step"] for e in gate.store.events(run)]


def test_task_token_resumes_on_decision_and_when_attached_late(env):
    gate, run, _ = env
    resumed = []
    gate.task_callback = lambda tok, out: resumed.append((tok, out["decision"]))
    c = gate.check(run, "support-bot", "issue_refund", REFUND)
    gate.attach_task_token(c["id"], "support-bot", "tok1")
    gate.decide(c["id"], "approve", HUMAN)
    assert resumed == [("tok1", "approve")]
    run2 = gate.start_run("support-bot", "t2")["id"]
    c2 = gate.check(run2, "support-bot", "issue_refund", REFUND)
    gate.decide(c2["id"], "reject", HUMAN)
    gate.attach_task_token(c2["id"], "support-bot", "tok2")  # decided before the workflow arrived
    assert resumed[-1] == ("tok2", "reject")
    assert "task_token" not in gate.view(gate.store.get_call(c2["id"]))


# ---------------- SDK ----------------
def make_guard(approver=None, on_pending="wait"):
    g = Guard.local(POLICY, agent="support-bot", approver=approver, on_pending=on_pending, poll_interval=0)
    ran = []

    @g.tool()
    def issue_refund(order_id: str, amount_usd: float):
        ran.append((order_id, amount_usd))
        return "ok"

    @g.tool()
    def read_document(key: str):
        return key
    return g, issue_refund, read_document, ran


def test_decorator_denied_body_never_runs():
    g, refund, _, ran = make_guard()
    with g.run("t"), pytest.raises(Denied):
        refund("1042", 5000)
    assert ran == []


def test_decorator_waits_for_approval_then_runs():
    g, refund, _, ran = make_guard(approver=lambda c: "approve")
    with g.run("t"):
        assert refund(order_id="1042", amount_usd=249) == "ok"
    assert ran == [("1042", 249)]


def test_decorator_rejected():
    g, refund, _, ran = make_guard(approver=lambda c: "reject")
    with g.run("t"), pytest.raises(Rejected):
        refund("1042", 249)
    assert ran == []


def test_decorator_raise_mode_then_execute_later():
    g, refund, _, ran = make_guard(on_pending="raise")
    with g.run("t"):
        with pytest.raises(ApprovalPending) as e:
            refund("1042", 249)
        cid = e.value.call_id
        g.client.approve(cid)
        assert g.execute(cid, {"order_id": "1042", "amount_usd": 249}) == "ok"
    assert ran == [("1042", 249)]


def test_call_tool_returns_observations_not_exceptions():
    g, *_ = make_guard(on_pending="raise")
    with g.run("t"):
        assert g.call_tool("read_document", {"key": "public/a.md"}) == {"status": "ok", "result": "public/a.md"}
        assert g.call_tool("read_document", {"key": "hr/a"})["status"] == "denied"
        assert g.call_tool("issue_refund", {"order_id": "1", "amount_usd": 9})["status"] == "pending_approval"
        assert g.call_tool("wire_money", {})["status"] == "denied"


def test_gated_call_outside_run_refused():
    g, _, read, _ = make_guard()
    with pytest.raises(Exception, match="inside"):
        read("public/a.md")


def test_tool_error_recorded_and_reraised():
    g = Guard.local(POLICY, agent="support-bot")

    @g.tool()
    def read_document(key: str):
        raise PermissionError("AccessDenied")
    with g.run("t") as run, pytest.raises(PermissionError):
        read_document("public/a.md")
    res = [e for e in g.client.gate.store.events(run["id"]) if e["step"] == "call.result"][0]
    assert res["data"]["ok"] is False and "AccessDenied" in res["data"]["result"]


def test_credentials_hook_gets_approved_args_only_after_gate():
    seen = []
    g = Guard.local(POLICY, agent="support-bot", approver=lambda c: "approve")

    @g.tool(credentials=lambda args: seen.append(args) or {"token": "scoped"})
    def issue_refund(order_id, amount_usd, credentials=None):
        return credentials
    with g.run("t"):
        with pytest.raises(Denied):
            issue_refund("1", 9999)
        assert seen == []
        assert issue_refund("1042", 249) == {"token": "scoped"}
    assert seen == [{"order_id": "1042", "amount_usd": 249}]
