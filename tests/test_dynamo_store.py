"""DynamoStore against moto: the conditional writes that make the deployed gate race-safe."""

import os
import threading

import boto3
import pytest
from moto import mock_aws

from agent_guardrails import Approver, Gate, GateError, load
from agent_guardrails.audit import verify
from agent_guardrails.store import DynamoStore

POLICY = "examples/support_agent/policy.yaml"


def create_table(ddb, name="gate"):
    ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in
                              ("pk", "sk", "gsi1pk", "gsi1sk", "gsi2pk", "gsi2sk")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        GlobalSecondaryIndexes=[
            {"IndexName": f"gsi{i}", "Projection": {"ProjectionType": "ALL"},
             "KeySchema": [{"AttributeName": f"gsi{i}pk", "KeyType": "HASH"},
                           {"AttributeName": f"gsi{i}sk", "KeyType": "RANGE"}]} for i in (1, 2)])


@pytest.fixture
def gate():
    os.environ.update(AWS_DEFAULT_REGION="us-west-2", AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing")
    os.environ.pop("AWS_PROFILE", None)
    with mock_aws():
        res = boto3.resource("dynamodb", region_name="us-west-2")
        create_table(res.meta.client)
        yield Gate(load(POLICY), DynamoStore("gate", res))


H = Approver("dashboard", "tim@aitecxo.com")


def test_full_lifecycle_and_chain(gate):
    run = gate.start_run("support-bot", "refund 1042")["id"]
    a = gate.check(run, "support-bot", "read_document", {"key": "public/a.md"})
    gate.consume(a["id"], "support-bot", {"key": "public/a.md"})
    gate.record_result(a["id"], "support-bot", True, {"bytes": 10})
    p = gate.check(run, "support-bot", "issue_refund", {"order_id": "1042", "amount_usd": 249.5})
    assert [c["id"] for c in gate.pending()] == [p["id"]]
    gate.decide(p["id"], "approve", H)
    assert gate.pending() == []
    granted = gate.consume(p["id"], "support-bot", {"order_id": "1042", "amount_usd": 249.5})
    assert granted["args"]["amount_usd"] == 249.5  # floats survive the Decimal round trip
    d = gate.check(run, "support-bot", "read_document", {"key": "hr/x.csv"})
    assert [c["id"] for c in gate.denials()] == [d["id"]]
    rep = gate.replay(run)
    steps = [e["step"] for e in rep["events"]]
    assert steps == ["run.started", "call.allowed", "call.executing", "call.result", "approval.requested",
                     "approval.decided", "call.executing", "call.denied"]
    assert rep["chain"]["ok"] and rep["chain"]["count"] == 8
    assert [c["id"] for c in rep["calls"]] == [a["id"], p["id"], d["id"]]
    assert gate.runs()[0]["id"] == run


def test_conditional_transition_blocks_double_execute(gate):
    run = gate.start_run("support-bot", "t")["id"]
    c = gate.check(run, "support-bot", "read_document", {"key": "public/a.md"})
    gate.consume(c["id"], "support-bot")
    with pytest.raises(GateError) as e:
        gate.consume(c["id"], "support-bot")
    assert e.value.status == 409


def test_counter_limit_is_conditional(gate):
    run = gate.start_run("support-bot", "t")["id"]
    assert gate.check(run, "support-bot", "issue_refund", {"order_id": "1", "amount_usd": 1})["state"] == "pending"
    assert gate.check(run, "support-bot", "issue_refund", {"order_id": "2", "amount_usd": 1})["state"] == "denied"


def test_duplicate_run_id_rejected(gate):
    gate.start_run("support-bot", "t", run_id="run_fixed")
    with pytest.raises(GateError) as e:
        gate.start_run("support-bot", "t", run_id="run_fixed")
    assert e.value.status == 409


def test_concurrent_audit_appends_keep_one_chain(gate):
    run = gate.start_run("support-bot", "t")["id"]
    errs = []

    def go(i):
        try:
            gate.store.append_event(run, "probe", "support-bot", "", {"i": i})
        except Exception as e:  # pragma: no cover
            errs.append(e)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    ev = gate.store.events(run)
    assert not errs and len(ev) == 7 and verify(ev)["ok"]


def test_tampering_in_table_detected(gate):
    run = gate.start_run("support-bot", "t")["id"]
    gate.check(run, "support-bot", "read_document", {"key": "hr/x.csv"})
    gate.store.table.update_item(Key={"pk": f"RUN#{run}", "sk": "EV#00000001"},
                                 UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "step"},
                                 ExpressionAttributeValues={":s": "call.allowed"})
    assert gate.replay(run)["chain"] == {"ok": False, "count": 2, "broken_at": 1, "why": "hash mismatch"}
