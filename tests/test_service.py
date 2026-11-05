"""The deployed Lambda handler: routing, caller identity, email links, Slack signatures. moto for AWS."""

import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlencode

import boto3
import pytest
from moto import mock_aws

from tests.test_dynamo_store import create_table

AGENT_ROLE = "arn:aws:iam::123456789012:role/AgentRole"
EXEC_ROLE = "arn:aws:iam::123456789012:role/ExecRole"
SLACK = {"bot_token": "xoxb-test", "signing_secret": "shh", "channel_id": "C1"}


@pytest.fixture
def svc(tmp_path):
    import yaml

    os.environ.update(AWS_DEFAULT_REGION="us-west-2", AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing")
    os.environ.pop("AWS_PROFILE", None)
    doc = yaml.safe_load(open("examples/support_agent/policy.yaml"))
    doc["approval"]["approvers"] = {"emails": ["tim@aitecxo.com"], "slack_user_ids": ["U_TIM"]}
    (tmp_path / "policy.json").write_text(json.dumps(doc))
    with mock_aws():
        create_table(boto3.client("dynamodb", region_name="us-west-2"))
        topic = boto3.client("sns", region_name="us-west-2").create_topic(Name="approvals")["TopicArn"]
        secret = boto3.client("secretsmanager", region_name="us-west-2").create_secret(
            Name="slack", SecretString=json.dumps(SLACK))["ARN"]
        os.environ.update(TABLE_NAME="gate", POLICY_FILE=str(tmp_path / "policy.json"), APPROVAL_TOPIC_ARN=topic,
                          SLACK_SECRET_ARN=secret,
                          PRINCIPALS=json.dumps({AGENT_ROLE: {"agent": "support-bot"},
                                                 EXEC_ROLE: {"agent": "", "execute_for": ["support-bot"]}}))
        from service import handler as h

        h._gate = h._principals = h._slack_secret = None
        sent = []
        yield h, sent
        h._gate = h._principals = h._slack_secret = None


def iam_event(route, role=AGENT_ROLE, body=None, path=None):
    arn = role.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/") + "/session-1" if role else ""
    return {"routeKey": route, "pathParameters": path or {}, "body": json.dumps(body) if body is not None else None,
            "requestContext": {"domainName": "abc123.execute-api.us-west-2.amazonaws.com",
                               "authorizer": {"iam": {"userArn": arn}} if arn else {}}}


def jwt_event(route, email="tim@aitecxo.com", body=None, path=None):
    return {"routeKey": route, "pathParameters": path or {}, "body": json.dumps(body) if body is not None else None,
            "requestContext": {"domainName": "abc123.execute-api.us-west-2.amazonaws.com",
                               "authorizer": {"jwt": {"claims": {"sub": "u-1", "email": email}}}}}


def call(h, ev):
    r = h.handler(ev)
    return r["statusCode"], json.loads(r["body"]) if r["headers"]["Content-Type"].startswith("application/json") \
        else r["body"]


def start_and_request_refund(h, monkeypatch=None):
    s, run = call(h, iam_event("POST /v1/runs", body={"task": "refund"}))
    assert s == 201
    s, c = call(h, iam_event("POST /v1/runs/{id}/calls", path={"id": run["id"]},
                             body={"tool": "issue_refund", "args": {"order_id": "1042", "amount_usd": 249}}))
    assert s == 201 and c["state"] == "pending"
    return run, c


@pytest.fixture(autouse=True)
def no_slack_network(monkeypatch):
    from agent_guardrails import notify

    posted = []
    monkeypatch.setattr(notify, "_post_json", lambda url, body, tok: posted.append(body) or {"ok": True, "ts": "1"})
    return posted


def test_unregistered_caller_refused(svc):
    h, _ = svc
    s, b = call(h, iam_event("POST /v1/runs", role="arn:aws:iam::123456789012:role/Mallory", body={"task": "x"}))
    assert s == 403 and "not a registered agent" in b["error"]
    s, _ = call(h, iam_event("POST /v1/runs", role="", body={"task": "x"}))
    assert s == 403


def test_executor_cannot_start_runs_or_check(svc):
    h, _ = svc
    s, b = call(h, iam_event("POST /v1/runs", role=EXEC_ROLE, body={"task": "x"}))
    assert s == 403


def test_dashboard_approval_then_executor_consumes(svc, no_slack_network):
    h, _ = svc
    run, c = start_and_request_refund(h)
    assert no_slack_network and no_slack_network[0]["channel"] == "C1"  # Slack got the buttons
    s, pend = call(h, jwt_event("GET /v1/dashboard/pending"))
    assert s == 200 and [x["id"] for x in pend["items"]] == [c["id"]]
    assert "email_token_hash" not in pend["items"][0]
    # agent can't execute before approval
    s, _ = call(h, iam_event("POST /v1/calls/{id}/consume", path={"id": c["id"]}, body={}))
    assert s == 409
    s, d = call(h, jwt_event("POST /v1/dashboard/calls/{id}/decide", path={"id": c["id"]},
                             body={"decision": "approve", "note": "matches policy"}))
    assert s == 200 and d["state"] == "approved" and d["approver"]["id"] == "tim@aitecxo.com"
    s, g = call(h, iam_event("POST /v1/calls/{id}/consume", role=EXEC_ROLE, path={"id": c["id"]}, body={}))
    assert s == 200 and g["args"] == {"order_id": "1042", "amount_usd": 249}
    s, _ = call(h, iam_event("POST /v1/calls/{id}/result", role=EXEC_ROLE, path={"id": c["id"]},
                             body={"ok": True, "result": {"outbox": "k"}}))
    assert s == 200
    s, rep = call(h, jwt_event("GET /v1/dashboard/runs/{id}", path={"id": run["id"]}))
    assert rep["chain"]["ok"]
    steps = [e["step"] for e in rep["events"]]
    assert steps == ["run.started", "approval.requested", "approval.notified", "approval.notified",
                     "approval.decided", "call.executing", "call.result"]


def test_dashboard_user_not_in_approvers_refused(svc):
    h, _ = svc
    _, c = start_and_request_refund(h)
    s, b = call(h, jwt_event("POST /v1/dashboard/calls/{id}/decide", email="mallory@example.com",
                             path={"id": c["id"]}, body={"decision": "approve"}))
    assert s == 403


def test_dashboard_requires_claims(svc):
    h, _ = svc
    s, _ = call(h, {"routeKey": "GET /v1/dashboard/pending", "requestContext": {}})
    assert s == 401


def email_secret_from_sns():
    """Read back the link moto's SNS backend recorded (the only place the secret exists)."""
    from moto.core import DEFAULT_ACCOUNT_ID
    from moto.sns.models import sns_backends

    msgs = [m for t in sns_backends[DEFAULT_ACCOUNT_ID]["us-west-2"].topics.values() for m in t.sent_notifications]
    body = msgs[-1][1] if isinstance(msgs[-1], tuple) else msgs[-1]
    link = [line for line in body.splitlines() if "/email/decide?" in line][0].strip()
    return link


def test_email_link_get_is_safe_post_decides(svc):
    h, _ = svc
    _, c = start_and_request_refund(h)
    link = email_secret_from_sns()
    assert link.startswith("https://abc123.execute-api.us-west-2.amazonaws.com/email/decide?call=")
    qs = dict(x.split("=", 1) for x in link.split("?", 1)[1].split("&"))
    r = h.handler({"routeKey": "GET /email/decide", "queryStringParameters": {"call": qs["call"], "t": qs["t"]}})
    assert r["statusCode"] == 200 and "method=post" in r["body"] and "1042" in r["body"]
    assert h.gate().get_call(c["id"])["state"] == "pending"  # GET changed nothing
    bad = h.handler({"routeKey": "POST /email/decide", "body": urlencode({"call": c["id"], "t": "guess",
                                                                         "decision": "approve"})})
    assert bad["statusCode"] == 403
    ok = h.handler({"routeKey": "POST /email/decide", "body": urlencode({"call": c["id"], "t": qs["t"],
                                                                        "decision": "reject"})})
    assert ok["statusCode"] == 200 and h.gate().get_call(c["id"])["state"] == "rejected"
    again = h.handler({"routeKey": "POST /email/decide", "body": urlencode({"call": c["id"], "t": qs["t"],
                                                                           "decision": "approve"})})
    assert again["statusCode"] == 409


def slack_event(payload, secret="shh", ts=None):  # noqa: S107 (test fixture)
    body = urlencode({"payload": json.dumps(payload)})
    ts = str(int(ts or time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
    return {"routeKey": "POST /slack/interact", "body": body,
            "headers": {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}}


def test_slack_signature_and_allow_list(svc):
    h, _ = svc
    _, c = start_and_request_refund(h)
    click = lambda user: {"user": {"id": user, "username": user}, "actions": [  # noqa: E731
        {"action_id": "approve", "value": c["id"]}]}
    assert h.handler(slack_event(click("U_TIM"), secret="wrong"))["statusCode"] == 401
    assert h.handler(slack_event(click("U_TIM"), ts=time.time() - 600))["statusCode"] == 401  # replay window
    r = h.handler(slack_event(click("U_MALLORY")))
    assert "Not recorded" in json.loads(r["body"])["text"]
    assert h.gate().get_call(c["id"])["state"] == "pending"
    r = h.handler(slack_event(click("U_TIM")))
    assert "Approved by <@U_TIM>" in json.loads(r["body"])["text"]
    assert h.gate().get_call(c["id"])["approver"] == {"channel": "slack", "id": "U_TIM", "name": "U_TIM"}


def test_args_mismatch_through_api(svc):
    h, _ = svc
    _, c = start_and_request_refund(h)
    call(h, jwt_event("POST /v1/dashboard/calls/{id}/decide", path={"id": c["id"]}, body={"decision": "approve"}))
    s, b = call(h, iam_event("POST /v1/calls/{id}/consume", path={"id": c["id"]},
                             body={"args": {"order_id": "1042", "amount_usd": 2490}}))
    assert s == 409 and "differ" in b["error"]


def test_direct_invoke_attach_token(svc):
    h, _ = svc
    _, c = start_and_request_refund(h)
    out = h.handler({"op": "attach_task_token", "call": c["id"], "agent": "support-bot", "token": "T"})
    assert out["state"] == "pending"


def test_bad_json_and_unknown_route(svc):
    h, _ = svc
    ev = iam_event("POST /v1/runs")
    ev["body"] = "{not json"
    assert h.handler(ev)["statusCode"] == 400
    assert h.handler({"routeKey": "GET /nope"})["statusCode"] == 404
