"""The deployed gate: one Lambda behind an HTTP API, plus a direct-invoke entry for Step Functions.

Routes and who may call them (enforced by API Gateway authorizers AND re-checked here):

  agent (IAM / SigV4)       POST /v1/runs                  start a run
                            POST /v1/runs/{id}/end
                            POST /v1/runs/{id}/calls       check a tool call
                            GET  /v1/calls/{id}
                            POST /v1/calls/{id}/consume    start executing (once; args must match)
                            POST /v1/calls/{id}/result
  dashboard (Cognito JWT)   GET  /v1/dashboard/{pending,denials,runs,policy}
                            GET  /v1/dashboard/runs/{id}   replay + chain verification
                            POST /v1/dashboard/calls/{id}/decide
  public, verified in code  GET|POST /email/decide         one-time link secret
                            POST /slack/interact           Slack signature + approver allow-list

Step Functions (lambda:InvokeFunction, waitForTaskToken):
  {"op": "attach_task_token", "call": "...", "agent": "...", "token": "..."}
"""

from __future__ import annotations

import base64
import html
import json
import os
import re
from urllib.parse import parse_qs

from agent_guardrails.engine import Approver, Gate, GateError
from agent_guardrails.notify import EmailNotifier, SlackNotifier, email_token_ok, verify_slack
from agent_guardrails.policy import parse
from agent_guardrails.store import DynamoStore

HERE = os.path.dirname(os.path.abspath(__file__))
_gate = None
_principals = None
_slack_secret = None
_request_url = ""


def _policy():
    with open(os.environ.get("POLICY_FILE", os.path.join(HERE, "..", "policy.json"))) as f:
        return parse(json.load(f))


def principals() -> dict:
    """{normalized role ARN: {"agent": name, "execute_for": [...]}} from the PRINCIPALS env var."""
    global _principals
    if _principals is None:
        raw = json.loads(os.environ.get("PRINCIPALS", "{}"))
        _principals = {normalize_arn(arn): v for arn, v in raw.items()}
    return _principals


def normalize_arn(arn: str) -> str:
    m = re.match(r"^arn:(aws[\w-]*):sts::(\d{12}):assumed-role/([\w+=,.@-]+)/[\w+=,.@-]+$", arn or "")
    return f"arn:{m.group(1)}:iam::{m.group(2)}:role/{m.group(3)}" if m else (arn or "")


def slack_config():
    global _slack_secret
    if _slack_secret is None:
        arn = os.environ.get("SLACK_SECRET_ARN")
        if not arn:
            _slack_secret = {}
        else:
            import boto3

            _slack_secret = json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"])
    return _slack_secret


def gate() -> Gate:
    global _gate
    if _gate is None:
        import boto3

        store = DynamoStore(os.environ["TABLE_NAME"])
        notifiers = []
        if os.environ.get("APPROVAL_TOPIC_ARN"):
            # The API URL can't be an env var (API -> Lambda -> API would be a cycle), so the link
            # base comes from the request that triggered the approval.
            notifiers.append(EmailNotifier(os.environ["APPROVAL_TOPIC_ARN"],
                                           lambda: os.environ.get("PUBLIC_URL") or _request_url, store,
                                           dashboard_url=os.environ.get("DASHBOARD_URL", "")))
        slack = slack_config()
        if slack.get("bot_token") and slack.get("channel_id"):
            notifiers.append(SlackNotifier(slack["bot_token"], slack["channel_id"],
                                           os.environ.get("DASHBOARD_URL", "")))
        sfn = boto3.client("stepfunctions")
        _gate = Gate(_policy(), store, notifiers,
                     task_callback=lambda token, out: sfn.send_task_success(taskToken=token, output=json.dumps(out)))
    return _gate


# ---------------- HTTP helpers ----------------
def _json(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body, default=str)}


def _html(status, body):
    page = ("<!doctype html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Agent approval</title><style>body{font-family:system-ui;max-width:640px;margin:40px auto;"
            "padding:0 16px;color:#12151C}pre{background:#f3f4f6;padding:12px;border-radius:8px;white-space:pre-wrap;"
            "word-break:break-word}button{font-size:18px;padding:12px 20px;margin:8px 8px 0 0;border:0;"
            "border-radius:10px;color:#fff;cursor:pointer}.a{background:#E0531F}.r{background:#4A505E}</style>"
            f"</head><body>{body}</body></html>")
    csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    return {"statusCode": status, "body": page,
            "headers": {"Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": csp,
                        "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}}


def _body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    return raw


def _jbody(event):
    raw = _body(event)
    if not raw:
        return {}
    v = json.loads(raw)
    if not isinstance(v, dict):
        raise GateError("body must be a JSON object")
    return v


# ---------------- entry point ----------------
def handler(event, _context=None):
    if "op" in event:  # direct invoke from Step Functions
        return direct(event)
    global _request_url
    route = event.get("routeKey", "")
    path = event.get("pathParameters") or {}
    domain = (event.get("requestContext") or {}).get("domainName", "")
    _request_url = f"https://{domain}" if re.match(r"^[a-z0-9.-]+\.amazonaws\.com$", domain) else ""
    try:
        if route.startswith(("POST /v1/runs", "GET /v1/calls", "POST /v1/calls")):
            return agent_route(route, path, event)
        if route.startswith(("GET /v1/dashboard", "POST /v1/dashboard")):
            return dashboard_route(route, path, event)
        if route == "GET /email/decide":
            return email_page(event)
        if route == "POST /email/decide":
            return email_decide(event)
        if route == "POST /slack/interact":
            return slack_interact(event)
        return _json(404, {"error": "no such route"})
    except GateError as e:
        return _json(e.status, {"error": str(e)})
    except json.JSONDecodeError:
        return _json(400, {"error": "invalid JSON"})


def direct(event):
    if event["op"] == "attach_task_token":
        return gate().attach_task_token(event["call"], event["agent"], event["token"])
    raise ValueError(f"unknown op {event['op']}")


def caller(event) -> dict:
    arn = (((event.get("requestContext") or {}).get("authorizer") or {}).get("iam") or {}).get("userArn", "")
    p = principals().get(normalize_arn(arn))
    if not p:
        raise GateError(f"caller {normalize_arn(arn) or '(unsigned)'} is not a registered agent", 403)
    return p


def agent_route(route, path, event):
    p = caller(event)
    agent, g = p.get("agent", ""), gate()
    body = _jbody(event) if route.startswith("POST") else {}
    if route == "POST /v1/runs":
        if not agent:
            raise GateError("this principal is an executor, not an agent", 403)
        return _json(201, g.start_run(agent, body.get("task", ""), body.get("meta") or {}))
    if route == "POST /v1/runs/{id}/end":
        return _json(200, g.end_run(path["id"], agent, str(body.get("status", "finished"))[:20],
                                    body.get("answer", "")))
    if route == "POST /v1/runs/{id}/calls":
        return _json(201, g.check(path["id"], agent, str(body.get("tool", "")), body.get("args"),
                                  body.get("context", "")))
    execute_for = set(p.get("execute_for") or [])
    if route == "GET /v1/calls/{id}":
        call = g.get_call(path["id"])
        if call["agent"] != agent and call["agent"] not in execute_for:
            raise GateError("no such call", 404)
        return _json(200, g.view(call))
    if route == "POST /v1/calls/{id}/consume":
        return _json(200, g.consume(path["id"], agent or "executor", body.get("args"), execute_for))
    if route == "POST /v1/calls/{id}/result":
        return _json(200, g.record_result(path["id"], agent or "executor", bool(body.get("ok")), body.get("result"),
                                          execute_for))
    return _json(404, {"error": "no such route"})


def human(event) -> Approver:
    claims = ((((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {})
    email = (claims.get("email") or "").lower()
    if not claims.get("sub"):
        raise GateError("sign in required", 401)
    return Approver("dashboard", email or claims["sub"], email or claims.get("cognito:username", ""))


def allowed_emails(g):
    emails = (g.policy.approvers or {}).get("emails")
    return {e.lower() for e in emails} if emails else None


def dashboard_route(route, path, event):
    who, g = human(event), gate()
    qs = event.get("queryStringParameters") or {}
    limit = max(1, min(int(qs.get("limit", 50)), 200))
    if route == "GET /v1/dashboard/pending":
        return _json(200, {"items": g.pending(limit), "you": who.to_dict()})
    if route == "GET /v1/dashboard/denials":
        return _json(200, {"items": g.denials(limit)})
    if route == "GET /v1/dashboard/runs":
        return _json(200, {"items": g.runs(limit)})
    if route == "GET /v1/dashboard/runs/{id}":
        return _json(200, g.replay(path["id"]))
    if route == "GET /v1/dashboard/policy":
        return _json(200, g.policy.to_dict())
    if route == "POST /v1/dashboard/calls/{id}/decide":
        body = _jbody(event)
        return _json(200, g.decide(path["id"], str(body.get("decision")), who, body.get("note", ""),
                                   allowed_emails(g)))
    return _json(404, {"error": "no such route"})


# ---------------- email ----------------
def email_page(event):
    qs = event.get("queryStringParameters") or {}
    call_id, secret = qs.get("call", ""), qs.get("t", "")
    try:
        call = gate().get_call(call_id)
    except GateError:
        return _html(404, "<p>This approval link is not valid.</p>")
    if not email_token_ok(call, secret):
        return _html(403, "<p>This approval link is not valid.</p>")
    if call["state"] != "pending":
        return _html(410, f"<p>This request is already <b>{html.escape(call['state'])}</b>.</p>")
    args = html.escape(json.dumps(call["args"], indent=1, sort_keys=True, default=str))
    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    return _html(200, f"<h2>Approve <code>{e(call['tool'])}</code>?</h2><p>Agent <b>{e(call['agent'])}</b>, "
                      f"rule <code>{e(call['rule'])}</code>.</p><pre>{args}</pre>"
                      f"<form method=post><input type=hidden name=call value='{e(call_id)}'>"
                      f"<input type=hidden name=t value='{e(secret)}'>"
                      "<button class=a name=decision value=approve>Approve</button>"
                      "<button class=r name=decision value=reject>Reject</button></form>")


def email_decide(event):
    form = {k: v[0] for k, v in parse_qs(_body(event)).items()}
    call_id, secret, decision = form.get("call", ""), form.get("t", ""), form.get("decision")
    if decision not in ("approve", "reject"):
        return _html(400, "<p>Invalid request.</p>")
    g = gate()
    try:
        call = g.get_call(call_id)
    except GateError:
        return _html(404, "<p>This approval link is not valid.</p>")
    if not email_token_ok(call, secret):
        return _html(403, "<p>This approval link is not valid.</p>")
    try:
        g.decide(call_id, decision, Approver("email", "email-link", "approver via email link"))
    except GateError as e:
        return _html(e.status, f"<p>{html.escape(str(e))}</p>")
    word = "Approved" if decision == "approve" else "Rejected"
    return _html(200, f"<h2>{word}.</h2><p>The agent has been told. You can close this page.</p>")


# ---------------- slack ----------------
def slack_interact(event):
    cfg = slack_config()
    raw = _body(event)
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    ts, sig = headers.get("x-slack-request-timestamp", ""), headers.get("x-slack-signature", "")
    if not cfg.get("signing_secret") or not verify_slack(cfg["signing_secret"], ts, raw, sig):
        return _json(401, {"error": "bad signature"})
    payload = json.loads(parse_qs(raw).get("payload", ["{}"])[0])
    user = (payload.get("user") or {}).get("id", "")
    actions = payload.get("actions") or []
    if not actions:
        return _json(200, {})
    act = actions[0]
    allowed = set((gate().policy.approvers or {}).get("slack_user_ids") or [])
    decision = {"approve": "approve", "reject": "reject"}.get(act.get("action_id"))
    if not decision:
        return _json(200, {})
    try:
        gate().decide(act.get("value", ""), decision,
                      Approver("slack", user, (payload.get("user") or {}).get("username", user)), "",
                      allowed if allowed else set())  # no allow-list configured = nobody may approve via Slack
        text = f"{'Approved' if decision == 'approve' else 'Rejected'} by <@{user}>."
    except GateError as e:
        text = f"Not recorded: {e}"
    return _json(200, {"replace_original": False, "response_type": "ephemeral", "text": text})
