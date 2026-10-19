"""Lambda function URL for the approver.

GET shows a confirmation page and changes nothing. Only a POST from the button
completes the Step Functions task. That matters: email security scanners open
links automatically, and a GET-to-approve link would let a scanner approve.
"""
import base64
import html
import json
import os
import time
from urllib.parse import parse_qs

import boto3

from common import audit

PAGE = """<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1">
<title>Agent approval</title><style>body{{font-family:system-ui;max-width:560px;margin:40px auto;padding:0 16px;color:#12151C}}
button{{font-size:20px;padding:14px 22px;margin:8px 8px 0 0;border:0;border-radius:10px;color:#fff;cursor:pointer}}
.a{{background:#E0531F}}.r{{background:#4A505E}}</style></head><body>{body}</body></html>"""


def _page(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "text/html; charset=utf-8"}, "body": PAGE.format(body=body)}


def handler(event, _context, sfn=None):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    if method == "GET":
        token = (event.get("queryStringParameters") or {}).get("token", "")
        if not token:
            return _page(400, "<p>Missing approval token.</p>")
        t = html.escape(token, quote=True)
        return _page(200, f"<h2>Approve the agent's action?</h2><p>Check the email for details.</p>"
                          f"<form method=post><input type=hidden name=token value=\"{t}\">"
                          f"<button class=a name=decision value=approve>Approve</button>"
                          f"<button class=r name=decision value=reject>Reject</button></form>")
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    form = {k: v[0] for k, v in parse_qs(raw).items()}
    decision, token = form.get("decision"), form.get("token", "")
    if decision not in ("approve", "reject") or not token:
        return _page(400, "<p>Invalid request.</p>")
    sfn = sfn or boto3.client("stepfunctions")
    out = {"decision": decision, "approver": "human via email link", "decided_at": int(time.time())}
    try:
        sfn.send_task_success(taskToken=token, output=json.dumps(out))
    except sfn.exceptions.TaskTimedOut:
        return _page(410, "<p>This approval request expired.</p>")
    except sfn.exceptions.InvalidToken:
        return _page(400, "<p>This approval link is not valid.</p>")
    audit("", "human_decision", decision=decision)
    word = "Approved" if decision == "approve" else "Rejected"
    return _page(200, f"<h2>{word}.</h2><p>The workflow has been told. You can close this page.</p>")
