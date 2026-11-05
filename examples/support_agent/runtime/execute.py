"""Runs ONLY approved (or policy-allowed) calls, with a role the agent doesn't have.

Invoked by Step Functions after the approval wait. It asks the gate to consume the
call (succeeds once; the gate returns the arguments the human saw), performs it,
and records the result. Sending and refunding are simulated: both write a JSON
file to s3://<bucket>/outbox/. Nothing reaches a real customer or payment system.
"""

from __future__ import annotations

import json
import os

from agent_guardrails.sdk import HttpClient

SIMULATED = {"send_customer_email": "SENT (simulated)", "issue_refund": "REFUNDED (simulated)"}


def perform(s3, bucket, call, args):
    if call["tool"] not in SIMULATED:
        raise ValueError(f"executor does not implement {call['tool']}")
    key = f"outbox/{call['run']}/{call['id']}.json"
    s3.put_object(Bucket=bucket, Key=key, ContentType="application/json",
                  Body=json.dumps({"status": SIMULATED[call["tool"]], "tool": call["tool"], "args": args,
                                   "approved_by": call.get("approver")}, indent=2).encode())
    return {"outbox_key": key}


def handler(event, _context, client=None, s3=None):
    import boto3

    client = client or HttpClient(os.environ["GATE_API_URL"])
    s3 = s3 or boto3.client("s3")
    call_id = event["call"]
    granted = client.consume(call_id, "executor", None)
    try:
        out = perform(s3, os.environ["DATA_BUCKET"], granted, granted["args"])
    except Exception as e:
        client.record_result(call_id, "executor", False, f"{type(e).__name__}: {e}")
        raise
    client.record_result(call_id, "executor", True, out)
    return {"call": call_id, "tool": granted["tool"], **out}
