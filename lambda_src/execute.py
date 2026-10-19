"""Runs only after a human approved. Simulated send: writes the message to the outbox prefix."""
import json
import os

import boto3

from common import audit

BUCKET = os.environ.get("DATA_BUCKET", "")


def handler(event, _context, s3=None):
    s3 = s3 or boto3.client("s3")
    execution = event.get("execution", "local")
    run_id = execution.rsplit(":", 1)[-1]
    keys = []
    for i, action in enumerate(event.get("actions", []), 1):
        key = f"outbox/{run_id}-{i}.json"
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps({"status": "SENT (simulated)", **action}, indent=2).encode(),
                      ContentType="application/json")
        audit(execution, "action_executed", action_type=action.get("action_type"), to=action.get("to"), outbox_key=key,
              note="simulated: written to S3 outbox, no real email")
        keys.append(key)
    return {"executed": keys}
