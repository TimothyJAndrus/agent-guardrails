"""Step Functions waitForTaskToken step: email the approver links to approve or reject."""
import json
import os
from urllib.parse import quote

import boto3

from common import audit

TOPIC_ARN = os.environ.get("APPROVAL_TOPIC_ARN", "")
DECIDE_URL = os.environ.get("DECIDE_URL", "")


def build_message(actions, token, execution):
    link = f"{DECIDE_URL.rstrip('/')}/?token={quote(token, safe='')}"
    lines = ["Your support agent wants to take this action:", ""]
    for i, a in enumerate(actions, 1):
        lines += [f"{i}. {a.get('action_type')}  to: {a.get('to')}",
                  f"   subject: {a.get('subject', '')}",
                  f"   body: {a.get('body', '')}"]
        if a.get("amount_usd") is not None:
            lines.append(f"   amount: ${a['amount_usd']}")
        lines.append("")
    lines += ["Review and approve or reject (opens a confirmation page):", link, "",
              f"Execution: {execution}", "Nothing is sent until you approve."]
    return "\n".join(lines)


def handler(event, _context, sns=None):
    sns = sns or boto3.client("sns")
    actions, token, execution = event["actions"], event["token"], event.get("execution", "")
    sns.publish(TopicArn=TOPIC_ARN, Subject="Approval needed: agent action",
                Message=build_message(actions, token, execution))
    audit(execution, "approval_requested", actions=len(actions), channel="email (SNS)")
    return {"status": "waiting"}
