"""The agent: a Bedrock Converse tool-use loop with exactly two tools.

- read_document: reads from S3 using THIS function's IAM role. There is no
  application-level allow-list on purpose: IAM is the only thing stopping a
  restricted read, so the demo shows the limit living outside the model and
  outside the app code.
- propose_action: records a customer-facing action for a human to approve.
  The agent has no tool that sends anything, and its role cannot change the
  workflow that requires approval.
"""
import json
import os
import re

import boto3
from botocore.exceptions import ClientError

from common import audit

MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
BUCKET = os.environ.get("DATA_BUCKET", "")
MODEL_MODE = os.environ.get("MODEL_MODE", "bedrock")  # "bedrock" | "scripted" (rehearsal only)
MAX_TURNS = 6
ACTION_TYPES = ("send_customer_email", "issue_refund")

SYSTEM = (
    "You are an operations assistant for Acme Outdoor Gear. Use read_document to read any company "
    "file the user names. You cannot send, refund, or change anything yourself: use propose_action "
    "for a customer-facing action (at most one per request) and a human will approve or reject it. "
    "When asked to reply to or draft a message for a customer, put the message in propose_action "
    "instead of writing it in your answer; do not ask whether to propose it. "
    "If a tool returns an error, report it plainly and do not guess the content. Keep answers short."
)

TOOLS = [
    {"toolSpec": {
        "name": "read_document",
        "description": "Read any company file (markdown, text, or CSV) from the document store by its key, e.g. public/refund-policy.md or finance/report.csv.",
        "inputSchema": {"json": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}},
    }},
    {"toolSpec": {
        "name": "propose_action",
        "description": "Propose a customer-facing action. It is NOT executed: a human must approve it first.",
        "inputSchema": {"json": {
            "type": "object",
            "properties": {
                "action_type": {"type": "string", "enum": list(ACTION_TYPES)},
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
                "amount_usd": {"type": "number"},
            },
            "required": ["action_type", "to", "body"],
        }},
    }},
]


def read_document(s3, key, execution):
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
        text = obj["Body"].read().decode("utf-8")[:6000]
        audit(execution, "tool_allowed", tool="read_document", key=key, bytes=len(text))
        return {"key": key, "content": text}, "success"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Error")
        audit(execution, "tool_denied", tool="read_document", key=key, error=code,
              enforced_by="IAM policy on the agent's role")
        return {"error": f"{code}: the agent's IAM role is not permitted to read {key}"}, "error"


def propose_action(args, proposed, execution):
    if proposed:
        audit(execution, "proposal_rejected", reason="one action per request", args=args)
        return {"error": "only one action can be proposed per request; one is already queued"}, "error"
    if args.get("action_type") not in ACTION_TYPES:
        audit(execution, "proposal_rejected", reason="unknown action_type", args=args)
        return {"error": "unknown action_type"}, "error"
    proposed.append(args)
    audit(execution, "action_proposed", action=args)
    return {"status": "queued for human approval; nothing has been sent"}, "success"


def run_agent(task, execution="local", bedrock=None, s3=None):
    bedrock = bedrock or (ScriptedModel() if MODEL_MODE == "scripted" else boto3.client("bedrock-runtime"))
    s3 = s3 or boto3.client("s3")
    audit(execution, "task_received", task=task, model=MODEL_ID, mode=MODEL_MODE)
    messages = [{"role": "user", "content": [{"text": task}]}]
    proposed, answer = [], ""
    for turn in range(MAX_TURNS):
        resp = bedrock.converse(
            modelId=MODEL_ID, system=[{"text": SYSTEM}], messages=messages,
            toolConfig={"tools": TOOLS}, inferenceConfig={"maxTokens": 800},
        )
        msg = resp["output"]["message"]
        messages.append(msg)
        texts = [c["text"] for c in msg["content"] if "text" in c]
        uses = [c["toolUse"] for c in msg["content"] if "toolUse" in c]
        if texts:
            answer = re.sub(r"</?response>", "", re.sub(r"<thinking>.*?</thinking>", "", "\n".join(texts), flags=re.S)).strip()
        if resp.get("stopReason") != "tool_use" or not uses:
            break
        results = []
        for u in uses:
            audit(execution, "tool_requested", tool=u["name"], input=u.get("input", {}))
            if u["name"] == "read_document":
                out, status = read_document(s3, str(u.get("input", {}).get("key", "")), execution)
            elif u["name"] == "propose_action":
                out, status = propose_action(u.get("input", {}), proposed, execution)
            else:
                out, status = {"error": "unknown tool"}, "error"
            results.append({"toolResult": {"toolUseId": u["toolUseId"], "content": [{"json": out}], "status": status}})
        messages.append({"role": "user", "content": results})
    else:
        audit(execution, "turn_limit_reached", max_turns=MAX_TURNS)
    audit(execution, "agent_finished", answer=answer, proposed_actions=len(proposed))
    return {"answer": answer, "proposed_actions": proposed, "mode": MODEL_MODE}


def handler(event, _context):
    return run_agent(event["task"], execution=event.get("execution", "local"))


class ScriptedModel:
    """Rehearsal-only stand-in for Bedrock (MODEL_MODE=scripted). Labeled in every result.

    It never runs unless explicitly configured, and the agent reports mode="scripted".
    It exists so the AWS wiring (IAM, approval workflow, logs) can be tested end to end
    without model access, and as a clearly-announced fallback if conference Wi-Fi fails.
    """

    def converse(self, messages, **_):
        task = messages[0]["content"][0]["text"].lower()
        last = messages[-1]
        tool_results = [c["toolResult"] for c in last["content"] if "toolResult" in c] if last["role"] == "user" else []
        n_tool_turns = sum(1 for m in messages if m["role"] == "user" and any("toolResult" in c for c in m["content"]))

        def use(name, inp, i):
            return {"toolUse": {"toolUseId": f"t{i}", "name": name, "input": inp}}

        def reply(content, stop):
            return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop}

        if "hr/" in task:
            key = task[task.index("hr/"):].split()[0].strip(".,")
            if n_tool_turns == 0:
                return reply([{"text": "[scripted] Reading the file."}, use("read_document", {"key": key}, 1)], "tool_use")
            err = tool_results[0]["content"][0]["json"].get("error", "")
            return reply([{"text": f"[scripted] I couldn't read that file: {err}"}], "end_turn")
        if "refund" in task:
            if n_tool_turns == 0:
                return reply([use("read_document", {"key": "public/ticket-1042.md"}, 1),
                              use("read_document", {"key": "public/refund-policy.md"}, 2)], "tool_use")
            if n_tool_turns == 1:
                return reply([use("propose_action", {
                    "action_type": "send_customer_email", "to": "jordan.lee@example.com",
                    "subject": "Your refund request #1042",
                    "body": "[scripted] Hi Jordan, your tent was returned within 30 days, so you qualify for a full refund of $249. It will reach your card in 5-7 business days.",
                }, 3)], "tool_use")
            return reply([{"text": "[scripted] I drafted a reply and sent it for human approval."}], "end_turn")
        return reply([{"text": "[scripted] No tools needed."}], "end_turn")
