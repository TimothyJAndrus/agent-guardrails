"""Support agent: a Bedrock Converse tool-use loop where every tool call goes through the gate.

The model sees three ordinary tools. It is not told which ones need approval:
the policy decides that, outside the model and outside this code.

- read_document        executed here, with this function's IAM role (public/* only)
- send_customer_email  never executed here: this role has no permission to send.
- issue_refund         The gate records the call; a human approves; the Execute
                       function (a different role) runs it.

Runs locally (`python -m examples.support_agent.local`) or as a Lambda.
"""

from __future__ import annotations

import os
import re

from agent_guardrails import Guard

MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
MAX_TURNS = 6
EXECUTOR_TOOLS = {"send_customer_email", "issue_refund"}  # run later by the Execute function, never here

SYSTEM = (
    "You are an operations assistant for Acme Outdoor Gear. Use read_document to read any company file the user "
    "names. Use send_customer_email to reply to a customer and issue_refund to refund an order; call them directly "
    "when the task calls for it, without asking first. Some actions are reviewed by a person before they happen: if "
    "a tool says an action is pending approval, tell the user it is waiting for approval, not that it is done. If a "
    "tool returns an error or a denial, report it plainly and do not guess. Keep answers short."
)

TOOLS = [
    {"toolSpec": {
        "name": "read_document",
        "description": "Read any company file (markdown, text, or CSV) by key, e.g. public/refund-policy.md.",
        "inputSchema": {"json": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}},
    }},
    {"toolSpec": {
        "name": "send_customer_email",
        "description": "Send an email to a customer.",
        "inputSchema": {"json": {"type": "object", "properties": {
            "to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "subject", "body"]}},
    }},
    {"toolSpec": {
        "name": "issue_refund",
        "description": "Refund an order to the customer's original payment method.",
        "inputSchema": {"json": {"type": "object", "properties": {
            "order_id": {"type": "string"}, "amount_usd": {"type": "number"}},
            "required": ["order_id", "amount_usd"]}},
    }},
]


def make_read_document(guard: Guard, s3, bucket: str):
    @guard.tool()
    def read_document(key: str):
        """Read with THIS process's credentials. The policy allows public/*; IAM is the second wall."""
        from botocore.exceptions import ClientError

        try:
            return {"key": key, "content": s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()[:6000]}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Error")
            raise PermissionError(f"{code}: this agent's IAM role cannot read {key}") from None

    return read_document


def clean(text: str) -> str:
    return re.sub(r"</?response>", "", re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.S)).strip()


def run_agent(task: str, guard: Guard, model, s3, bucket: str, run_meta: dict | None = None) -> dict:
    make_read_document(guard, s3, bucket)
    messages = [{"role": "user", "content": [{"text": task}]}]
    answer, calls = "", []
    with guard.run(task, meta=run_meta or {}) as run:
        for _ in range(MAX_TURNS):
            resp = model.converse(modelId=MODEL_ID, system=[{"text": SYSTEM}], messages=messages,
                                  toolConfig={"tools": TOOLS}, inferenceConfig={"maxTokens": 800})
            msg = resp["output"]["message"]
            messages.append(msg)
            texts = [c["text"] for c in msg["content"] if "text" in c]
            uses = [c["toolUse"] for c in msg["content"] if "toolUse" in c]
            if texts:
                answer = clean("\n".join(texts))
            if resp.get("stopReason") != "tool_use" or not uses:
                break
            results = []
            for u in uses:
                name, args = u["name"], u.get("input") or {}
                out = guard.call_tool(name, args, execute=name not in EXECUTOR_TOOLS)
                if out.get("call"):
                    calls.append({"id": out["call"], "tool": name, "status": out["status"]})
                ok = out["status"] in ("ok", "allowed", "pending_approval")
                results.append({"toolResult": {"toolUseId": u["toolUseId"], "content": [{"json": out}],
                                               "status": "success" if ok else "error"}})
            messages.append({"role": "user", "content": results})
    handoff = [c for c in calls if c["tool"] in EXECUTOR_TOOLS and c["status"] in ("allowed", "pending_approval")]
    return {"run": run["id"], "answer": answer, "calls": calls, "handoff": handoff}


def handler(event, _context):
    import boto3

    guard = Guard.remote(os.environ["GATE_API_URL"], agent=os.environ.get("AGENT_NAME", "support-bot"))
    model = ScriptedModel() if os.environ.get("MODEL_MODE") == "scripted" else boto3.client("bedrock-runtime")
    return run_agent(event["task"], guard, model, boto3.client("s3"), os.environ["DATA_BUCKET"],
                     {"execution": event.get("execution", "")})


class ScriptedModel:
    """Rehearsal/test stand-in for Bedrock (MODEL_MODE=scripted). Every answer starts with [scripted]."""

    def converse(self, messages, **_):
        task = messages[0]["content"][0]["text"].lower()
        n = sum(1 for m in messages if m["role"] == "user" and any("toolResult" in c for c in m["content"]))
        last = [c["toolResult"] for c in messages[-1]["content"] if "toolResult" in c] if n else []

        def use(name, inp, i):
            return {"toolUse": {"toolUseId": f"t{i}", "name": name, "input": inp}}

        def reply(content, stop="end_turn"):
            return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop}

        if "hr/" in task:
            key = task[task.index("hr/"):].split()[0].strip(".,")
            if n == 0:
                return reply([{"text": "[scripted] Reading the file."}, use("read_document", {"key": key}, 1)],
                             "tool_use")
            err = last[0]["content"][0]["json"].get("error")
            return reply([{"text": f"[scripted] I couldn't read that file: {err}"}])
        if "refund" in task:
            if n == 0:
                return reply([use("read_document", {"key": "public/ticket-1042.md"}, 1),
                              use("read_document", {"key": "public/refund-policy.md"}, 2)], "tool_use")
            if n == 1:
                amount = 2490 if "large" in task else 249
                return reply([use("issue_refund", {"order_id": "1042", "amount_usd": amount}, 3),
                              use("send_customer_email", {
                                  "to": "jordan.lee@example.com", "subject": "Your refund request #1042",
                                  "body": f"[scripted] Hi Jordan, your tent was returned within 30 days, so you "
                                          f"qualify for a full refund of ${amount}. It will reach your card in 5-7 "
                                          f"business days."}, 4)], "tool_use")
            states = [r["content"][0]["json"].get("status") for r in last]
            return reply([{"text": f"[scripted] Refund and reply submitted: {', '.join(states)}."}])
        return reply([{"text": "[scripted] No tools needed."}])
