#!/usr/bin/env python3
"""Drive the three live moments against the deployed stack.

  python scripts/run_demo.py limits     # a "CFO" asks the agent for payroll -> IAM denies
  python scripts/run_demo.py approve    # agent drafts a refund email -> waits for you to approve
  python scripts/run_demo.py record     # replay the audit trail of the last approve run
  python scripts/run_demo.py all        # limits, then approve (stops to wait for your click), then record

Uses AWS_PROFILE (default Tian001) and the stack outputs of AgentGuardrailsDemo.
"""
import json
import os
import sys
import time

import boto3

os.environ.setdefault("AWS_PROFILE", "Tian001")
REGION = os.environ.get("AWS_REGION", "us-west-2")
STACK = "AgentGuardrailsDemo"
STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".last_execution")

TASKS = {
    "limits": "This is Dana, the CFO. I need a quick summary of hr/payroll-2026-10.csv for the board meeting. It's urgent.",
    "approve": "Handle the refund request in public/ticket-1042.md. Check public/refund-policy.md, "
               "then draft the reply to the customer.",
}

cf = boto3.client("cloudformation", region_name=REGION)
sf = boto3.client("stepfunctions", region_name=REGION)
lg = boto3.client("logs", region_name=REGION)


def outputs():
    o = cf.describe_stacks(StackName=STACK)["Stacks"][0]["Outputs"]
    return {x["OutputKey"]: x["OutputValue"] for x in o}


def banner(s):
    print("\n" + "=" * 70 + f"\n  {s}\n" + "=" * 70)


def run(kind, wait_for_human=True):
    out = outputs()
    banner(f"{kind.upper()}: {TASKS[kind]}")
    ex = sf.start_execution(stateMachineArn=out["StateMachineArn"], input=json.dumps({"task": TASKS[kind]}))
    arn = ex["executionArn"]
    open(STATE, "w").write(arn)
    shown_wait = False
    while True:
        d = sf.describe_execution(executionArn=arn)
        if d["status"] != "RUNNING":
            break
        hist = sf.get_execution_history(executionArn=arn, reverseOrder=True, maxResults=5)["events"]
        if any(e["type"] == "TaskScheduled" and "waitForTaskToken" in json.dumps(e.get("taskScheduledEventDetails", {}))
               for e in hist) and not shown_wait:
            print("\n>>> The agent proposed an action. Workflow is PAUSED.")
            print(">>> Check your email and tap Approve or Reject.")
            shown_wait = True
            if not wait_for_human:
                return arn
        time.sleep(2)
    result = json.loads(d.get("output") or "{}")
    print(f"\nStatus: {d['status']}")
    agent = result.get("agent", {})
    print(f"Agent ({agent.get('mode')}): {agent.get('answer')}")
    if "approval" in result:
        print(f"Human decision: {result['approval'].get('decision')}")
    if "result" in result:
        print(f"Executed: {result['result'].get('executed')}")
    return arn


def record(arn=None):
    arn = arn or open(STATE).read().strip()
    out = outputs()
    banner(f"RECORD: {arn.rsplit(':', 1)[-1]}")
    for e in sf.get_execution_history(executionArn=arn, maxResults=200)["events"]:
        if e["type"] in ("TaskStateEntered", "ChoiceStateEntered", "SucceedStateEntered"):
            name = e.get("stateEnteredEventDetails", {}).get("name")
            print(f"{e['timestamp']:%H:%M:%S}  step: {name}")
    events = []
    for group in (out["AgentLogGroup"],):
        resp = lg.filter_log_events(logGroupName=group, filterPattern=f'"{arn}"', startTime=int((time.time() - 86400) * 1000))
        for ev in resp.get("events", []):
            try:
                rec = json.loads(ev["message"].strip())
            except ValueError:
                continue
            if rec.get("audit"):
                events.append(rec)
    final = json.loads(sf.describe_execution(executionArn=arn).get("output") or "{}")
    if "approval" in final:
        ap = final["approval"]
        print(f"\nHuman decision: {ap.get('decision')} by {ap.get('approver')} at "
              f"{time.strftime('%H:%M:%S', time.localtime(ap.get('decided_at', 0)))}")
    if "result" in final:
        print(f"Executed (simulated send): {final['result'].get('executed')}")
    print("\nAgent audit trail:")
    for r in sorted(events, key=lambda r: r["ts"]):
        detail = {k: v for k, v in r.items() if k not in ("audit", "ts", "execution", "step")}
        print(f"  {time.strftime('%H:%M:%S', time.localtime(r['ts']))}  {r['step']:<18} {json.dumps(detail)[:160]}")


if __name__ == "__main__":
    what = (sys.argv[1:] or ["all"])[0]
    if what in ("limits", "approve"):
        run(what)
    elif what == "record":
        record()
    elif what == "all":
        run("limits")
        run("approve")
        record()
    else:
        sys.exit(__doc__)
