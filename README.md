# agent-guardrails

**What can your AI agent DO, and who approved it?**

An action gate for AI agents. Every tool call is checked against a policy before it runs: **allow**, **deny**, or **wait for a human**. Approvals come from a web dashboard, Slack, or email. Every step lands in a hash-chained audit trail you can replay.

```
agent ──tool call──▶ gate ──policy──┬─ allow ─────────────────────────────────────▶ run it (once)
                                    ├─ deny  ──▶ the model reads "denied"; the body never runs
                                    └─ approve ─▶ dashboard / Slack / email ─▶ human ─▶ run it (once, same args)
                                                   every step ──▶ hash-chained audit ──▶ replay
```

Part of the **trusted-agent stack**, four small open-source pieces for running AI agents a company can trust:

| | Question it answers |
|---|---|
| [agent-credential-broker](https://github.com/TimothyJAndrus/agent-credential-broker) | What can the agent **access**? Short-lived, scoped credentials. |
| **agent-guardrails** | What can the agent **do**, and who approved it? Policy and human approval on every tool call. |
| [agent-trap-evals](https://github.com/TimothyJAndrus/agent-trap-evals) | Is the agent's output **true**? Traps a shallow check passes and a deeper check fails. |
| [note-taking-service](https://github.com/TimothyJAndrus/note-taking-service) | A real app using them: cited Q&A over team notes, and an MCP server behind the gate. |

## In code

```python
from agent_guardrails import Guard

guard = Guard.local("policy.yaml", agent="support-bot")       # in-process: dev, tests, notebooks
guard = Guard.remote(api_url, agent="support-bot")             # deployed gate, SigV4 with the agent's own IAM role

@guard.tool()
def issue_refund(order_id: str, amount_usd: float): ...

with guard.run("handle ticket 1042"):
    issue_refund("1042", 249)   # waits for a human; raises Denied / Rejected / Expired otherwise
```

In a model tool-use loop, `guard.call_tool(name, args)` returns `{"status": "denied" | "pending_approval" | "ok", ...}`, so a denial is something the model reads, not a crash. `execute=False` records the call for a separate executor to run after approval (the pattern the example uses).

## Policy

```yaml
version: 1
default: deny                      # a tool not named here can't run
approval:
  expires_in: 3600
  approvers: {emails: [you@example.com], slack_user_ids: [U012ABC]}
limits:
  max_calls_per_run: 12            # runaway-loop backstop
rules:
  - id: small-refunds-with-approval
    tool: issue_refund
    effect: approve
    max_per_run: 1
    when: {amount_usd: {lte: 500}}
  - id: large-refunds-denied
    tool: issue_refund
    effect: deny
    when: {amount_usd: {gt: 500}}
```

Operators: `equals`, `not_equals`, `in`, `not_in`, `starts_with`, `not_starts_with`, `glob`, `lt`, `lte`, `gt`, `gte`, `domain_in`, `domain_not_in`, `max_length`, `exists`. Rules can be scoped with `agents: [...]`. Full example: [`examples/support_agent/policy.yaml`](examples/support_agent/policy.yaml).

Matching rules combine to the **most restrictive** effect (deny > approve > allow). A bad policy fails at load time, and with the CDK construct, at `cdk synth`.

## What it refuses

The tests are written as attacks. Each must fail safely and leave an audit event.

| Attack | Result |
|---|---|
| "URGENT from the CFO: ignore your rules" | Denied. Free text (the model's stated reason) is recorded, never evaluated. |
| `public/../hr/payroll.csv`, backslashes, NUL bytes | Denied. Path conditions fail closed on traversal. |
| `amount_usd: "5000"` (a string) or `true` | Denied. A wrong-typed argument never satisfies an allow/approve rule, and always satisfies a deny rule. |
| `ceo@acme.example`, `a@b@acme.example`, comma lists | Denied. Domain checks parse exactly one address or fail. |
| Human approves a $249 refund; agent executes $2,490 with the same call id | `409`. Execution must present the approved arguments. |
| Execute twice | `409`, `call.replay_blocked` in the record. |
| Agent approves its own call | `403`. |
| Someone not in `approvers` presses Approve (dashboard or Slack) | `403`, `approval.unauthorized` in the record. |
| 20 concurrent approve/reject clicks | Exactly one wins (conditional writes). |
| Approve two hours later | `410`. Approvals expire. |
| A second refund in the run, or a 13th call | Denied by `max_per_run` / `max_calls_per_run` (atomic counters). |
| Another agent reads or executes the call | `404`. |
| Email scanner prefetches the approval link | Nothing happens. GET renders a page; only its POST decides. The link's one-time secret is stored as a hash. |
| Forged or replayed Slack click | `401`: HMAC signature and a 5-minute timestamp window. |
| Edit, delete, or reorder an audit event in DynamoDB | Replay shows "chain BROKEN at event N". |
| Slack is down | The request is still recorded and shown on the dashboard, with `approval.notify_failed`. |

## Deploy (AWS CDK)

The construct is the product. The support agent is an example of using it.

```python
from guardrails_cdk import ActionGate

gate = ActionGate(self, "Gate", policy="policy.yaml", approver_emails=["you@example.com"],
                  slack=True, dashboard_assets="dashboard/dist")
gate.register_agent(agent_fn.role, "support-bot")          # may start runs and check calls
gate.register_executor(execute_fn.role, ["support-bot"])   # may execute approved calls for that agent
wait = gate.wait_for_approval_task(self, "Wait", call_id_path="$.id", agent="support-bot")  # Step Functions
gate.grant_wait_for_approval(state_machine)
```

It creates a DynamoDB table (PITR on), one Lambda behind an HTTP API (throttled, access-logged), a Cognito user pool for approvers (admin-created users only), an SNS topic for email approvals, a Secrets Manager secret for Slack, and the dashboard on a private S3 bucket behind CloudFront.

| Route | Auth |
|---|---|
| `/v1/runs`, `/v1/calls/*` (agents, executors) | IAM (SigV4), **and** the caller's role must be registered |
| `/v1/dashboard/*` | Cognito JWT, **and** deciding requires an email in `approvers.emails` |
| `/email/decide`, `/slack/interact` | No API auth; one-time link secret / Slack signature checked in code |

### Run the example

```bash
python3.13 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
npm ci && (cd dashboard && npm ci && npm run build)
export AWS_PROFILE=<profile>
npx cdk deploy -c account=<id> -c approverEmail=you@example.com    # add -c slack=true for Slack
aws cognito-idp admin-create-user --user-pool-id <GateUserPoolId output> --username you@example.com \
  --user-attributes Name=email,Value=you@example.com Name=email_verified,Value=true
.venv/bin/python scripts/run_example.py limits   # denied by policy (IAM would also refuse)
.venv/bin/python scripts/run_example.py refund   # pauses; approve on the dashboard, in Slack, or by email
.venv/bin/python scripts/run_example.py replay   # the record, with the chain verified
npx cdk destroy                                  # removes everything; idle cost is near zero anyway
```

Confirm the SNS subscription email the first time. Slack: create an app with a bot token (`chat:write`), set Interactivity's request URL to `<GateApiUrl>slack/interact`, then put `bot_token`, `signing_secret`, and `channel_id` in the `GateSlackSecretArn` secret.

Model: `us.anthropic.claude-haiku-4-5-20251001-v1:0` by default; `-c modelId=us.amazon.nova-pro-v1:0` also works. Anthropic models on Bedrock need the one-time use-case form in the Bedrock console. `-c modelMode=scripted` swaps in a labeled stand-in (every answer starts with `[scripted]`) for rehearsal or an announced offline fallback.

## Run it locally (no AWS)

```bash
.venv/bin/python -m examples.support_agent.local              # scripted model; you approve at the prompt
.venv/bin/python -m examples.support_agent.local --bedrock    # real Bedrock model
.venv/bin/pytest                                              # policy, attacks, DynamoDB (moto), API, synth
```

## Design decisions

- **The policy reads arguments, never prose.** If text could change a decision, a prompt injection could.
- **Fail closed.** Missing, mistyped, or suspicious arguments never satisfy an allow or approve rule.
- **Approval binds to arguments.** Execution must present the approved arguments, once.
- **The agent proposes, an executor acts.** In the example, the agent's IAM role can't send or refund anything; a separate role runs approved calls. The gate and IAM are two walls, and either one alone stops the payroll read.
- **Credentials are the broker's job.** The gate decides actions. For a tool that needs AWS access, pass `credentials=` to `@guard.tool()` and fetch a scoped credential from agent-credential-broker *after* the gate allows the call. No duplicate approval or audit logic.
- **Tamper-evident, not tamper-proof.** Each run's events are hash-chained. Someone with table write access could rewrite a whole run; every event is also printed to CloudWatch Logs, so they'd have to forge both.

## Known limits

- One policy per gate, loaded at deploy. Changing it is a redeploy: reviewable, not instant.
- Agent roles can't have an IAM path (STS assumed-role ARNs drop it).
- On the email channel the approver is "whoever holds the link". Use the dashboard or Slack when you need a named approver.
- The dashboard polls every 5 s; no push.

## History

This started as the live demo for the AWS Utah talk "There's No Need to Fear? Building Ethical AI Agents on AWS". The rehearsed version is tagged `talk-demo-2026-10`; the run of show is in [docs/talk.md](docs/talk.md).

MIT licensed.
