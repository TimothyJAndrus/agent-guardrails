# Agent Guardrails Demo

A small AI agent on AWS that shows the three controls from the talk **"There's No Need to Fear? Building Ethical AI Agents on AWS"** (Tim Andrus, AITeCXO):

| Control | What the audience sees | How it's built |
|---|---|---|
| **1. Limits** | A "CFO" urgently asks the agent for payroll. The agent tries, and AWS refuses. | The agent's IAM role can read `public/*` in one bucket and call one model family. Nothing else. No allow-list in the code: IAM is the only wall. |
| **2. An approver** | The agent drafts a refund email. The workflow pauses until a human taps **Approve** in an email. | Step Functions `waitForTaskToken`. Only a separate Lambda can resume it, and only on a POST from the confirmation page (email scanners that open links can't approve). The agent has no send tool and no permission on the workflow. |
| **3. A record** | Replay every step: what was asked, what was read, what was denied, who approved, what was sent. | JSON audit lines from every Lambda in CloudWatch Logs, Step Functions logging at `ALL` with execution data, X-Ray tracing. |

"Sending" is simulated: approved messages are written to `s3://<bucket>/outbox/`. No real customer email is ever sent.

## Architecture
```
run_demo.py ──> Step Functions ──> Agent Lambda ──> Bedrock (Converse + tools)
                     │                  └─> S3 read (IAM: public/* only)
                     │
                     ├─(action proposed)─> RequestApproval Lambda ──> SNS email to approver
                     │        ⏸ waitForTaskToken
                     │   approver taps link ──> Decide Lambda URL (GET = page, POST = decide)
                     │                              └─> states:SendTaskSuccess
                     └─(approved)─> Execute Lambda ──> S3 outbox/ (simulated send)
```

## Deploy
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
npm install                       # CDK CLI pinned in package.json
export AWS_PROFILE=Tian001 PATH="$PWD/.venv/bin:$PATH"
npx cdk bootstrap aws://358254890860/us-west-2   # once per account/region
npx cdk deploy                    # ~90 seconds
```
Confirm the SNS subscription email the first time. Change the approver with `-c approverEmail=you@example.com`.

## Run the demo
```bash
.venv/bin/python scripts/run_demo.py limits    # moment 1
.venv/bin/python scripts/run_demo.py approve   # moment 2: pauses until you approve in email
.venv/bin/python scripts/run_demo.py record    # moment 3: replay the last run
```

## Tests
```bash
.venv/bin/python -m pytest -q                              # 16 tests, no AWS calls
AWS_PROFILE=Tian001 .venv/bin/python tests/live_model_check.py   # real Bedrock, local fake S3
```
The stack tests assert the controls are in the template: the agent role has no write, SNS, or Step Functions permissions and no wildcard actions; only the Decide function can resume the workflow; logging is `ALL`.

## Model
Default: `us.anthropic.claude-haiku-4-5-20251001-v1:0` (Claude Haiku 4.5; enabled Oct 19 after the Anthropic use-case form). Fallback: `-c modelId=us.amazon.nova-pro-v1:0` (Amazon Nova Pro, tested working). Switch with `-c modelId=...`; the IAM policy follows the model ID. Anthropic models on Bedrock need the one-time Anthropic use-case form in the Bedrock console first.

`MODEL_MODE=scripted` swaps Bedrock for a labeled, deterministic stand-in (every answer starts with `[scripted]`). Use it only for rehearsal, or as an announced fallback if venue Wi-Fi fails.

## Tear down
```bash
npx cdk destroy    # removes everything, including the bucket and logs
```
Cost while idle is effectively zero: no servers run between demos.

## Rehearsal log
- **Oct 19, 2026:** full run on Claude Haiku 4.5, approved from Tim's phone. Approval email arrived quickly and the page worked on mobile Gmail. Pause to tap: 19 s. Whole approval moment: ~26 s.

## Run of show (after slide 9, ~4 minutes)
1. `run_demo.py limits` (~10 s): "The CFO is in a hurry. Watch what AWS says."
2. `run_demo.py approve` (~30 s): hold up the phone, read the draft aloud, tap Approve.
3. `run_demo.py record` (~15 s): "Every step, who approved it, and when. That's the record."
Then go to slide 10. Mirror the phone to the projector (AirPlay to the presenting Mac) so the room sees the approval.
Fallback if venue Wi-Fi fails: `-c modelMode=scripted` (announce it), or show the recorded replay output.
