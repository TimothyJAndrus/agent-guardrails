# Talk: "There's No Need to Fear? Building Ethical AI Agents on AWS"

AWS Utah, Tim Andrus (AITeCXO). This repo began as the talk's live demo: three controls, three moments.

| Control | What the audience sees | Built with today |
|---|---|---|
| **1. Limits** | A "CFO" urgently asks the agent for payroll. It's refused. | Policy rule `no-hr-or-finance` (gate), and the agent's IAM role can read `public/*` only (AWS). Two walls. |
| **2. An approver** | The agent refunds and emails a customer. Nothing happens until a human taps Approve. | `approve` rules; dashboard, Slack, or email; Step Functions waits on a task token. |
| **3. A record** | Replay every step: asked, read, denied, who approved, what ran. | Hash-chained audit events per run; dashboard replay verifies the chain. |

The exact version rehearsed on Oct 19, 2026 is tagged `talk-demo-2026-10` (stack name `AgentGuardrailsDemo`, scripts `scripts/run_demo.py limits|approve|record`). Check out that tag to give the talk exactly as rehearsed.

## Rehearsal log

- **Oct 19, 2026** (tagged version): full run on Claude Haiku 4.5, approved from Tim's phone. Approval email arrived quickly; the page worked in mobile Gmail. Pause to tap: 19 s. Whole approval moment: ~26 s.

## Run of show (after slide 9, ~4 minutes)

Tagged version:

1. `run_demo.py limits` (~10 s): "The CFO is in a hurry. Watch what AWS says."
2. `run_demo.py approve` (~30 s): hold up the phone, read the draft aloud, tap Approve.
3. `run_demo.py record` (~15 s): "Every step, who approved it, and when. That's the record."

Current version (same beats, dashboard instead of terminal for moment 3):

1. `scripts/run_example.py limits`
2. `scripts/run_example.py refund`: approve on the phone (dashboard or email)
3. Dashboard → Runs → the run: the replay, with "Audit chain verified"

Mirror the phone to the projector (AirPlay to the presenting Mac) so the room sees the approval.
Fallback if venue Wi-Fi fails: deploy with `-c modelMode=scripted` and announce it, or run `python -m examples.support_agent.local` (no AWS at all).
