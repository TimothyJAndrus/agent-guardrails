#!/usr/bin/env python3
import aws_cdk as cdk

from examples.support_agent.stack import SupportAgentStack

app = cdk.App()
SupportAgentStack(
    app, "AgentGuardrails",
    env=cdk.Environment(account=app.node.try_get_context("account") or None,
                        region=app.node.try_get_context("region") or "us-west-2"),
    description="agent-guardrails example: a support agent behind an action gate (policy, approvals, replay).",
)
app.synth()
