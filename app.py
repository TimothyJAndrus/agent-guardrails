#!/usr/bin/env python3
import aws_cdk as cdk

from stack.guardrails_stack import AgentGuardrailsDemoStack

app = cdk.App()
AgentGuardrailsDemoStack(
    app, "AgentGuardrailsDemo",
    env=cdk.Environment(account=app.node.try_get_context("account") or "358254890860",
                        region=app.node.try_get_context("region") or "us-west-2"),
    description="AWS Utah talk demo: an AI agent with limits, a human approver, and a record.",
)
app.synth()
