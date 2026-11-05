"""Example stack: the support agent from the talk, rebuilt on the ActionGate construct.

  agent Lambda  --SigV4-->  gate API  (policy: allow / deny / approve)
       |                       |  pending -> email / Slack / dashboard
       v                       v
  Step Functions: run agent -> for each handed-off call: wait for decision -> Execute Lambda

Two walls, on purpose:
  POLICY  the gate refuses hr/* reads, internal emails, refunds > $500, a second refund in a run.
  IAM     the agent's role can read public/* only, invoke one model family, and call the gate.
          It cannot write to S3, send email, resume workflows, or touch the gate's table.
"""

from __future__ import annotations

import os

import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_s3_deployment as s3deploy,
)
from aws_cdk import (
    aws_stepfunctions as sfn,
)
from aws_cdk import (
    aws_stepfunctions_tasks as tasks,
)
from constructs import Construct

from guardrails_cdk import ActionGate, _stage_code

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
AGENT = "support-bot"


def base_model_id(model_id: str) -> str:
    """'us.amazon.nova-pro-v1:0' -> 'amazon.nova-pro-v1:0' (inference-profile prefix stripped)."""
    parts = model_id.split(".")
    return ".".join(parts[1:]) if parts[0] in ("us", "eu", "apac", "global") else model_id


def _runtime_asset(policy_doc):
    """agent_guardrails + this example's runtime/ in one asset (agent and executor import both)."""
    import shutil

    out = _stage_code(policy_doc)
    shutil.copytree(os.path.join(HERE, "runtime"), os.path.join(out, "runtime"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return out


class SupportAgentStack(cdk.Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        ctx = self.node.try_get_context
        model_id = ctx("modelId") or "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        model_mode = ctx("modelMode") or "bedrock"
        approver = ctx("approverEmail")
        dashboard = os.path.join(ROOT, "dashboard", "dist")

        gate = ActionGate(self, "Gate", policy=os.path.join(HERE, "policy.yaml"),
                          approver_emails=[approver] if approver else None,
                          slack=bool(ctx("slack")),
                          dashboard_assets=dashboard if os.path.isdir(dashboard) else None,
                          removal_policy=cdk.RemovalPolicy.DESTROY, log_retention=logs.RetentionDays.ONE_WEEK)

        bucket = s3.Bucket(self, "Docs", block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                           removal_policy=cdk.RemovalPolicy.DESTROY, auto_delete_objects=True)
        s3deploy.BucketDeployment(self, "SeedDocs", sources=[s3deploy.Source.asset(os.path.join(ROOT, "data"))],
                                  destination_bucket=bucket, prune=False)

        code = lambda_.Code.from_asset(_runtime_asset(gate.policy_doc))

        def fn(name, handler, timeout, env):
            return lambda_.Function(
                self, name, runtime=lambda_.Runtime.PYTHON_3_13, architecture=lambda_.Architecture.ARM_64,
                code=code, handler=handler, timeout=cdk.Duration.seconds(timeout), memory_size=256,
                environment={"GATE_API_URL": gate.api_url, "DATA_BUCKET": bucket.bucket_name, **env},
                tracing=lambda_.Tracing.ACTIVE,
                log_group=logs.LogGroup(self, f"{name}Logs", retention=logs.RetentionDays.ONE_WEEK,
                                        removal_policy=cdk.RemovalPolicy.DESTROY))

        agent = fn("Agent", "runtime.agent.handler", 120,
                   {"MODEL_ID": model_id, "MODEL_MODE": model_mode, "AGENT_NAME": AGENT})
        agent.add_to_role_policy(iam.PolicyStatement(
            sid="ReadPublicDocsOnly", actions=["s3:GetObject"], resources=[bucket.arn_for_objects("public/*")]))
        agent.add_to_role_policy(iam.PolicyStatement(
            sid="InvokeOneModelFamily", actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=[f"arn:aws:bedrock:*:{self.account}:inference-profile/{model_id}",
                       f"arn:aws:bedrock:*::foundation-model/{base_model_id(model_id)}*"]))
        gate.register_agent(agent.role, AGENT)

        execute = fn("Execute", "runtime.execute.handler", 30, {})
        execute.add_to_role_policy(iam.PolicyStatement(
            sid="WriteOutboxOnly", actions=["s3:PutObject"], resources=[bucket.arn_for_objects("outbox/*")]))
        gate.register_executor(execute.role, [AGENT])

        # ---------- workflow ----------
        run_agent = tasks.LambdaInvoke(
            self, "Run agent", lambda_function=agent,
            payload=sfn.TaskInput.from_object({"task": sfn.JsonPath.string_at("$.task"),
                                               "execution": sfn.JsonPath.string_at("$$.Execution.Id")}),
            result_selector={"run.$": "$.Payload.run", "answer.$": "$.Payload.answer",
                             "handoff.$": "$.Payload.handoff"},
            result_path="$.agent")
        wait = gate.wait_for_approval_task(self, "Wait for a human decision", call_id_path="$.id", agent=AGENT,
                                           timeout=cdk.Duration.hours(1), result_path="$.approval")
        wait.add_catch(sfn.Pass(self, "Timed out waiting: nothing executed",
                                result=sfn.Result.from_object({"decision": "timeout"}), result_path="$.approval"),
                       errors=["States.Timeout"], result_path="$.error")
        do_it = tasks.LambdaInvoke(
            self, "Execute approved call", lambda_function=execute,
            payload=sfn.TaskInput.from_object({"call": sfn.JsonPath.string_at("$.id")}),
            result_selector={"executed.$": "$.Payload"}, result_path="$.result")
        done_exec = sfn.Pass(self, "Executed")
        skipped = sfn.Pass(self, "Not approved: nothing executed")
        per_call = sfn.Choice(self, "Needs a human?").when(
            sfn.Condition.string_equals("$.status", "pending_approval"),
            wait.next(sfn.Choice(self, "Approved?")
                      .when(sfn.Condition.string_equals("$.approval.decision", "approve"), do_it)
                      .otherwise(skipped))).otherwise(do_it)
        do_it.next(done_exec)
        each = sfn.Map(self, "For each handed-off call", items_path="$.agent.handoff", result_path="$.calls",
                       max_concurrency=4)
        each.item_processor(per_call)
        definition = run_agent.next(each).next(sfn.Succeed(self, "Done"))

        wf_logs = logs.LogGroup(self, "WorkflowLogs", retention=logs.RetentionDays.ONE_WEEK,
                                removal_policy=cdk.RemovalPolicy.DESTROY)
        machine = sfn.StateMachine(
            self, "Workflow", definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=cdk.Duration.hours(2), tracing_enabled=True,
            logs=sfn.LogOptions(destination=wf_logs, level=sfn.LogLevel.ALL, include_execution_data=True))
        gate.grant_wait_for_approval(machine)

        for k, v in {"StateMachineArn": machine.state_machine_arn, "Bucket": bucket.bucket_name,
                     "AgentRoleArn": agent.role.role_arn, "AgentFunction": agent.function_name}.items():
            cdk.CfnOutput(self, k, value=v)
        self.gate, self.agent_fn, self.execute_fn, self.machine = gate, agent, execute, machine
