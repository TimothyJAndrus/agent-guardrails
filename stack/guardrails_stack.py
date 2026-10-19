"""One stack, three controls.

LIMITS    The agent's IAM role can read s3://<bucket>/public/* and call one model family.
          Nothing else: no writes, no restricted/ prefix, no SNS, no Step Functions.
APPROVER  A Step Functions waitForTaskToken step pauses the workflow and emails the
          approver. Only a POST to the decide URL resumes it. The agent cannot touch it.
RECORD    Every Lambda prints JSON audit lines; the state machine logs ALL events with
          execution data; X-Ray tracing is on.
"""
import os

import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
)
from constructs import Construct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "lambda_src")
DATA = os.path.join(HERE, "..", "data")
SM_NAME = "AgentGuardrailsDemo"


def base_model_id(model_id: str) -> str:
    """'us.amazon.nova-pro-v1:0' -> 'amazon.nova-pro-v1:0' (inference-profile prefix stripped)."""
    parts = model_id.split(".")
    return ".".join(parts[1:]) if parts[0] in ("us", "eu", "apac", "global") else model_id


class AgentGuardrailsDemoStack(cdk.Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        model_id = self.node.try_get_context("modelId")
        model_mode = self.node.try_get_context("modelMode") or "bedrock"
        approver = self.node.try_get_context("approverEmail")

        # ---------- data ----------
        bucket = s3.Bucket(
            self, "Docs",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )
        s3deploy.BucketDeployment(self, "SeedDocs", sources=[s3deploy.Source.asset(DATA)],
                                  destination_bucket=bucket, prune=False)

        def fn(name, handler, timeout=30, env=None):
            group = logs.LogGroup(self, f"{name}Logs", retention=logs.RetentionDays.ONE_WEEK,
                                  removal_policy=cdk.RemovalPolicy.DESTROY)
            return lambda_.Function(
                self, name,
                runtime=lambda_.Runtime.PYTHON_3_13,
                architecture=lambda_.Architecture.ARM_64,
                code=lambda_.Code.from_asset(SRC),
                handler=handler,
                timeout=cdk.Duration.seconds(timeout),
                memory_size=256,
                environment=env or {},
                log_group=group,
                tracing=lambda_.Tracing.ACTIVE,
            )

        # ---------- 1. LIMITS: the agent ----------
        agent = fn("Agent", "agent.handler", timeout=120,
                   env={"MODEL_ID": model_id, "DATA_BUCKET": bucket.bucket_name, "MODEL_MODE": model_mode})
        agent.add_to_role_policy(iam.PolicyStatement(
            sid="ReadPublicDocsOnly",
            actions=["s3:GetObject"],
            resources=[bucket.arn_for_objects("public/*")],
        ))
        base = base_model_id(model_id)
        agent.add_to_role_policy(iam.PolicyStatement(
            sid="InvokeOneModelFamily",
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=[
                f"arn:aws:bedrock:*:{self.account}:inference-profile/{model_id}",
                f"arn:aws:bedrock:*::foundation-model/{base}*",
            ],
        ))

        # ---------- 2. APPROVER ----------
        topic = sns.Topic(self, "ApprovalTopic", display_name="Agent approval")
        if approver:
            topic.add_subscription(subs.EmailSubscription(approver))

        sm_arn = cdk.Stack.of(self).format_arn(service="states", resource="stateMachine",
                                               resource_name=SM_NAME,
                                               arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME)
        decide = fn("Decide", "decide.handler")
        decide.add_to_role_policy(iam.PolicyStatement(
            sid="ResumeOnlyThisWorkflow", actions=["states:SendTaskSuccess"], resources=[sm_arn]))
        decide_url = decide.add_function_url(auth_type=lambda_.FunctionUrlAuthType.NONE)

        request = fn("RequestApproval", "request_approval.handler",
                     env={"APPROVAL_TOPIC_ARN": topic.topic_arn, "DECIDE_URL": decide_url.url})
        topic.grant_publish(request)

        execute = fn("Execute", "execute.handler", env={"DATA_BUCKET": bucket.bucket_name})
        execute.add_to_role_policy(iam.PolicyStatement(
            sid="WriteOutboxOnly", actions=["s3:PutObject"], resources=[bucket.arn_for_objects("outbox/*")]))

        # ---------- workflow ----------
        run_agent = tasks.LambdaInvoke(
            self, "Run agent", lambda_function=agent,
            payload=sfn.TaskInput.from_object({"task": sfn.JsonPath.string_at("$.task"),
                                               "execution": sfn.JsonPath.string_at("$$.Execution.Id")}),
            result_selector={"answer.$": "$.Payload.answer", "proposed_actions.$": "$.Payload.proposed_actions",
                             "mode.$": "$.Payload.mode"},
            result_path="$.agent",
        )
        ask_human = tasks.LambdaInvoke(
            self, "Wait for human approval", lambda_function=request,
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            payload=sfn.TaskInput.from_object({"actions": sfn.JsonPath.list_at("$.agent.proposed_actions"),
                                               "token": sfn.JsonPath.task_token,
                                               "execution": sfn.JsonPath.string_at("$$.Execution.Id")}),
            result_path="$.approval",
            task_timeout=sfn.Timeout.duration(cdk.Duration.hours(1)),
        )
        do_it = tasks.LambdaInvoke(
            self, "Execute approved action", lambda_function=execute,
            payload=sfn.TaskInput.from_object({"actions": sfn.JsonPath.list_at("$.agent.proposed_actions"),
                                               "execution": sfn.JsonPath.string_at("$$.Execution.Id")}),
            result_selector={"executed.$": "$.Payload.executed"},
            result_path="$.result",
        )
        definition = run_agent.next(
            sfn.Choice(self, "Did the agent propose an action?")
            .when(sfn.Condition.is_present("$.agent.proposed_actions[0]"),
                  ask_human.next(
                      sfn.Choice(self, "Approved?")
                      .when(sfn.Condition.string_equals("$.approval.decision", "approve"),
                            do_it.next(sfn.Succeed(self, "Done: approved and executed")))
                      .otherwise(sfn.Succeed(self, "Done: rejected, nothing sent"))))
            .otherwise(sfn.Succeed(self, "Done: no action needed")))

        sm_logs = logs.LogGroup(self, "WorkflowLogs", retention=logs.RetentionDays.ONE_WEEK,
                                removal_policy=cdk.RemovalPolicy.DESTROY)
        machine = sfn.StateMachine(
            self, "Workflow", state_machine_name=SM_NAME,
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=cdk.Duration.hours(2),
            tracing_enabled=True,
            logs=sfn.LogOptions(destination=sm_logs, level=sfn.LogLevel.ALL, include_execution_data=True),
        )

        for k, v in {
            "StateMachineArn": machine.state_machine_arn,
            "Bucket": bucket.bucket_name,
            "DecideUrl": decide_url.url,
            "AgentFunction": agent.function_name,
            "AgentRoleArn": agent.role.role_arn,
            "AgentLogGroup": agent.log_group.log_group_name,
            "WorkflowLogGroup": sm_logs.log_group_name,
        }.items():
            cdk.CfnOutput(self, k, value=v)
