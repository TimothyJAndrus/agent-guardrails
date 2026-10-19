"""Synth-time tests: the controls are actually in the CloudFormation template."""
import json
import os
import sys

import aws_cdk as cdk
from aws_cdk.assertions import Match, Template

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from stack.guardrails_stack import AgentGuardrailsDemoStack, base_model_id  # noqa: E402


def template():
    app = cdk.App(context={"modelId": "us.amazon.nova-pro-v1:0", "modelMode": "bedrock",
                           "approverEmail": "tim@aitecxo.com"})
    s = AgentGuardrailsDemoStack(app, "T", env=cdk.Environment(account="358254890860", region="us-west-2"))
    return Template.from_stack(s)


def policies(t):
    return {k: v for k, v in t.find_resources("AWS::IAM::Policy").items()}


def agent_statements(t):
    for k, v in policies(t).items():
        if k.startswith("AgentServiceRoleDefaultPolicy"):
            return v["Properties"]["PolicyDocument"]["Statement"]
    raise AssertionError("agent policy not found")


def test_base_model_id():
    assert base_model_id("us.anthropic.claude-sonnet-4-6") == "anthropic.claude-sonnet-4-6"
    assert base_model_id("us.amazon.nova-pro-v1:0") == "amazon.nova-pro-v1:0"


def test_agent_role_is_least_privilege():
    st = agent_statements(template())
    actions = sorted(a for s in st for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"]))
    assert "s3:PutObject" not in actions and "sns:Publish" not in actions
    assert not any(a.startswith("states:") for a in actions)
    assert not any(a.endswith("*") for a in actions)
    s3 = [s for s in st if s.get("Sid") == "ReadPublicDocsOnly"][0]
    assert "/public/*" in json.dumps(s3["Resource"])
    assert "hr/" not in json.dumps(st)


def test_only_decide_can_resume_workflow():
    holders = [k for k, v in policies(template()).items() if "states:SendTaskSuccess" in json.dumps(v)]
    assert len(holders) == 1 and holders[0].startswith("DecideServiceRoleDefaultPolicy")


def test_workflow_waits_for_task_token_and_logs_everything():
    t = template()
    sm = list(t.find_resources("AWS::StepFunctions::StateMachine").values())[0]["Properties"]
    assert ".waitForTaskToken" in json.dumps(sm["DefinitionString"])
    assert sm["LoggingConfiguration"]["Level"] == "ALL"
    assert sm["LoggingConfiguration"]["IncludeExecutionData"] is True
    assert sm["TracingConfiguration"]["Enabled"] is True


def test_bucket_private_and_disposable():
    t = template()
    t.has_resource_properties("AWS::S3::Bucket", {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}})
    t.has_resource("AWS::S3::Bucket", {"DeletionPolicy": "Delete"})


def test_approver_subscribed():
    template().has_resource_properties("AWS::SNS::Subscription", {"Protocol": "email", "Endpoint": "tim@aitecxo.com"})
