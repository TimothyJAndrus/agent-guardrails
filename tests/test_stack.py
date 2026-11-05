"""Synth-time tests: the controls are actually in the CloudFormation template."""

import json
import os

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Match, Template

from agent_guardrails.policy import PolicyError
from examples.support_agent.stack import SupportAgentStack, base_model_id
from guardrails_cdk import ActionGate

ENV = cdk.Environment(account="123456789012", region="us-west-2")


@pytest.fixture(scope="module")
def t():
    app = cdk.App(context={"modelId": "us.anthropic.claude-haiku-4-5-20251001-v1:0", "approverEmail": "a@example.com",
                           "slack": True})
    return Template.from_stack(SupportAgentStack(app, "T", env=ENV))


def statements(t, prefix):
    for k, v in t.find_resources("AWS::IAM::Policy").items():
        if k.startswith(prefix):
            return v["Properties"]["PolicyDocument"]["Statement"]
    raise AssertionError(f"{prefix} policy not found")


def actions(st):
    return sorted(a for s in st for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"]))


def test_base_model_id():
    assert base_model_id("us.amazon.nova-pro-v1:0") == "amazon.nova-pro-v1:0"


def test_agent_role_least_privilege(t):
    st = statements(t, "AgentServiceRoleDefaultPolicy")
    acts = actions(st)
    assert set(acts) == {"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "execute-api:Invoke",
                         "s3:GetObject", "xray:PutTelemetryRecords", "xray:PutTraceSegments"}
    assert not any(a.startswith(("dynamodb:", "sns:", "states:", "secretsmanager:")) for a in acts)
    s3 = [s for s in st if s.get("Sid") == "ReadPublicDocsOnly"][0]
    assert "/public/*" in json.dumps(s3["Resource"])


def test_agent_can_only_reach_agent_routes(t):
    st = [s for s in statements(t, "AgentServiceRoleDefaultPolicy") if s["Action"] == "execute-api:Invoke"][0]
    res = json.dumps(st["Resource"])
    assert "/v1/runs" in res and "/v1/calls" in res
    assert "dashboard" not in res and "email" not in res and "slack" not in res
    assert "{id}" not in res, "IAM resources must wildcard path parameters, or every /{id} route is a 403"
    assert "/POST/v1/runs/*/calls" in res


def test_only_gate_function_touches_table_and_resumes_workflows(t):
    for k, v in t.find_resources("AWS::IAM::Policy").items():
        doc = json.dumps(v)
        if "dynamodb:PutItem" in doc or "states:SendTaskSuccess" in doc:
            assert k.startswith("GateGateFunctionServiceRoleDefaultPolicy"), k


def test_executor_writes_outbox_only(t):
    st = statements(t, "ExecuteServiceRoleDefaultPolicy")
    put = [s for s in st if s.get("Sid") == "WriteOutboxOnly"][0]
    assert "/outbox/*" in json.dumps(put["Resource"])
    assert "s3:GetObject" not in actions(st) and not any(a.startswith("bedrock:") for a in actions(st))


def test_route_authorizers(t):
    routes = {v["Properties"]["RouteKey"]: v["Properties"].get("AuthorizationType", "NONE")
              for v in t.find_resources("AWS::ApiGatewayV2::Route").values()}
    for rk, auth in routes.items():
        if rk.startswith("OPTIONS"):
            continue
        if "/v1/dashboard" in rk:
            assert auth == "JWT", rk
        elif rk.split(" ")[1].startswith("/v1/"):
            assert auth == "AWS_IAM", rk
        else:
            assert rk in ("GET /email/decide", "POST /email/decide", "POST /slack/interact"), rk


def test_principals_registered(t):
    fn = [v for k, v in t.find_resources("AWS::Lambda::Function").items() if k.startswith("GateGateFunction")][0]
    p = json.dumps(fn["Properties"]["Environment"]["Variables"]["PRINCIPALS"])
    assert "AgentServiceRole" in p and "ExecuteServiceRole" in p and "support-bot" in p


def test_table_pitr_and_approvers_no_self_signup(t):
    t.has_resource_properties("AWS::DynamoDB::GlobalTable", {
        "Replicas": Match.array_with([Match.object_like({
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}})])})
    t.has_resource_properties("AWS::Cognito::UserPool", {
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True}})


def test_workflow_waits_and_logs_everything(t):
    sm = list(t.find_resources("AWS::StepFunctions::StateMachine").values())[0]["Properties"]
    d = json.dumps(sm["DefinitionString"])
    assert ".waitForTaskToken" in d and "attach_task_token" in d
    assert sm["LoggingConfiguration"]["Level"] == "ALL" and sm["LoggingConfiguration"]["IncludeExecutionData"]


def test_api_has_access_logs_and_throttling(t):
    t.has_resource_properties("AWS::ApiGatewayV2::Stage", {
        "AccessLogSettings": Match.object_like({"DestinationArn": Match.any_value()}),
        "DefaultRouteSettings": Match.object_like({"ThrottlingRateLimit": 50})})


def test_bad_policy_fails_synth(tmp_path):
    bad = tmp_path / "p.json"
    bad.write_text(json.dumps({"rules": [{"id": "x", "tool": "t", "effect": "sometimes"}]}))
    stack = cdk.Stack(cdk.App(), "B", env=ENV)
    with pytest.raises(PolicyError):
        ActionGate(stack, "G", policy=str(bad))


def test_construct_standalone_minimal():
    """The construct works without email, Slack, or a dashboard."""
    stack = cdk.Stack(cdk.App(), "M", env=ENV)
    ActionGate(stack, "G", policy={"rules": [{"id": "a", "tool": "*", "effect": "approve"}]})
    t = Template.from_stack(stack)
    t.resource_count_is("AWS::SNS::Topic", 0)
    t.resource_count_is("AWS::CloudFront::Distribution", 0)
    routes = [v["Properties"]["RouteKey"] for v in t.find_resources("AWS::ApiGatewayV2::Route").values()]
    assert "POST /slack/interact" not in routes


@pytest.mark.skipif(not os.path.isdir("dashboard/dist"), reason="dashboard not built")
def test_dashboard_private_bucket_behind_cloudfront(t):
    t.resource_count_is("AWS::CloudFront::Distribution", 1)
    t.has_resource_properties("AWS::CloudFront::Distribution", {"DistributionConfig": Match.object_like({
        "DefaultCacheBehavior": Match.object_like({"ViewerProtocolPolicy": "redirect-to-https"})})})
