"""CDK construct: drop an action gate into any stack.

    from guardrails_cdk import ActionGate

    gate = ActionGate(self, "Gate", policy="policy.yaml", approver_emails=["you@example.com"])
    gate.register_agent(agent_fn.role, "support-bot")         # may check calls and execute its own
    gate.register_executor(execute_fn.role, ["support-bot"])  # may execute calls on behalf of agents
    gate.grant_wait_for_approval(state_machine)                # Step Functions can wait for a decision

What it creates:

- DynamoDB table (runs, calls, counters, hash-chained audit events), PITR on.
- One Lambda (the gate) behind an HTTP API:
    agent routes      AWS_IAM auth; the caller's role must also be registered (checked in code)
    dashboard routes  Cognito JWT auth; deciding also requires the email to be in policy approvers
    email / Slack     no API auth; one-time link secret / Slack signature verified in code
- Cognito user pool for approvers (no self sign-up).
- SNS topic for email approvals (if approver_emails), Secrets Manager secret for Slack (if slack=True).
- Dashboard: private S3 bucket behind CloudFront (OAC), with config.json written at deploy time.

The policy is validated at synth time: a bad policy fails `cdk synth`, not a tool call.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile

import aws_cdk as cdk
from aws_cdk import (
    aws_apigatewayv2 as apigw,
)
from aws_cdk import (
    aws_apigatewayv2_authorizers as authz,
)
from aws_cdk import (
    aws_apigatewayv2_integrations as integ,
)
from aws_cdk import (
    aws_cloudfront as cf,
)
from aws_cdk import (
    aws_cloudfront_origins as origins,
)
from aws_cdk import (
    aws_cognito as cognito,
)
from aws_cdk import (
    aws_dynamodb as ddb,
)
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
    aws_secretsmanager as sm,
)
from aws_cdk import (
    aws_sns as sns,
)
from aws_cdk import (
    aws_sns_subscriptions as subs,
)
from aws_cdk import (
    aws_stepfunctions as sfn,
)
from constructs import Construct

import agent_guardrails
from agent_guardrails import policy as policy_mod

PKG_DIR = os.path.dirname(os.path.abspath(agent_guardrails.__file__))
SERVICE_DIR = os.path.join(os.path.dirname(PKG_DIR), "service")

AGENT_ROUTES = [
    ("POST", "/v1/runs"), ("POST", "/v1/runs/{id}/end"), ("POST", "/v1/runs/{id}/calls"),
    ("GET", "/v1/calls/{id}"), ("POST", "/v1/calls/{id}/consume"), ("POST", "/v1/calls/{id}/result"),
]
DASHBOARD_ROUTES = [
    ("GET", "/v1/dashboard/pending"), ("GET", "/v1/dashboard/denials"), ("GET", "/v1/dashboard/runs"),
    ("GET", "/v1/dashboard/runs/{id}"), ("GET", "/v1/dashboard/policy"),
    ("POST", "/v1/dashboard/calls/{id}/decide"),
]
PUBLIC_ROUTES = [("GET", "/email/decide"), ("POST", "/email/decide"), ("POST", "/slack/interact")]


def _load_policy(policy) -> dict:
    if isinstance(policy, dict):
        doc = policy
    else:
        path = str(policy)
        with open(path) as f:
            if path.endswith(".json"):
                doc = json.load(f)
            else:
                import yaml

                doc = yaml.safe_load(f)
    policy_mod.parse(doc)  # raises PolicyError at synth time
    return doc


def _stage_code(policy_doc: dict) -> str:
    """Lambda asset: agent_guardrails/ + service/ + policy.json. Content-hashed, so stable across synths."""
    out = tempfile.mkdtemp(prefix="agent-guardrails-asset-")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(PKG_DIR, os.path.join(out, "agent_guardrails"), ignore=ignore)
    shutil.copytree(SERVICE_DIR, os.path.join(out, "service"), ignore=ignore)
    with open(os.path.join(out, "policy.json"), "w") as f:
        json.dump(policy_doc, f, sort_keys=True, indent=1)
    return out


class ActionGate(Construct):
    def __init__(self, scope: Construct, cid: str, *, policy, approver_emails: list[str] | None = None,
                 slack: bool = False, dashboard_assets: str | None = None, cognito_domain_prefix: str | None = None,
                 removal_policy: cdk.RemovalPolicy = cdk.RemovalPolicy.RETAIN,
                 log_retention: logs.RetentionDays = logs.RetentionDays.ONE_MONTH) -> None:
        super().__init__(scope, cid)
        stack = cdk.Stack.of(self)
        self.policy_doc = _load_policy(policy)
        if approver_emails:
            approvers = self.policy_doc.setdefault("approval", {}).setdefault("approvers", {})
            approvers.setdefault("emails", list(approver_emails))
        self._principals: dict[str, dict] = {}
        destroy = removal_policy == cdk.RemovalPolicy.DESTROY

        # ---------- state ----------
        self.table = ddb.TableV2(
            self, "Table",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="sk", type=ddb.AttributeType.STRING),
            billing=ddb.Billing.on_demand(),
            point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True),
            removal_policy=removal_policy,
            global_secondary_indexes=[
                ddb.GlobalSecondaryIndexPropsV2(
                    index_name="gsi1", partition_key=ddb.Attribute(name="gsi1pk", type=ddb.AttributeType.STRING),
                    sort_key=ddb.Attribute(name="gsi1sk", type=ddb.AttributeType.STRING)),
                ddb.GlobalSecondaryIndexPropsV2(
                    index_name="gsi2", partition_key=ddb.Attribute(name="gsi2pk", type=ddb.AttributeType.STRING),
                    sort_key=ddb.Attribute(name="gsi2sk", type=ddb.AttributeType.STRING)),
            ],
        )

        # ---------- approvers ----------
        self.user_pool = cognito.UserPool(
            self, "Approvers",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            standard_attributes=cognito.StandardAttributes(email=cognito.StandardAttribute(required=True)),
            mfa=cognito.Mfa.OPTIONAL, mfa_second_factor=cognito.MfaSecondFactor(otp=True, sms=False),
            password_policy=cognito.PasswordPolicy(min_length=12),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            removal_policy=removal_policy,
        )

        env = {"TABLE_NAME": self.table.table_name, "POLICY_FILE": "/var/task/policy.json",
               "PRINCIPALS": "{}"}
        self.topic = None
        if approver_emails:
            self.topic = sns.Topic(self, "ApprovalTopic", display_name="Agent approval", enforce_ssl=True)
            for e in approver_emails:
                self.topic.add_subscription(subs.EmailSubscription(e))
            env["APPROVAL_TOPIC_ARN"] = self.topic.topic_arn
        self.slack_secret = None
        if slack:
            self.slack_secret = sm.Secret(
                self, "SlackSecret", description="agent-guardrails Slack app: bot_token, signing_secret, channel_id",
                secret_object_value={k: cdk.SecretValue.unsafe_plain_text("set-me")
                                     for k in ("bot_token", "signing_secret", "channel_id")},
                removal_policy=removal_policy)
            env["SLACK_SECRET_ARN"] = self.slack_secret.secret_arn

        group = logs.LogGroup(self, "GateLogs", retention=log_retention,
                              removal_policy=cdk.RemovalPolicy.DESTROY if destroy else cdk.RemovalPolicy.RETAIN)
        self.function = lambda_.Function(
            self, "GateFunction",
            runtime=lambda_.Runtime.PYTHON_3_13, architecture=lambda_.Architecture.ARM_64,
            code=lambda_.Code.from_asset(_stage_code(self.policy_doc)), handler="service.handler.handler",
            timeout=cdk.Duration.seconds(15), memory_size=512, environment=env, log_group=group,
            tracing=lambda_.Tracing.ACTIVE,
        )
        self.table.grant_read_write_data(self.function)
        if self.topic:
            self.topic.grant_publish(self.function)
        if self.slack_secret:
            self.slack_secret.grant_read(self.function)
        self.function.add_to_role_policy(iam.PolicyStatement(
            sid="ResumeWaitingWorkflows", actions=["states:SendTaskSuccess"],
            resources=[stack.format_arn(service="states", resource="stateMachine", resource_name="*",
                                        arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME)]))

        # ---------- dashboard ----------
        self.distribution = None
        self.dashboard_url = ""
        if dashboard_assets:
            site = s3.Bucket(self, "DashboardBucket", block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                             encryption=s3.BucketEncryption.S3_MANAGED, enforce_ssl=True,
                             removal_policy=cdk.RemovalPolicy.DESTROY, auto_delete_objects=True)
            headers = cf.ResponseHeadersPolicy(
                self, "DashboardHeaders",
                security_headers_behavior=cf.ResponseSecurityHeadersBehavior(
                    content_security_policy=cf.ResponseHeadersContentSecurityPolicy(
                        content_security_policy="default-src 'self'; connect-src 'self' https://*.amazonaws.com "
                                                "https://*.amazoncognito.com; img-src 'self' data:; "
                                                "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                        override=True),
                    frame_options=cf.ResponseHeadersFrameOptions(frame_option=cf.HeadersFrameOption.DENY,
                                                                 override=True),
                    strict_transport_security=cf.ResponseHeadersStrictTransportSecurity(
                        access_control_max_age=cdk.Duration.days(365), include_subdomains=True, override=True),
                    content_type_options=cf.ResponseHeadersContentTypeOptions(override=True),
                    referrer_policy=cf.ResponseHeadersReferrerPolicy(
                        referrer_policy=cf.HeadersReferrerPolicy.NO_REFERRER, override=True)))
            self.distribution = cf.Distribution(
                self, "Dashboard", default_root_object="index.html",
                default_behavior=cf.BehaviorOptions(
                    origin=origins.S3BucketOrigin.with_origin_access_control(site),
                    viewer_protocol_policy=cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    response_headers_policy=headers),
                minimum_protocol_version=cf.SecurityPolicyProtocol.TLS_V1_2_2021)
            self.dashboard_url = f"https://{self.distribution.distribution_domain_name}"
            self.function.add_environment("DASHBOARD_URL", self.dashboard_url)

        # ---------- API ----------
        access_logs = logs.LogGroup(self, "ApiAccessLogs", retention=log_retention,
                                    removal_policy=cdk.RemovalPolicy.DESTROY if destroy else cdk.RemovalPolicy.RETAIN)
        self.api = apigw.HttpApi(self, "Api", description="agent-guardrails action gate", create_default_stage=False,
                                 cors_preflight=apigw.CorsPreflightOptions(
                                     allow_origins=["http://localhost:5173"] + (
                                         [self.dashboard_url] if self.dashboard_url else []),
                                     allow_headers=["authorization", "content-type"],
                                     allow_methods=[apigw.CorsHttpMethod.GET, apigw.CorsHttpMethod.POST]))
        stage = apigw.HttpStage(self, "Stage", http_api=self.api, auto_deploy=True,
                                throttle=apigw.ThrottleSettings(rate_limit=50, burst_limit=100))
        cfn_stage = stage.node.default_child
        cfn_stage.access_log_settings = apigw.CfnStage.AccessLogSettingsProperty(
            destination_arn=access_logs.log_group_arn,
            format=json.dumps({"requestId": "$context.requestId", "route": "$context.routeKey",
                               "status": "$context.status", "caller": "$context.identity.userArn",
                               "ip": "$context.identity.sourceIp", "ts": "$context.requestTimeEpoch"}))
        self.function.add_environment("PUBLIC_URL", stage.url)  # email links (no cycle: stage -> api only)

        target = integ.HttpLambdaIntegration("Gate", self.function)
        iam_auth = authz.HttpIamAuthorizer()

        callback = [self.dashboard_url + "/"] if dashboard_assets else ["http://localhost:5173/"]
        if dashboard_assets:
            callback.append("http://localhost:5173/")
        self.user_pool_client = self.user_pool.add_client(
            "DashboardClient", generate_secret=False, prevent_user_existence_errors=True,
            auth_flows=cognito.AuthFlow(user_srp=True),
            o_auth=cognito.OAuthSettings(flows=cognito.OAuthFlows(authorization_code_grant=True),
                                         scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL],
                                         callback_urls=callback, logout_urls=callback),
            access_token_validity=cdk.Duration.hours(1), id_token_validity=cdk.Duration.hours(1),
            refresh_token_validity=cdk.Duration.hours(12))
        prefix = cognito_domain_prefix or f"guardrails-{cdk.Names.unique_id(self).lower()[-20:]}"
        self.user_pool_domain = self.user_pool.add_domain(
            "Domain", cognito_domain=cognito.CognitoDomainOptions(domain_prefix=prefix))
        jwt_auth = authz.HttpJwtAuthorizer(
            "Cognito", f"https://cognito-idp.{stack.region}.amazonaws.com/{self.user_pool.user_pool_id}",
            jwt_audience=[self.user_pool_client.user_pool_client_id])

        for method, path in AGENT_ROUTES:
            self.api.add_routes(path=path, methods=[apigw.HttpMethod(method)], integration=target,
                                authorizer=iam_auth)
        for method, path in DASHBOARD_ROUTES:
            self.api.add_routes(path=path, methods=[apigw.HttpMethod(method)], integration=target,
                                authorizer=jwt_auth)
        for method, path in PUBLIC_ROUTES:
            if path.startswith("/slack") and not slack:
                continue
            self.api.add_routes(path=path, methods=[apigw.HttpMethod(method)], integration=target)

        if dashboard_assets:
            s3deploy.BucketDeployment(
                self, "DashboardDeploy", destination_bucket=site, distribution=self.distribution,
                sources=[s3deploy.Source.asset(dashboard_assets),
                         s3deploy.Source.json_data("config.json", {
                             "apiUrl": stage.url, "region": stack.region,
                             "userPoolClientId": self.user_pool_client.user_pool_client_id,
                             "cognitoDomain": self.user_pool_domain.base_url()})])

        for k, v in {"ApiUrl": stage.url, "TableName": self.table.table_name,
                     "UserPoolId": self.user_pool.user_pool_id, "GateFunctionName": self.function.function_name,
                     **({"DashboardUrl": self.dashboard_url} if dashboard_assets else {}),
                     **({"SlackSecretArn": self.slack_secret.secret_arn} if self.slack_secret else {})}.items():
            cdk.CfnOutput(self, k, value=v)
        self._stage = stage

    # ---------- wiring ----------
    @property
    def api_url(self) -> str:
        return self._stage.url

    def _register(self, role: iam.IRole, entry: dict):
        # PRINCIPALS is a JSON env var keyed by role ARN. A token inside the JSON string resolves to
        # Fn::Join at synth. Roles with a path aren't supported: STS assumed-role ARNs drop the path.
        self._principals[role.role_arn] = entry
        self.function.add_environment("PRINCIPALS", json.dumps(self._principals))
        role.add_to_principal_policy(iam.PolicyStatement(
            sid=f"CallActionGate{len(self._principals)}", actions=["execute-api:Invoke"],
            # IAM matches the concrete request path, so path parameters must be wildcards here.
            resources=[self.api.arn_for_execute_api(method=m, path=p.replace("{id}", "*"), stage="$default")
                       for m, p in AGENT_ROUTES]))

    def register_agent(self, role: iam.IRole, agent_name: str) -> None:
        """Let a role act as `agent_name`: start runs, check calls, execute its own approved calls."""
        if not policy_mod._NAME.match(agent_name):
            raise ValueError("invalid agent name")
        self._register(role, {"agent": agent_name})

    def register_executor(self, role: iam.IRole, for_agents: list[str]) -> None:
        """Let a role (e.g. a post-approval Lambda) execute calls made by these agents. It cannot check calls."""
        self._register(role, {"agent": "", "execute_for": list(for_agents)})

    def grant_wait_for_approval(self, state_machine: sfn.IStateMachine) -> None:
        self.function.grant_invoke(state_machine)

    def wait_for_approval_task(self, scope: Construct, cid: str, *, call_id_path: str, agent: str,
                               timeout: cdk.Duration | None = None, result_path: str = "$.approval"):
        """A Step Functions task that pauses until the call at `call_id_path` is decided."""
        from aws_cdk import aws_stepfunctions_tasks as tasks

        return tasks.LambdaInvoke(
            scope, cid, lambda_function=self.function,
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            payload=sfn.TaskInput.from_object({"op": "attach_task_token", "agent": agent,
                                               "call": sfn.JsonPath.string_at(call_id_path),
                                               "token": sfn.JsonPath.task_token}),
            result_path=result_path, task_timeout=sfn.Timeout.duration(timeout or cdk.Duration.hours(1)))
