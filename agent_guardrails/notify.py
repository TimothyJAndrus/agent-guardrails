"""Approval channels. The dashboard needs no notifier: it lists pending calls.

Email: an SNS message with a link. The link opens a confirmation page (GET
changes nothing, so mail scanners that prefetch links can't approve). Only the
POST from that page decides. The link carries a one-time secret; only its
sha256 is stored.

Slack: a message with Approve / Reject buttons. Clicks arrive at
/slack/interact, are verified with the Slack signing secret (HMAC, 5-minute
window), and count only if the clicking user's Slack ID is in the policy's
approvers.slack_user_ids.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.request
from urllib.parse import quote


def summarize(call: dict, limit: int = 1500) -> str:
    args = json.dumps(call.get("args", {}), indent=1, sort_keys=True, default=str)
    if len(args) > limit:
        args = args[:limit] + "\n... (truncated; full arguments on the dashboard)"
    return args


class EmailNotifier:
    channel = "email"

    def __init__(self, topic_arn: str, base_url, store, sns=None, dashboard_url: str = ""):
        """`base_url` may be a string or a zero-argument callable (the API URL is only known per request)."""
        self.topic_arn, self._base_url, self.store = topic_arn, base_url, store
        self.dashboard_url = dashboard_url.rstrip("/")
        self._sns = sns

    @property
    def base_url(self) -> str:
        url = self._base_url() if callable(self._base_url) else self._base_url
        if not url:
            raise RuntimeError("email approval link base URL is unknown")
        return url.rstrip("/")

    @property
    def sns(self):
        if self._sns is None:
            import boto3

            self._sns = boto3.client("sns")
        return self._sns

    def notify(self, call: dict) -> dict:
        secret = secrets.token_urlsafe(32)
        self.store.update_call(call["id"], {"email_token_hash": hashlib.sha256(secret.encode()).hexdigest()})
        link = f"{self.base_url}/email/decide?call={quote(call['id'])}&t={quote(secret)}"
        lines = [f"Agent '{call['agent']}' wants to call {call['tool']}.", "",
                 f"Rule: {call['rule']} ({call['reason']})", "", "Arguments:", summarize(call), "",
                 "Review and decide (opens a confirmation page; nothing happens until you press a button):", link]
        if self.dashboard_url:
            lines += ["", f"Dashboard: {self.dashboard_url}/#/runs/{call['run']}"]
        lines += ["", f"Run {call['run']} / call {call['id']}. This request expires at "
                      f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(call['expires_at']))}."]
        self.sns.publish(TopicArn=self.topic_arn, Subject=f"Approval needed: {call['tool']}"[:100],
                         Message="\n".join(lines))
        return {"topic": self.topic_arn.rsplit(":", 1)[-1]}


def email_token_ok(call: dict, secret: str) -> bool:
    want = call.get("email_token_hash") or ""
    got = hashlib.sha256((secret or "").encode()).hexdigest()
    return bool(want) and hmac.compare_digest(want, got)


class SlackNotifier:
    channel = "slack"

    def __init__(self, bot_token: str, channel_id: str, dashboard_url: str = "", post=None):
        self.bot_token, self.channel_id, self.dashboard_url = bot_token, channel_id, dashboard_url.rstrip("/")
        self._post = post or _post_json

    def notify(self, call: dict) -> dict:
        text = f"Agent *{call['agent']}* wants to call `{call['tool']}` (rule `{call['rule']}`)"
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"```{summarize(call, 2500)}```"}},
            {"type": "actions", "block_id": f"gate:{call['id']}", "elements": [
                {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve"},
                 "action_id": "approve", "value": call["id"],
                 "confirm": {"title": {"type": "plain_text", "text": "Approve this action?"},
                             "text": {"type": "plain_text", "text": f"{call['tool']} will run with these arguments."},
                             "confirm": {"type": "plain_text", "text": "Approve"},
                             "deny": {"type": "plain_text", "text": "Cancel"}}},
                {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Reject"},
                 "action_id": "reject", "value": call["id"]},
            ]},
        ]
        if self.dashboard_url:
            blocks.append({"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"<{self.dashboard_url}/#/runs/{call['run']}|Open run in dashboard>"}]})
        r = self._post("https://slack.com/api/chat.postMessage", {"channel": self.channel_id, "text": text,
                                                                   "blocks": blocks}, self.bot_token)
        if not r.get("ok"):
            raise RuntimeError(f"slack: {r.get('error', 'unknown error')}")
        return {"slack_ts": r.get("ts")}


def _post_json(url, body, token):
    if not url.startswith("https://slack.com/"):
        raise ValueError("refusing non-Slack URL")
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={  # noqa: S310
        "Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (checked above)
        return json.loads(resp.read())


def verify_slack(signing_secret: str, timestamp: str, body: str, signature: str, now=None) -> bool:
    """Slack request signing v0. Rejects anything older than 5 minutes (replay)."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - ts) > 300:
        return False
    base = f"v0:{ts}:{body}".encode()
    want = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature or "")
