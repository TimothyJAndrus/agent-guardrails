"""agent-guardrails: an action gate for AI agents.

Every tool call is checked against a policy (allow / deny / require approval),
approvals come from a human over the dashboard, Slack, or email, and every step
lands in a hash-chained audit trail you can replay.
"""

from .engine import Approver, Gate, GateError
from .policy import Decision, Policy, PolicyError, load, parse
from .sdk import ApprovalPending, Denied, Expired, Guard, GuardError, Rejected
from .store import DynamoStore, MemoryStore

__version__ = "0.1.0"

__all__ = [
    "ApprovalPending", "Approver", "Decision", "Denied", "DynamoStore", "Expired", "Gate", "GateError", "Guard",
    "GuardError", "MemoryStore", "Policy", "PolicyError", "Rejected", "load", "parse", "__version__",
]
