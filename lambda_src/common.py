"""Shared helpers: structured audit log lines (one JSON object per event)."""
import json
import time


def audit(execution, step, **fields):
    """Print one audit event. CloudWatch Logs keeps it; scripts/run_demo.py replays it."""
    rec = {"audit": True, "ts": round(time.time(), 3), "execution": execution or "local", "step": step}
    rec.update(fields)
    print(json.dumps(rec, default=str))
    return rec
