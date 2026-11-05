"""Storage for runs, calls, counters, and the audit chain.

Two implementations with the same interface:

- MemoryStore: one process, for local mode and tests.
- DynamoStore: the deployed service. Every state change is a conditional
  write, so two Lambdas racing to approve or execute the same call can't both
  win, and audit sequence numbers can't collide.

Single-table layout (DynamoDB):

    pk            sk             item
    RUN#<id>      RUN            run           gsi1: RUNS / <started>
    RUN#<id>      EV#<seq:08>    audit event
    RUN#<id>      COUNT#<rule>   counter
    CALL#<id>     CALL           call          gsi1: STATE#<state> / <created>, gsi2: RUN#<run> / <created>
"""

from __future__ import annotations

import copy
import json
import threading
from decimal import Decimal

from .audit import GENESIS, make_event


class MemoryStore:
    def __init__(self):
        self._lock = threading.RLock()
        self._runs, self._calls, self._counts, self._events = {}, {}, {}, {}

    def put_run(self, run):
        with self._lock:
            if run["id"] in self._runs:
                return False
            self._runs[run["id"]] = copy.deepcopy(run)
            return True

    def get_run(self, run_id):
        r = self._runs.get(run_id)
        return copy.deepcopy(r) if r else None

    def update_run(self, run_id, upd):
        with self._lock:
            self._runs[run_id].update(upd)

    def list_runs(self, limit=50):
        return sorted((copy.deepcopy(r) for r in self._runs.values()), key=lambda r: -r["started"])[:limit]

    def put_call(self, call):
        with self._lock:
            self._calls[call["id"]] = copy.deepcopy(call)

    def get_call(self, call_id):
        c = self._calls.get(call_id)
        return copy.deepcopy(c) if c else None

    def update_call(self, call_id, upd):
        with self._lock:
            self._calls[call_id].update(upd)

    def transition_call(self, call_id, from_states, upd):
        with self._lock:
            c = self._calls.get(call_id)
            if not c or c["state"] not in from_states:
                return False
            c.update(upd)
            return True

    def calls_by_state(self, state, limit=50):
        return sorted((copy.deepcopy(c) for c in self._calls.values() if c["state"] == state),
                      key=lambda c: -c["created"])[:limit]

    def calls_for_run(self, run_id):
        return sorted((copy.deepcopy(c) for c in self._calls.values() if c["run"] == run_id),
                      key=lambda c: c["created"])

    def get_counts(self, run_id):
        return dict(self._counts.get(run_id, {}))

    def incr_count(self, run_id, key, limit=None):
        with self._lock:
            c = self._counts.setdefault(run_id, {})
            if limit is not None and c.get(key, 0) >= limit:
                return False
            c[key] = c.get(key, 0) + 1
            return True

    def append_event(self, run, step, agent, tool, data):
        with self._lock:
            chain = self._events.setdefault(run, [])
            ev = make_event(run, len(chain), chain[-1]["hash"] if chain else GENESIS, step, agent, tool,
                            _plain(data))
            chain.append(ev)
        print(json.dumps({"audit": True, **ev}, default=str))
        return ev

    def events(self, run_id):
        return copy.deepcopy(self._events.get(run_id, []))


def _plain(v):
    """JSON round-trip: what's hashed is exactly what is stored and read back."""
    return json.loads(json.dumps(v, default=str), parse_float=float)


def _to_ddb(v):
    return json.loads(json.dumps(v, default=str), parse_float=Decimal)


def _from_ddb(v):
    if isinstance(v, list):
        return [_from_ddb(x) for x in v]
    if isinstance(v, dict):
        return {k: _from_ddb(x) for k, x in v.items()}
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    return v


class DynamoStore:
    KEYS = ("pk", "sk", "gsi1pk", "gsi1sk", "gsi2pk", "gsi2sk")

    def __init__(self, table_name, resource=None):
        import boto3

        self.table = (resource or boto3.resource("dynamodb")).Table(table_name)
        self._errors = self.table.meta.client.exceptions

    def _clean(self, item):
        return _from_ddb({k: v for k, v in item.items() if k not in self.KEYS}) if item else None

    # runs
    def put_run(self, run):
        item = {"pk": f"RUN#{run['id']}", "sk": "RUN", "gsi1pk": "RUNS", "gsi1sk": f"{run['started']:017.3f}",
                **_to_ddb(run)}
        try:
            self.table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
            return True
        except self._errors.ConditionalCheckFailedException:
            return False

    def get_run(self, run_id):
        return self._clean(self.table.get_item(Key={"pk": f"RUN#{run_id}", "sk": "RUN"}).get("Item"))

    def update_run(self, run_id, upd):
        self._update({"pk": f"RUN#{run_id}", "sk": "RUN"}, upd)

    def list_runs(self, limit=50):
        r = self.table.query(IndexName="gsi1", KeyConditionExpression="gsi1pk = :p",
                             ExpressionAttributeValues={":p": "RUNS"}, ScanIndexForward=False, Limit=limit)
        return [self._clean(i) for i in r["Items"]]

    # calls
    def _call_keys(self, call):
        return {"pk": f"CALL#{call['id']}", "sk": "CALL", "gsi1pk": f"STATE#{call['state']}",
                "gsi1sk": f"{call['created']:017.3f}", "gsi2pk": f"RUN#{call['run']}",
                "gsi2sk": f"{call['created']:017.3f}"}

    def put_call(self, call):
        self.table.put_item(Item={**self._call_keys(call), **_to_ddb(call)},
                            ConditionExpression="attribute_not_exists(pk)")

    def get_call(self, call_id):
        return self._clean(self.table.get_item(Key={"pk": f"CALL#{call_id}", "sk": "CALL"},
                                               ConsistentRead=True).get("Item"))

    def update_call(self, call_id, upd):
        self._update({"pk": f"CALL#{call_id}", "sk": "CALL"}, upd)

    def transition_call(self, call_id, from_states, upd):
        upd = dict(upd)
        if "state" in upd:
            upd["gsi1pk"] = f"STATE#{upd['state']}"
        names = {f"#s{i}": s for i, s in enumerate(["state"])}
        values = {f":f{i}": s for i, s in enumerate(sorted(from_states))}
        cond = f"#s0 IN ({', '.join(values)})"
        try:
            self._update({"pk": f"CALL#{call_id}", "sk": "CALL"}, upd, cond, names, values)
            return True
        except self._errors.ConditionalCheckFailedException:
            return False

    def calls_by_state(self, state, limit=50):
        r = self.table.query(IndexName="gsi1", KeyConditionExpression="gsi1pk = :p",
                             ExpressionAttributeValues={":p": f"STATE#{state}"}, ScanIndexForward=False, Limit=limit)
        return [self._clean(i) for i in r["Items"]]

    def calls_for_run(self, run_id):
        items, kw = [], {"IndexName": "gsi2", "KeyConditionExpression": "gsi2pk = :p",
                         "ExpressionAttributeValues": {":p": f"RUN#{run_id}"}}
        while True:
            r = self.table.query(**kw)
            items += r["Items"]
            if "LastEvaluatedKey" not in r:
                return [self._clean(i) for i in items]
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    # counters
    def get_counts(self, run_id):
        r = self.table.query(KeyConditionExpression="pk = :p AND begins_with(sk, :c)",
                             ExpressionAttributeValues={":p": f"RUN#{run_id}", ":c": "COUNT#"}, ConsistentRead=True)
        return {i["sk"][6:]: int(i["n"]) for i in r["Items"]}

    def incr_count(self, run_id, key, limit=None):
        kw = {"Key": {"pk": f"RUN#{run_id}", "sk": f"COUNT#{key}"}, "UpdateExpression": "ADD n :one",
              "ExpressionAttributeValues": {":one": 1}}
        if limit is not None:
            kw["ConditionExpression"] = "attribute_not_exists(n) OR n < :lim"
            kw["ExpressionAttributeValues"][":lim"] = limit
        try:
            self.table.update_item(**kw)
            return True
        except self._errors.ConditionalCheckFailedException:
            return False

    # audit chain
    def _last_event(self, run_id):
        r = self.table.query(KeyConditionExpression="pk = :p AND begins_with(sk, :e)",
                             ExpressionAttributeValues={":p": f"RUN#{run_id}", ":e": "EV#"},
                             ScanIndexForward=False, Limit=1, ConsistentRead=True)
        return self._clean(r["Items"][0]) if r["Items"] else None

    def append_event(self, run, step, agent, tool, data):
        data = _plain(data)
        for _ in range(8):
            last = self._last_event(run)
            seq, prev = (last["seq"] + 1, last["hash"]) if last else (0, GENESIS)
            ev = make_event(run, seq, prev, step, agent, tool, data)
            try:
                self.table.put_item(Item={"pk": f"RUN#{run}", "sk": f"EV#{seq:08d}", **_to_ddb(ev)},
                                    ConditionExpression="attribute_not_exists(pk)")
                print(json.dumps({"audit": True, **ev}, default=str))
                return ev
            except self._errors.ConditionalCheckFailedException:
                continue  # another writer took this seq; re-read the head and retry
        raise RuntimeError("audit append contention")

    def events(self, run_id):
        items, kw = [], {"KeyConditionExpression": "pk = :p AND begins_with(sk, :e)",
                         "ExpressionAttributeValues": {":p": f"RUN#{run_id}", ":e": "EV#"}, "ConsistentRead": True}
        while True:
            r = self.table.query(**kw)
            items += r["Items"]
            if "LastEvaluatedKey" not in r:
                return [self._clean(i) for i in items]
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    # helper
    def _update(self, key, upd, cond=None, names=None, values=None):
        names, values = dict(names or {}), dict(values or {})
        sets = []
        for i, (k, v) in enumerate(upd.items()):
            names[f"#u{i}"] = k
            values[f":u{i}"] = _to_ddb(v)
            sets.append(f"#u{i} = :u{i}")
        kw = {"Key": key, "UpdateExpression": "SET " + ", ".join(sets), "ExpressionAttributeNames": names,
              "ExpressionAttributeValues": values}
        if cond:
            kw["ConditionExpression"] = cond
        self.table.update_item(**kw)
