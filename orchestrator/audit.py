"""Append-only, hash-chained log. Editing any past line breaks the chain."""
import hashlib
import json
import time

GENESIS = "0" * 64


def _digest(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path, self.prev = path, GENESIS
        try:
            with open(path) as f:
                for line in f:
                    self.prev = json.loads(line)["hash"]
        except FileNotFoundError:
            pass

    def append(self, kind, **data):
        entry = {"ts": time.time(), "kind": kind, "data": data, "prev": self.prev}
        entry["hash"] = _digest(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self.prev = entry["hash"]

    def verify(self):
        prev, n = GENESIS, 0
        try:
            with open(self.path) as f:
                for line in f:
                    e = json.loads(line)
                    h = e.pop("hash")
                    if e["prev"] != prev or _digest(e) != h:
                        return {"ok": False, "broken_at": n}
                    prev, n = h, n + 1
        except FileNotFoundError:
            pass
        return {"ok": True, "entries": n}

    # TODO: copy self.prev to a separate machine on a schedule (anchoring), so deleting
    # the newest entries or rebuilding the whole chain is detected too.
