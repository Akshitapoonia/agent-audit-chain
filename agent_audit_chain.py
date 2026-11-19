"""Hash-chained audit log for AI agent tool calls, with signed checkpoints.

Reference implementation. Standard library only. Tested on Python 3.9.
Not production code: keys live in memory and storage is a Python list.
"""
import hashlib
import hmac
import json
import time

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


class AuditChain:
    def __init__(self, checkpoint_every: int = 1000, key: bytes = b"demo-key",
                 field_key: bytes = b"demo-field-key"):
        self.field_key = field_key  # separate key: guards low-entropy fields like patient IDs
        self.entries = []
        self.checkpoints = []  # would live in a separate, write-once store
        self.every = checkpoint_every
        self.key = key

    def fdigest(self, obj) -> str:
        return hmac.new(self.field_key, canonical(obj), hashlib.sha256).hexdigest()

    def append(self, agent_id, principal, tool, args, decision, reason, result):
        prev = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        body = {
            "seq": len(self.entries),
            "ts": time.time(),
            "agent_id": agent_id,
            "principal": principal,
            "tool": tool,
            "args_digest": self.fdigest(args),  # keyed hash of inputs, not the PHI itself
            "decision": decision,             # allow / deny / escalate
            "reason": reason,
            "result_digest": self.fdigest(result),
            "prev_hash": prev,
        }
        body["entry_hash"] = digest(body)
        self.entries.append(body)
        if (body["seq"] + 1) % self.every == 0:
            self._checkpoint(body)
        return body

    def _checkpoint(self, last):
        msg = f'{last["seq"]}:{last["entry_hash"]}'.encode()
        sig = hmac.new(self.key, msg, hashlib.sha256).hexdigest()
        self.checkpoints.append({"seq": last["seq"], "entry_hash": last["entry_hash"], "sig": sig})

    def verify(self):
        """Return (ok, first_bad_seq, reason)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e["seq"] != i:
                return False, i, "sequence gap or reorder"
            if e["prev_hash"] != prev:
                return False, i, "broken link"
            body = {k: v for k, v in e.items() if k != "entry_hash"}
            if digest(body) != e["entry_hash"]:
                return False, i, "entry modified"
            prev = e["entry_hash"]
        for c in self.checkpoints:
            if c["seq"] >= len(self.entries):
                return False, c["seq"], "log truncated below checkpoint"
            if self.entries[c["seq"]]["entry_hash"] != c["entry_hash"]:
                return False, c["seq"], "checkpoint mismatch"
            msg = f'{c["seq"]}:{c["entry_hash"]}'.encode()
            good = hmac.new(self.key, msg, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(good, c["sig"]):
                return False, c["seq"], "bad checkpoint signature"
        return True, None, "ok"


def fill(chain, n):
    for i in range(n):
        chain.append("agent:refill-01", "user:rn-4471", "read_meds",
                     {"patient": f"p{i % 500}"}, "allow", "in scope", {"n": 3})


if __name__ == "__main__":
    import copy

    N = 100_000
    c = AuditChain(checkpoint_every=1000)
    t = time.perf_counter(); fill(c, N); t_app = time.perf_counter() - t
    t = time.perf_counter(); ok = c.verify(); t_ver = time.perf_counter() - t
    print(f"append {N} entries: {t_app:.2f}s ({N / t_app:,.0f}/s)")
    print(f"verify {N} entries: {t_ver:.2f}s ({N / t_ver:,.0f}/s) -> {ok}")
    size = sum(len(canonical(e)) for e in c.entries)
    print(f"avg entry size: {size / N:.0f} bytes")

    # Tamper tests on a smaller chain (checkpoint every 100)
    def fresh():
        x = AuditChain(checkpoint_every=100); fill(x, 1000); return x

    x = fresh(); x.entries[437]["decision"] = "allow"; x.entries[437]["reason"] = "edited"
    print("edit one entry        ->", x.verify())

    x = fresh()
    e = x.entries[437]; e["decision"] = "deny"
    body = {k: v for k, v in e.items() if k != "entry_hash"}; e["entry_hash"] = digest(body)
    print("edit + rehash entry   ->", x.verify())

    x = fresh(); del x.entries[437]
    print("delete middle entry   ->", x.verify())

    x = fresh(); x.entries[10], x.entries[11] = x.entries[11], x.entries[10]
    print("swap two entries      ->", x.verify())

    def fresh2():  # 1050 entries, checkpoints at 99, 199, ..., 999
        x = AuditChain(checkpoint_every=100); fill(x, 1050); return x

    x = fresh2(); del x.entries[-30:]
    print("truncate after last ckpt ->", x.verify())

    x = fresh2(); del x.entries[-200:]
    print("truncate past a ckpt     ->", x.verify())

    # Attacker with write access to the log (but not the checkpoint key or store)
    # rewrites entry 437 and recomputes every later hash.
    x = fresh2()
    x.entries[437]["decision"] = "escalate"
    prev = x.entries[436]["entry_hash"]
    for e in x.entries[437:]:
        e["prev_hash"] = prev
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        e["entry_hash"] = digest(body); prev = e["entry_hash"]
    print("rewrite tail, ckpts kept ->", x.verify())

    x.checkpoints.clear()
    print("rewrite tail, no ckpts   ->", x.verify())
