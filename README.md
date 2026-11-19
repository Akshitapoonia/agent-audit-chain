# agent-audit-chain

A small, standard-library-only Python example of a tamper-evident audit log for AI agent tool calls: a hash chain plus signed checkpoints, with tests for eight tampering attacks.

This is a teaching example, not production code. Keys live in memory, storage is a Python list, and checkpoints are signed with HMAC for brevity. In production, sign checkpoints with an asymmetric key held in a KMS or HSM and write them to a separate, write-once store.

## What it does

Each entry records one tool call: the agent's own identity, the person it acted for, the tool, the policy decision (allow, deny, escalate), and keyed digests of the inputs and outputs. Each entry includes the hash of the previous one. Every N entries, a signed checkpoint is written to a separate store.

Argument and result digests use a keyed hash (HMAC-SHA-256) so low-entropy values such as patient IDs cannot be recovered by hashing guesses.

## Run it

    python3 agent_audit_chain.py

No dependencies. It appends and verifies 100,000 entries, then runs the attack tests.

## Results

Run on a developer laptop, single-threaded Python 3.9. Throughput varies between runs.

| Measure | Result |
|---|---|
| Append 100,000 entries | about 1.1 to 1.5 s (roughly 70,000 to 90,000 per second) |
| Verify 100,000 entries | about 0.57 s (roughly 175,000 per second) |
| Average entry size | 473 bytes |

| Attack | Detected |
|---|---|
| Edit one entry | Yes |
| Edit an entry and recompute its hash | Yes |
| Delete an entry from the middle | Yes |
| Swap two entries | Yes |
| Truncate entries after the last checkpoint | No |
| Truncate past a checkpoint | Yes |
| Rewrite from entry N on and recompute all hashes, checkpoints intact | Yes |
| Same rewrite, checkpoints also deleted | No |

The two "No" rows are the point: a hash chain alone cannot detect tail truncation or a full rewrite. Checkpoints stored outside the attacker's reach narrow the window, and the checkpoint interval sets how much unverified tail remains.

## Limits

- Tamper evidence shows a record was not changed after it was written. It does not show the record was correct.
- Log at the single enforcement point every tool call must pass, and reconcile against downstream systems' own access records.
- A single chain serializes writers. Use one chain per agent instance or a sequencer.
- Plan key rotation before writing the first checkpoint.

## License

MIT. See LICENSE.
