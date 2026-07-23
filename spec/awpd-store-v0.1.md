# awpd Store v0.1 — Persistence Layout (bbolt)

**Status:** draft. Implementation spec for the reference daemon only — NOT
normative for the protocol. The invariants marked **[P]** are protocol
obligations from `awp-core`; everything else is `awpd`'s choice.

## 1. Model

One bbolt DB file, single writer (bbolt's concurrency model). Every envelope
event mutates the store in **one transaction** — atomicity boundaries below
are load-bearing for crash safety. Keys are raw ULID/domain bytes as shown;
values are JSON unless noted.

## 2. Buckets

### `meta`
`schema → int`. Migrations refuse to open a newer schema version.

### `seen` — inbound dedupe **[P]**
- Key: envelope ULID. Value: 8-byte big-endian unix expiry = `ts + ttl`.
- Written in the **same tx** as the `inq` insert — gate 4 and gate 5 of core
  §2.2 are atomic; a crash between them cannot produce an acked-but-lost or
  processed-twice envelope.
- **[P]** Retention: never delete before expiry (receivers must retain
  seen-ids ≥ max accepted TTL).
- GC: hourly cursor scan deleting expired keys.

### `inq` / `inq_active` — inbound processing queue
- `inq` key: envelope ULID (ULID ⇒ arrival-ordered iteration for free).
  Value: full envelope.
- Claim: move key `inq → inq_active` in one tx. Complete: delete from
  `inq_active` + write thread updates, same tx.
- Boot recovery: everything in `inq_active` moves back to `inq`.
  Semantics are **at-least-once**; processing MUST be idempotent per
  envelope `id`.

### `outbox` — delivery records (see `awpd-outbox-v0.1.md`)
- Key: envelope ULID.
- Value: `{envelope, state, attempts, next_at, last_err}`.

### `outbox_sched` — retry schedule index
- Key: `next_at (8B big-endian) ++ ULID`. Value: empty.
- Rewritten whenever `next_at` changes, same tx as the `outbox` update.
- The delivery loop reads the head of this bucket — never scans `outbox`.

### `threads`
- Key: thread ULID.
- Value: `{peer, opened_ts, closed: bool, closed_by, last_ts, last_id}`.
- **[P]** Two-party invariant enforced here at processing time: an envelope
  whose (`from`,`to`) don't match `peer` is a protocol error
  (`error(refused)`), not a silent merge.

### `thread_msgs`
- Key: `thread ULID ++ envelope ULID`. Value: envelope ULID (ref into the
  archived envelope).
- Prefix range scan returns the conversation in (`ts`,`id`) order because
  ULIDs sort lexically by time.

### `keys_cache`
- Key: domain. Value: `{index_json, fetched_at, etag}`.
- `Refresh(domain)` — the gate-3 rotation retry — deletes then re-fetches.
- A fetch failure keeps the stale entry but **marks it stale**: verification
  degrades loudly (logged, surfaced), never silently.

### `sessions` — only when hosting `state: provider` apps
- Key: sid ULID. Value: `{caller_principal, entity, expires}`.
- Tokens are self-authenticating (signed), so this bucket is bookkeeping and
  revocation support — **absence after restart means
  still-valid-if-signature-verifies**, not revoked. (The wrong polarity —
  presence = valid — would revoke every session on data loss.)

## 3. Transaction boundaries (summary)

| Event | Single tx contains |
|---|---|
| Inbound accepted | `seen` insert + `inq` insert |
| Worker claim | `inq` delete + `inq_active` insert |
| Worker complete | `inq_active` delete + `threads` update + `thread_msgs` insert |
| Outbound enqueue | `outbox` insert + `outbox_sched` insert |
| Retry reschedule | `outbox` update + `outbox_sched` delete/insert |
| Boot recovery | bulk `inq_active → inq`; bulk `outbox` `delivering → queued` |

## 4. Sizing

Envelopes ≤ 256 KiB by protocol **[P]**; `resource` bodies keep the store
small by construction. No overflow/blob handling needed in v0.1.
