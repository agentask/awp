# AWP-Discovery v0.1 — Index Query and Submission Schema

**Status: STRAWMAN.** Every field is provisional until validated against a
real crawler over real domains (post-milestone-1). Normative language is used
so the draft is testable, not because it is settled. Discovery mechanisms
(direct, referral, crawl graph) are defined in `awp-core` §3; this document
defines only the **index interface**.

## 1. Model

An index is an ordinary AWP domain publishing two standard `tool` entities:

| Entity | Purpose |
|---|---|
| `{domain}#search` | Query the crawled corpus. |
| `{domain}#submit` | Announce a domain's existence for crawling. |

Because they are ordinary tools, they inherit everything from core + awp-sig:
signed manifests, sync transport, the error grammar. An agent that can call
any AWP tool can use any index — and cross-check several, since the schema
below is identical everywhere.

## 2. `#search`

### 2.1 Input

```json
{
  "query": "generate PDF invoices with Israeli VAT handling",
  "filters": {
    "kind": "tool",
    "domain": null,
    "state": null,
    "distribution": "hosted",
    "updated_after": "2026-01-01T00:00:00.000Z"
  },
  "expr": "kind = tool and (distribution = hosted or distribution = both)",
  "limit": 10,
  "cursor": null
}
```

| Field | Rules |
|---|---|
| `query` | REQUIRED. Free-text capability need in natural language — the corpus is natural-language `description` fields, so the query language is natural language. |
| `filters` | OPTIONAL structured shorthand. Every field optional; absent = unrestricted. |
| `expr` | OPTIONAL filter expression (§2.2). |
| `limit` | OPTIONAL, default 10, max 50. |
| `cursor` | OPTIONAL opaque pagination token from a prior result. Offset pagination is forbidden — corpora shift under recrawls. |

Combination semantics: `semantic(query) ∧ filters ∧ expr`. `filters` is
defined as sugar: it compiles to an `expr` conjunction, and when both are
present they are ANDed. Indexes implement one engine, not two.

### 2.2 Filter expression DSL

Minimal by design — comparisons, boolean composition, nothing else:

```abnf
expr    = or
or      = and *( "or" and )
and     = not *( "and" not )
not     = [ "not" ] ( comp / "(" expr ")" )
comp    = field op value
field   = "kind" / "domain" / "state" / "distribution" / "updated"
op      = "=" / "!=" / "~" / ">=" / "<="        ; "~" = substring, domain only
value   = token / dquoted / rfc3339
```

- `>=` / `<=` apply to `updated` only; `~` to `domain` only (suffix matching:
  `domain ~ "acme.com"` matches subdomains).
- `kind`, `state`, `distribution` values come from the core spec enums.
- No free-text fields in the DSL — semantic matching belongs to `query`; the
  DSL filters facts. Indexes MUST reject expressions outside this grammar
  with `error(unsupported_body)` semantics (`400`, core §2.6 body).
- Depth cap: 8 nested groups; length cap: 1024 bytes.

### 2.3 Output

```json
{
  "results": [
    {
      "principal": "invoicer.example.com#generate",
      "kind": "tool",
      "description": "verbatim from the manifest, never rewritten",
      "score": 0.92,
      "crawled_at": "2026-07-20T04:11:00.000Z",
      "last_verified": "2026-07-20T04:11:00.000Z"
    }
  ],
  "cursor": "opaque-or-null"
}
```

| Field | Rules |
|---|---|
| `principal` | Resolvable name. **Results are pointers, not truth** — callers MUST resolve and verify against the target's own domain index before use (core §3). |
| `description` | Verbatim from the signed manifest. Indexes MUST NOT rewrite, summarize, or augment it — a modified description breaks the attribution chain to the publishing domain. |
| `score` | Opaque relevance/quality scalar in [0,1]. The ONLY place opinion is allowed (§4). |
| `crawled_at` | When the serving snapshot of this entity was fetched. |
| `last_verified` | When the entity's signature chain last verified. The staleness-honesty mechanism: an index MUST disclose how old its view is. |

## 3. `#submit`

```json
// input
{ "domain": "newcomer.dev" }
// output
{ "accepted": true, "note": "queued for crawl" }
```

The entire schema. You can submit **existence, never claims** — the index
crawls the domain's own signed documents and believes only those. Solves the
zero-peer-edges bootstrap for new domains. `accepted: true` promises a crawl
attempt, not inclusion: a domain whose index fails verification is dropped
(core §3 crawler conduct). Indexes SHOULD dedupe submissions and MAY
rate-limit them aggressively.

## 4. Ranking claims — the honesty rule

Two categories, hard boundary:

1. **Verifiable facts** MAY be returned as named fields: `crawled_at`,
   `last_verified`, and (if an index extends the result schema) signature
   validity, observed uptime, peer in-degree, domain age. Every named field
   MUST be independently checkable by the caller in principle.
2. **Everything else** — quality judgments, popularity heuristics, semantic
   relevance — collapses into the opaque `score`. An index MUST NOT present
   opinion as fact: no `"trusted": true`, no `"recommended": true`, no
   `"safe": true`, ever.

Ranking formulas are proprietary; that is the competitive surface. The
Sybil constraints of core §4 apply: peer in-degree is a weak signal, weighted
by asserting-domain credibility, never used raw as primary ranking.

## 5. Authentication and rate limiting

Queries and submissions are ordinary sync calls, so signing per `awp-sig` is
available for free. Whether an index **requires** it is index policy:

- Anonymous (unsigned) queries are permitted by this spec; an index that
  accepts them SHOULD rate-limit by network origin.
- Signed callers are identifiable per domain; indexes SHOULD offer them
  higher limits — the incentive that moves traffic to signed without
  mandating it.
- The request/response schema is identical in both modes. An index that
  requires signing rejects unsigned calls with `401` per awp-sig; nothing
  else changes.

## 6. Conformance (v0.1 index)

1. Publishes `#search` and `#submit` with manifests conforming to §2/§3
   schemas (`io` fields MUST match).
2. Serves descriptions verbatim from signed manifests.
3. Populates `crawled_at` and `last_verified` truthfully.
4. Emits no opinion-as-fact fields (§4).
5. Implements cursor pagination; rejects offset-style abuse.
6. Follows core §3 crawler conduct: verify-before-serve, honor
   `crawl: false`, no fabricated edges.
7. Rejects out-of-grammar `expr` with the core §2.6 error body.

## 7. Deferred to v0.2

Index-to-index corpus exchange (common-crawl equivalent) · reputation
attestations (signed third-party vouching) · personalized ranking ·
subscription/push discovery ("notify me when a matching entity appears").
