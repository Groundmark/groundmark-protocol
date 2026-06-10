# Groundmark verification library (`poc/lib`)

Relying-party verifier for the Groundmark protocol. Given an HTTP request from an
agent, it verifies the request per the **core draft** (Level 0) and — as later
components land — evaluates attestations per the **companion draft**.

The two Internet-Drafts in the repo root are the spec of record. Where this code
and a draft disagree, the draft wins.

## Runtime

TypeScript on **Node ≥ 24**, run directly via Node's native type-stripping — no
build step. Tests use the built-in `node:test` runner.

```sh
npm test            # runs node --test over test/**/*.test.ts
```

There are **no runtime dependencies** for the Level 0 core (`node:crypto`
provides Ed25519). Future components will add a real RFC 8785 (JCS) library for
attestation canonicalization; each dependency is justified in the PR.

## Component map (instruction §3)

| # | Component | Status | Source |
|---|-----------|--------|--------|
| 1 | RFC 9421 parser + signature base | ✅ | `src/rfc9421/{parse,message,signatureBase,contentDigest}.ts` |
| 2 | DNSSEC-validating resolver | ⏸ **interface + mock only** — concrete validating client pending the resolver-approach decision (instruction §2) and a real demo domain | `src/dns/{resolver,mockResolver}.ts` |
| 3 | Agent key resolver | ✅ | `src/agent/keyResolver.ts` |
| 4 | Request-signature verifier | ✅ | `src/verifyRequest.ts` |
| 5 | Claim resolver | ⬜ not started | — |
| 6 | Attestation validator | ⬜ not started | — |
| 7 | IDSP key resolver + attestation-signature verifier | ⬜ not started | — |
| 8 | Revocation + caching engine | ⬜ not started | — |
| 9 | Policy + verdict layer | ⬜ not started | — |

Components 1–4 are the self-standing **Level 0** core: they establish that a
request came from a party controlling the agent domain's DNSSEC-protected key,
and nothing more.

## The resolver seam

Every DNS read goes through `DnssecResolver`. Only a DNSSEC-validated (`secure`)
answer is usable; `insecure`/`bogus`/`indeterminate`/`error` are rejected (core
§7.1). `MockDnssecResolver` backs the offline test suite and exercises the
unsigned-zone case. A production validating client implements the same interface.

## Hygiene

- No private keys are committed. Tests that need key material generate ephemeral
  keys at test time.
- `ref=` URLs are treated as confidential and are never logged (enforced as the
  attestation layer lands).
