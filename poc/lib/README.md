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
| 2 | DNSSEC-validating resolver | ⏸ **interface + mock**; concrete local-AD client gated on a real demo domain (decision recorded in `docs/dnssec-resolver.md`) | `src/dns/{resolver,mockResolver,agentidRecord}.ts` |
| 3 | Agent key resolver | ✅ | `src/agent/keyResolver.ts` |
| 4 | Request-signature verifier | ✅ | `src/verifyRequest.ts` |
| 5 | Claim resolver | ✅ | `src/claim/{parseAgentClaim,resolveClaims}.ts` |
| 6 | Attestation validator | ✅ | `src/attestation/{payload,canonical,verify}.ts` |
| 7 | IDSP key resolver + attestation-signature verifier | ✅ | `src/idsp/idspKeyResolver.ts`, `src/attestation/verify.ts` |
| 8 | Revocation + caching engine | ✅ | `src/revocation/revocation.ts`, `src/cache/ttl.ts` |
| 9 | Policy + verdict layer | ✅ | `src/attestation/evaluate.ts`, `src/verify.ts` |
| 10 | Groundmark-Claim presentation binding + atomic nonce finalization | ✅ | `src/presentation/groundmarkClaim.ts`, `src/verifyRequest.ts`, `src/verify.ts` |

Components 1–4 are the self-standing **Level 0** core: they establish that a
request came from a party controlling the agent domain's DNSSEC-protected key,
and nothing more. Components 5–9 add the optional attestation layer; the
top-level `verifyAgentRequest` ties them together under a relying-party policy.
Presentation-profile verification additionally requires a signature-covered
`Groundmark-Claim` header, binds DNS `claim=`/`idsp=`/`ref=` to the signed attestation
payload, and commits a nonce with `NonceStore.consumeOnce(nonce, expiresAt)` only after
the full composite verdict is acceptable.

`IssuedNonceStore` (`src/nonce/issuedNonceStore.ts`) is a `NonceStore` that accepts
only nonces this relying party issued: `issue()` makes one for the `Accept-Signature`
challenge (lifetime at most 300 s), and `consumeOnce` accepts it once, unexpired. A
store that only checks "not seen before" would also accept a nonce the agent made up.

## Dependencies

- `canonicalize` — RFC 8785 (JCS) canonicalization for attestation signatures.
  Required because §5 forbids hand-rolling canonicalization; the generator's
  `sort_keys` shortcut is only valid for ASCII-keyed, float-free payloads.

Ed25519, SHA-256, and HTTP come from `node:crypto` / the platform — no other
runtime dependencies.

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
