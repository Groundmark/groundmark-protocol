# Groundmark Level 1 PoC — fixtures

This directory is the **runtime-agnostic substrate** for the registry-as-IDSP, Level 1
("operator accountability") proof of concept: keys, DNS record values, signed
attestation JSON, revocation responses, and a graded fixture corpus — i.e. **the world
the verification library will run against**.

The relying-party **verification library now lives in `lib/`** (TypeScript / Node ≥ 24,
run via native type-stripping; tests with `node:test`). It verifies a request against
the core draft (Level 0) and evaluates attestations against the companion draft, and it
includes the **`Groundmark-Claim` presentation binding** (`lib/src/presentation/`). The
generator here (`tools/generate.py`, Python + `cryptography`) is **incidental tooling**
that builds the runtime-agnostic fixture corpus; its language implies nothing about the
library's runtime.

## Authoritative sources

**The protocol is [`spec/groundmark-protocol.md`](../spec/groundmark-protocol.md).** Where this PoC
and the spec disagree, **the spec wins**.

This PoC predates the spec's port onto W3C DID/VC (16 November 2026) and implements the
**retired** model: schema 1.0 JSON attestations signed with Ed25519 over JCS, open
`_agentclaim` references, and a revocation endpoint. Its Level 0 path (RFC 9421 request
signing, `_agentid` key resolution, DNSSEC resolver seam, nonce handling) matches the spec
(§4.1, §4.3, §5). The credential path (`_idsp` host check, SD-JWT credentials, `did:web`
cross-check, Token Status List) is not yet ported; see spec §18 for the legacy window.

For the section references below, the submitted -00 drafts in the repo root describe the
model this PoC was built to:

- `draft-noss-jeftovic-groundmark-core-00.md`: DNS record wire formats (§4),
  request authentication via RFC 9421 (§5). Worked example §3.1.
- `draft-noss-jeftovic-groundmark-attestation-00.md`: attestation JSON schema (§6),
  claim vocabulary (§5), signature construction (§7). Worked example §6.4.

## Run and verify vs. regenerate

A **fresh clone can run and verify** the committed fixtures with no extra setup —
`cd lib && npm test` exercises the whole corpus (the committed public keys and
signatures are all that verification needs).

A fresh clone **cannot regenerate byte-identical signatures**, because the signing
private keys are **gitignored and never committed** (`keys/*.private.pem`). Without the
original keys, regeneration could only produce a *different* corpus signed by new keys.

To prevent that from happening silently, the generator **fails safely**: if a required
private key is absent it **aborts** rather than minting new keys and replacing the
committed corpus.

```sh
python3 tools/generate.py            # reuses existing private keys -> byte-identical;
                                     # ABORTS if a private key is absent
python3 tools/generate.py --rotate-keys   # explicitly authorize a fixture-key rotation
                                          # (generates new keys; replaces the corpus)
```

With the original keys present, regeneration reuses them and — together with fixed
timestamps, a fixed nonce, and deterministic `ref=` tokens — produces **byte-identical**
output. Requires `python3` with the `cryptography` package.

## Layout

```
config.json            AGENT_DOMAIN / IDSP_DOMAIN / ISSUER_BASE_URL (placeholders)
tools/generate.py      reproducible generator (tooling, NOT the library)
keys/                  *.pub.b64url committed; *.private.pem gitignored, never committed
dns/                   TXT record values ready to publish (committed)
attestations/          good signed attestations + matching revocation responses
fixtures/good/         the good cases (verify clean)
fixtures/adversarial/  minimal single-fault mutations (see fixtures/README.md)
fixtures/request/      RFC 9421 signed-request vector (Level 0 request auth)
fixtures/presentation/ composite presentation vector + single-fault variants (see fixtures/README.md)
lib/                   the relying-party verification library (TypeScript / Node)
```

## The presentation fixtures (`fixtures/presentation/`)

A **presentation** is the holder agent's output: a Level 0 RFC 9421 request that also
carries a signature-bound `Groundmark-Claim` header, binding a specific attestation to a
specific request. `presentation.http` (+ `signature-base.txt`) is the good case; it
covers `@method @authority @target-uri content-digest groundmark-claim` and carries a
`nonce` parameter. The single-fault variants each isolate one binding/replay check
(missing header, header not signature-covered, missing nonce, claim_type∉DNS,
ref≠endpoint_url, nonce replay). The verifier also rejects cryptographically valid
attestations whose signed `claim_type` or `idsp` disagrees with the DNS `_agentclaim`
record, before revocation or policy evaluation. `presentation-canadian-presence.http` is
a second valid presentation (asserting the Canadian-presence claim) used to prove that
presenting a different claim cannot satisfy a policy that requires a specific claim type.

## What the good case demonstrates

The headline "operator-verified + Canadian presence" is **two independent stacked
claims** (attestation draft §4.5), both Level 1, both signed by the stand-in IDSP key
(the placeholder for the registry IDSP's signing key):

1. `operator-verified` — an identifiable operator is accountable for the agent.
2. `x-registry-example-canadian-presence` — a custom claim asserting Canadian presence.

A relying party verifies each cold: DNSSEC-retrieve the IDSP key at
`_agentid.<IDSP_DOMAIN>` (selecting `kid=k1`), confirm `endpoint_url` == the `ref=` URL,
confirm `level` ≥ policy floor and `expires_at` in the future, verify the Ed25519
signature, then check the revocation endpoint.

## Cryptographic details worth knowing

- **Keys**: Ed25519. The `p=` value in each `_agentid` record is the base64url
  (no-padding, RFC 4648) encoding of the raw 32-byte public key.
- **Attestation signature** (attestation draft §7): Ed25519 over the **JCS-canonical
  (RFC 8785)** serialization of the payload with the `signature` field removed,
  base64url-encoded. `endpoint_url` is inside the signed payload (binds against
  portability attacks, §9.1).
- **JCS shortcut**: `generate.py` approximates JCS with
  `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. This is
  exactly equivalent to RFC 8785 **only because** these payloads use ASCII keys and
  contain only strings, booleans, and small integers — **no floats, no non-ASCII**. The
  **production verification library MUST use a real RFC 8785 implementation.**
- **`ref=` tokens**: 128-bit, but **derived deterministically** from public inputs here
  so committed fixtures stay byte-stable. **Production MUST use a CSPRNG** (≥128 bits;
  core draft §4.2.2, §7.4).
- **Two base64 variants**: attestation `signature` and `p=` are base64url (no padding);
  the RFC 9421 `Signature` and `Content-Digest` values are standard base64 (sf-binary).

## Open spec items to confirm (drafts disagree with each other / with the registry)

1. **Custom claim-type ABNF conflict** (closed by the spec, §14.1: custom types are now type URIs). The attestation draft (§5) writes custom claim
   types as `x-<registrant-domain>-<claim-name>` (implying dots, e.g. `registry.example`), but the
   core draft's `x-token` ABNF permits only letters/digits/hyphens — **no dots**. This PoC
   uses `x-registry-example-canadian-presence` (dots → hyphens). Elliot/Mark need to reconcile the
   two drafts (either relax the core ABNF or change the §5 construction rule).
2. **Method identifiers not yet registered.** The Groundmark Method Identifier registry is
   reserved for later population (attestation draft §12.2). The `operator-verified` methods
   (`corporate-registry-lookup`, `organizational-domain-email-confirmation`) match the
   draft worked example, but the Canadian-presence methods (`self-asserted-presence`,
   `postal-address-verified`) and the evidence class `postal-address` are **honest
   placeholders** pending the registry.
