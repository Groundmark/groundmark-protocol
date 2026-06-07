# Groundmark Level 1 PoC — fixtures

This directory is the **runtime-agnostic substrate** for the registry-as-IDSP, Level 1
("operator accountability") proof of concept: keys, DNS record values, signed
attestation JSON, revocation responses, and a graded fixture corpus — i.e. **the world
the verification library will run against**.

It deliberately does **not** contain the verification library, a relying-party harness,
or any dynamic service. The library's runtime is undecided (waiting on Mark);
`lib/` is intentionally left unscaffolded. The generator here (`tools/generate.py`,
Python + `cryptography`) is **incidental tooling** and implies nothing about the
library's eventual language.

## Authoritative sources

The two Internet-Drafts in the repo root are the source of truth. Where this PoC and a
draft disagree, **the draft wins**:

- `draft-noss-jeftovic-groundmark-core-00.md` — DNS record wire formats (§4),
  request authentication via RFC 9421 (§5). Worked example §3.1.
- `draft-noss-jeftovic-groundmark-attestation-00.md` — attestation JSON schema (§6),
  claim vocabulary (§5), signature construction (§7). Worked example §6.4.

## Regenerate

One command, from this directory:

```sh
python3 tools/generate.py
```

It reuses existing private keys (so committed public keys — and every signature derived
from them — stay stable) and uses fixed timestamps and `ref=` tokens, so re-running
produces **byte-identical** output. Requires `python3` with the `cryptography` package.

## Layout

```
config.json            AGENT_DOMAIN / IDSP_DOMAIN / ISSUER_BASE_URL (placeholders)
tools/generate.py      reproducible generator (tooling, NOT the library)
keys/                  *.pub.b64url committed; *.private.pem gitignored, never committed
dns/                   TXT record values ready to publish (committed)
attestations/          good signed attestations + matching revocation responses
fixtures/good/         the good cases (verify clean)
fixtures/adversarial/  minimal single-fault mutations (see fixtures/README.md)
fixtures/request/      RFC 9421 signed-request vector
lib/                   intentionally absent — runtime undecided
```

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

1. **Custom claim-type ABNF conflict.** The attestation draft (§5) writes custom claim
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
