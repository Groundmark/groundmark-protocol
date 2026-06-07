# Groundmark PoC fixture corpus

The conformance target the verification library is graded against. Every adversarial
case is a **minimal mutation** of a good attestation, so a failure isolates exactly
one cause. The good cases are the Level 1 "operator-verified + Canadian presence"
headline as two independent stacked claims (attestation draft §4.5).

Regenerate everything with `python3 tools/generate.py` from `poc/`.

## `good/`

| File | What it is |
| --- | --- |
| `operator-verified.json` | Level 1 `operator-verified` attestation, fully valid (attestation draft §6.4 template). |
| `x-registry-example-canadian-presence.json` | Level 1 custom-claim attestation asserting Canadian presence, fully valid. |

Both must pass verification: DNSSEC-retrieved IDSP key → signature valid → `endpoint_url`
equals the `ref=` it was served from → `level` ≥ policy floor → `expires_at` in the
future → revocation response `{"revoked": false}`.

## `adversarial/`

Each case proves a **single** verifier check. All are based on the good
`operator-verified` attestation.

| File | Single property it proves | How it differs from good |
| --- | --- | --- |
| `expired.json` | Verifier enforces `expires_at` (attestation draft §6.2, §7.1). | `expires_at` in the past; still correctly signed. |
| `wrong-subject.json` | Verifier binds the attestation to the agent domain it was retrieved for. | `subject` ≠ agent domain; **re-signed**, so only the binding is wrong. |
| `bad-signature.json` | Verifier checks the Ed25519 signature. | Valid payload; one signature byte flipped (not re-signed). |
| `endpoint-mismatch.json` | Verifier enforces `endpoint_url` == `ref=` (portability attack, attestation draft §9.1). | `endpoint_url` points elsewhere; **re-signed** so the signature itself is valid. Treat it as served from the good `operator-verified` `ref=` URL. |
| `revoked.json` (+ `revoked.revocation.json`) | Verifier consults the revocation endpoint. | Attestation is fully valid; the paired revocation response is `{"revoked": true}`. |
| `unknown-schema-version.json` | Verifier rejects unknown `schema_version` (attestation draft §6.2, §7.1 step 1). | `schema_version` = `"2.0"`; **re-signed**. |
| `below-policy-level.json` | Verifier enforces the policy level floor (attestation draft §4, §6.2). | `level` = 0 while the harness requires ≥ 1; **re-signed**. |

"Re-signed" means the mutation is inside the signed payload and the signature is
recomputed, so the case fails on the *intended* check rather than incidentally on the
signature. `bad-signature` is the sole exception — there the signature is the defect.

### `unsigned-zone` — DNS-config case (no JSON file)

DNSSEC is REQUIRED for all Groundmark lookups (core draft §7.1; attestation draft §7.1
step 5). This case cannot be expressed as a JSON fixture because it depends on the zone,
not the payload. It is captured here for the future zone-provisioning step:

> Serve the IDSP `_agentid` record from a **non-DNSSEC-signed** zone (or one that fails
> validation). A conformant verifier MUST refuse to use the retrieved IDSP public key and
> MUST treat the attestation as unverifiable — even though the attestation JSON itself is
> byte-identical to the good `operator-verified` case and its signature would verify if
> the key were trusted. The good fixtures assume a DNSSEC-validated retrieval of both the
> agent `_agentid` and the IDSP `_agentid`.

## `request/` — RFC 9421 signed-request vector (stretch)

Runtime-agnostic target for the future request-verification element. There is **no**
`Agent-Identity` header — request authentication is RFC 9421 (core draft §5).

| File | Contents |
| --- | --- |
| `signed-request.http` | A complete `POST` signed with the **agent** key. Covers `@method`, `@authority`, `@target-uri`, and `content-digest` (core draft §5.3); carries `Content-Digest` (RFC 9530), `Signature-Input`, and `Signature` (RFC 9421). |
| `signature-base.txt` | The exact RFC 9421 signature base the `Signature` was computed over (one line per covered component, `@signature-params` last). |

A verifier reconstructs the signature base from the covered components and verifies the
`Signature` against the agent public key in `_agentid.<AGENT_DOMAIN>`. Note the two
distinct base64 encodings: `p=` and attestation `signature` are **base64url, no padding**
(RFC 4648); the RFC 9421 `Signature` value and the `Content-Digest` are **standard
base64** (RFC 9530 sf-binary).
