# Schema 1.1 verification

Protocol baseline: Groundmark/groundmark b9a879ac8e9d1354a41daf4177e7fb7f886389a5.

Use `verifyPresentedRequest11(rawRequest, context)` for a signed HTTP request
presenting one Groundmark claim. It authenticates the RFC 9421 request, resolves
the DNSSEC claim reference, binds the attestation to the exact authenticated
request key, verifies purpose-separated issuer/status signatures and freshness,
applies installed profile and issuer authorization, then commits the nonce.
Failures throw `Verification11Error` with a stable `reason`.

`verifyAttestation11(context)` is the lower-level seam. Its requestKey must come
from authenticated request verification, never the fetched attestation itself.
Neither API falls back to legacy schema 1.0.

Callers must supply:

- A DNSSEC-validating resolver and an HTTPS fetcher enforcing TLS, no redirects,
  no credentials, bounded reads/timeouts and SSRF controls. Do not log bearer URLs.
- Claim-profile validation and explicit issuer/key authorization for both signing
  purposes. DNSSEC discovery alone is not authorization.
- Atomic durable StatusHistory keyed by authenticated issuer plus immutable ID,
  preserving sequence/digest/terminal state across restarts and key rotation.
  MemoryStatusHistory is only for tests or a single session.
- A durable nonce store and request target/time policy via requestOptions.

The included engine vectors contain simulated method evidence and public test
keys. They prove interoperability in offline tests, not deployment conformance
or real identity verification. Production transport/storage adapters and live
cold verification remain deployment work.

Validation: Node 24, `node --test 'poc/lib/test/**/*.test.ts'` (92 passing tests),
and `npm --prefix poc/lib run typecheck`.
