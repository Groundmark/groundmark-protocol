# DNSSEC resolver — chosen approach

**Decision (10 Jun 2026): local validating resolver + trusted AD bit over loopback.**

Considered (instruction §2): (A) trusted validating resolver + AD-bit trust over
an authenticated channel, (B) in-process chain validation. We chose a specific
variant of (A): run a validating resolver (Unbound or Knot Resolver) on
**loopback** and trust the `AD` (Authenticated Data) bit in its responses.

Rationale: a mature validator performs the DNSSEC cryptography (lower risk than a
hand-built JS chain validator), the loopback channel makes the AD-trust boundary
effectively local rather than a third-party assumption, and the code stays small.
This is the pragmatic reading of core draft §7.1 for the PoC; the interface keeps
the door open to swap in option (B) for a strict end-to-end posture later.

## Implementation contract (`DnssecResolver`)

The concrete client MUST:

- Query the local validating resolver with DNSSEC OK (`DO`) set and require the
  `AD` bit in the response. Map results to the resolver contract:
  - `AD=1`, answer present → `{ status: "secure", records, ttl }`
  - `AD=1`, NODATA → `{ status: "secure", records: [] }`
  - `AD=0` / no AD → `status: "insecure"` (unsigned / not validated)
  - validation failure / `SERVFAIL` → `status: "bogus"` or `"error"`
  - unreachable / timeout → `status: "error"`
- Treat anything other than `status: "secure"` as fatal at the call sites
  (`_agentid` → invalid identity; `_agentclaim` → absent record).
- Only use a resolver address that is trusted and reachable over loopback (or an
  otherwise authenticated channel); never a plaintext path to an untrusted
  recursive resolver.

## Status: pending live domain

Node's built-in `dns` module does not expose the `AD` flag, so the concrete
client needs raw DNS (e.g. `node:dgram` + a DNS wire codec) against the local
resolver. That code is **only exercisable against live DNS**, and `config.json`
still holds placeholder domains — so per instruction §4 the live path is
integration-tested separately once a real demo domain exists. Until then the
offline suite runs entirely against `MockDnssecResolver`, which models this exact
contract (including forced `insecure`/`bogus` statuses for the unsigned-zone
case).
