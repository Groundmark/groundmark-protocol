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

## Status: implemented (`src/dns/loopbackResolver.ts`)

`LoopbackDnssecResolver` is the concrete client. Node's built-in `dns` module
does not expose the `AD` flag, so it speaks DNS wire format itself (a TXT query
with `RD`, `AD` and EDNS0 `DO`), with these choices on top of the contract above:

- **TCP only** (RFC 7766 framing), not UDP: on a shared host any local process
  that guesses the source port and ID could forge a UDP reply, and `AD` in a
  forged reply means nothing. Each answer must echo the query's ID and question
  (name, type, class), and only TXT records owned by the asked name count. Names
  are compared label by label. A truncated (TC) or non-query (opcode) response,
  a declared section that isn't there, or bytes after the last record make the
  answer an `error`, whatever its AD bit says.
- **Loopback only** unless the caller passes `allowNonLoopback` for a path that
  is otherwise authenticated.
- `SERVFAIL` maps to `bogus`; any other failing rcode, a timeout, or a
  malformed or mismatched answer maps to `error`. A validated NXDOMAIN or NODATA
  is `secure` with no records (TTL 0, so nothing is cached).

The offline suite exercises it against a fake DNS-over-TCP server on loopback
(`test/loopbackResolver.test.ts`). The live path runs with
`GM_LIVE_DNS=_agentid.<a signed agent domain> node --test test/loopbackResolver.test.ts`
on a machine with a validating resolver on 127.0.0.1; it has been run against
Unbound for a real, DNSSEC-signed agent domain. `MockDnssecResolver` still backs
the rest of the offline suite.
