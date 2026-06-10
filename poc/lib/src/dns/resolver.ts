/**
 * Component 2 — DNSSEC-validating resolver, the swappable seam.
 *
 * This module defines ONLY the interface and result contract. The concrete
 * validating client (validating recursive resolver + authenticated transport,
 * or an in-process validating library) is a pending decision (instruction §2)
 * and is also gated on a real demo domain for live testing. Every DNS read in
 * the library MUST go through a DnssecResolver so the implementation can be
 * swapped without touching the verification logic.
 *
 * Core draft §7.1 is the contract: a lookup is usable ONLY when the answer is
 * DNSSEC-validated ("secure"). The implementation MUST treat each of the
 * following as a fatal failure (NOT a usable answer):
 *   - SERVFAIL from a validating resolver,
 *   - an explicit AD=0 response from a recursive resolver relied on for
 *     validation (an "insecure"/unsigned zone),
 *   - any condition where a validated answer cannot be confirmed.
 *
 * The verification layers translate a non-"secure" status into the appropriate
 * rejection: an invalid identity for `_agentid` (§4.1.2), or an absent record
 * for `_agentclaim` (§4.2.2).
 */

/** DNSSEC security status, mirroring RFC 4035 / common validator semantics. */
export type DnssecStatus =
  | "secure" // validated chain of trust; AD set; the only usable status
  | "insecure" // provably unsigned (no chain of trust) — MUST be rejected
  | "bogus" // signatures present but validation failed — MUST be rejected
  | "indeterminate" // cannot determine security state — MUST be rejected
  | "error"; // transport/SERVFAIL/other failure — MUST be rejected

export interface TxtRecordSet {
  status: "secure";
  /**
   * One entry per TXT RR at the name. Each entry is the RR's character-strings
   * concatenated (RFC 1035 §3.3.14) — i.e. a single logical record value such
   * as `v=gm1; k=ed25519; p=...`. Surrounding quotes are NOT included.
   */
  records: string[];
  /** Lowest TTL (seconds) observed across the answer; the cache ceiling. */
  ttl: number;
}

export interface TxtResolutionFailure {
  status: Exclude<DnssecStatus, "secure">;
  detail: string;
}

export type TxtResolution = TxtRecordSet | TxtResolutionFailure;

export interface DnssecResolver {
  /**
   * Resolve TXT records at `name` through a DNSSEC-validating path.
   * Returns a "secure" record set (possibly empty `records` for validated
   * NODATA) or a failure status. MUST NOT return "secure" for an answer whose
   * DNSSEC chain was not validated end-to-end.
   */
  resolveTxt(name: string): Promise<TxtResolution>;
}

/** Type guard: a usable, DNSSEC-validated answer. */
export function isSecure(r: TxtResolution): r is TxtRecordSet {
  return r.status === "secure";
}
