/**
 * Component 8 (part 1) — claim-layer revocation with level-scaled fail-mode
 * (attestation draft §8, §8.1, §8.2).
 *
 * Outcomes:
 *   - revocation says revoked            -> claim_revoked (reject)
 *   - revocation says not revoked        -> accept
 *   - revocation endpoint unavailable    -> fail-mode by level:
 *       L3: fail closed (revocation_unavailable_fail_closed)
 *       L2: fail closed UNLESS issued <24h ago AND policy permits soft-fail
 *           (then fail open, logged)
 *       L1 (and below): MAY fail open, logged (§8.2 logging is MANDATORY)
 *
 * Hygiene (§7): fail-open audit entries reference the endpoint by ORIGIN + a
 * SHA-256 hash of the URL, never the full `ref=`/endpoint bearer URL.
 */

import { createHash } from "node:crypto";
import type { HttpsFetcher } from "../attestation/fetcher.ts";
import { FetchUnavailable } from "../attestation/fetcher.ts";
import { VerificationError } from "../errors.ts";

export interface RevocationPolicy {
  /** Whether L2 soft-fail is permitted for this transaction's risk profile. */
  allowLevel2SoftFail?: boolean;
}

/** Fail-open audit record. endpoint_url is redacted (§7); §8.2 required fields. */
export interface FailOpenAuditEntry {
  agentDomain: string;
  /** Origin (scheme://host[:port]) of the attestation endpoint — redacted form. */
  endpointOrigin: string;
  /** SHA-256 (hex) of the full endpoint_url — identifies it without exposing it. */
  endpointUrlSha256: string;
  idsp: string;
  claimType: string;
  level: number;
  reason: string;
  /** Time of decision (UNIX seconds). */
  decidedAt: number;
  /** Identity of the transaction/operation that proceeded under fail-open. */
  transactionId: string;
}

export interface AuditLogger {
  failOpen(entry: FailOpenAuditEntry): void;
}

export interface RevocationCheckInput {
  fetcher: HttpsFetcher;
  revocationEndpoint: string;
  endpointUrl: string;
  agentDomain: string;
  idsp: string;
  claimType: string;
  level: number;
  /** issued_at in UNIX seconds (for the L2 <24h soft-fail condition). */
  issuedAtSeconds: number;
  now: number;
  policy: RevocationPolicy;
  logger: AuditLogger;
  transactionId: string;
}

export interface RevocationCheckResult {
  /** True when the endpoint was unreachable and we accepted under fail-open. */
  failedOpen: boolean;
}

function redactOrigin(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "about:invalid";
  }
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/** Fetch the revocation status; null means "could not determine" (unavailable). */
async function fetchRevoked(fetcher: HttpsFetcher, url: string): Promise<boolean | null> {
  let res;
  try {
    res = await fetcher.get(url);
  } catch (e) {
    if (e instanceof FetchUnavailable) return null;
    throw e;
  }
  if (res.status < 200 || res.status >= 300) return null;
  try {
    const obj = JSON.parse(res.body.toString("utf8")) as unknown;
    if (typeof obj === "object" && obj !== null && typeof (obj as { revoked?: unknown }).revoked === "boolean") {
      return (obj as { revoked: boolean }).revoked;
    }
  } catch {
    /* fallthrough */
  }
  return null; // malformed response — treat as unavailable
}

export async function checkRevocation(input: RevocationCheckInput): Promise<RevocationCheckResult> {
  const revoked = await fetchRevoked(input.fetcher, input.revocationEndpoint);

  if (revoked === true) {
    throw new VerificationError(
      "claim_revoked",
      `claim ${input.claimType} for ${input.agentDomain} is revoked`,
    );
  }
  if (revoked === false) {
    return { failedOpen: false };
  }

  // Unavailable -> apply level-scaled fail-mode (§8.1).
  const reason = "revocation endpoint unavailable";
  const within24h = input.now - input.issuedAtSeconds < 24 * 60 * 60;

  let mayFailOpen: boolean;
  if (input.level >= 3) {
    mayFailOpen = false;
  } else if (input.level === 2) {
    mayFailOpen = Boolean(input.policy.allowLevel2SoftFail) && within24h;
  } else {
    mayFailOpen = true; // Level 1 and below
  }

  if (!mayFailOpen) {
    throw new VerificationError(
      "revocation_unavailable_fail_closed",
      `revocation unavailable; failing closed at level ${input.level}`,
    );
  }

  // Fail open — logging is MANDATORY (§8.2).
  input.logger.failOpen({
    agentDomain: input.agentDomain,
    endpointOrigin: redactOrigin(input.endpointUrl),
    endpointUrlSha256: sha256Hex(input.endpointUrl),
    idsp: input.idsp,
    claimType: input.claimType,
    level: input.level,
    reason,
    decidedAt: input.now,
    transactionId: input.transactionId,
  });
  return { failedOpen: true };
}
