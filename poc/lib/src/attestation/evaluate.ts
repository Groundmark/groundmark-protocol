/**
 * Component 9 — policy + verdict layer for the attestation pipeline.
 *
 * Orchestrates, per agent domain: resolve _agentclaim records (C5) -> for each
 * ref-form claim fetch the attestation -> validate + verify signature (C6/C7) ->
 * revocation check (C8). Produces a structured verdict that SURFACES each
 * attestation's method_disclosure rather than collapsing to accept/reject
 * (instruction §3 C9), so the relying party can make a contextual trust decision.
 *
 * Hygiene (§7): verdicts reference claims by claim_type only — never the ref= URL.
 */

import type { DnssecResolver } from "../dns/resolver.ts";
import type { HttpsFetcher } from "./fetcher.ts";
import { FetchUnavailable } from "./fetcher.ts";
import { resolveClaims } from "../claim/resolveClaims.ts";
import { parseAttestation, type MethodDisclosure } from "./payload.ts";
import { verifyAttestation } from "./verify.ts";
import { checkRevocation, type AuditLogger, type RevocationPolicy } from "../revocation/revocation.ts";
import { VerificationError, type VerifyFailureReason } from "../errors.ts";

export interface AttestationPolicy {
  /** Minimum attestation level the relying party requires. */
  levelFloor: number;
  /** Claim types that MUST be present and verified at/above the floor. */
  requiredClaimTypes?: string[];
  /** Whether L2 revocation soft-fail is permitted (passed through to C8). */
  allowLevel2SoftFail?: boolean;
}

export interface EvaluateOptions {
  resolver: DnssecResolver;
  fetcher: HttpsFetcher;
  now: number;
  policy: AttestationPolicy;
  logger: AuditLogger;
  /** Identifies the operation for fail-open audit logging (§8.2). */
  transactionId: string;
}

export interface ClaimVerdict {
  claimType: string;
  ok: boolean;
  level?: number;
  idsp?: string;
  /** Surfaced verbatim so the relying party can weigh the IDSP's disclosure. */
  methodDisclosure?: MethodDisclosure;
  /** True for self-asserted val-form claims (Level 0, unverified). */
  selfAsserted?: boolean;
  /** True when accepted under revocation fail-open (audit-logged). */
  failedOpen?: boolean;
  reason?: VerifyFailureReason;
  detail?: string;
}

export interface AttestationVerdict {
  agentDomain: string;
  claims: ClaimVerdict[];
  /** All requiredClaimTypes present and verified at/above the floor. */
  policySatisfied: boolean;
  /** Required claim types not satisfied (empty when policy is satisfied). */
  missingClaims: string[];
}

export async function evaluateAttestations(
  agentDomain: string,
  opts: EvaluateOptions,
): Promise<AttestationVerdict> {
  const records = await resolveClaims(opts.resolver, agentDomain);
  const claims: ClaimVerdict[] = [];

  for (const record of records) {
    if (record.kind === "val") {
      // Self-asserted Level 0 disclosure (attestation draft §4.1, §5.6).
      claims.push({ claimType: record.claimType, ok: true, level: 0, selfAsserted: true });
      continue;
    }

    // exp= DNS hint: MUST NOT use a claim whose exp has passed (core §4.2.2).
    if (record.exp !== undefined) {
      const expMs = Date.parse(record.exp);
      if (!Number.isNaN(expMs) && Math.floor(expMs / 1000) <= opts.now) {
        claims.push({ claimType: record.claimType, ok: false, reason: "claim_exp_passed" });
        continue;
      }
    }

    claims.push(await evaluateRefClaim(record.claimType, record.ref, record.idsp, agentDomain, opts));
  }

  const missingClaims: string[] = [];
  for (const required of opts.policy.requiredClaimTypes ?? []) {
    const ok = claims.some(
      (c) => c.claimType === required && c.ok && !c.selfAsserted && (c.level ?? -1) >= opts.policy.levelFloor,
    );
    if (!ok) missingClaims.push(required);
  }

  return { agentDomain, claims, policySatisfied: missingClaims.length === 0, missingClaims };
}

async function evaluateRefClaim(
  claimType: string,
  ref: string,
  idsp: string,
  agentDomain: string,
  opts: EvaluateOptions,
): Promise<ClaimVerdict> {
  // Fetch the attestation. Errors reference the claim type, never the URL (§7).
  let body: Buffer;
  try {
    const res = await opts.fetcher.get(ref);
    if (res.status < 200 || res.status >= 300) {
      return { claimType, ok: false, reason: "attestation_fetch_failed", detail: `HTTP ${res.status}` };
    }
    body = res.body;
  } catch (e) {
    if (e instanceof FetchUnavailable) {
      return { claimType, ok: false, reason: "attestation_fetch_failed", detail: "endpoint unreachable" };
    }
    throw e;
  }

  // Validate + verify signature (C6/C7).
  let payload;
  try {
    const parsed = parseAttestation(body);
    payload = await verifyAttestation(parsed, {
      agentDomain,
      refUrl: ref,
      now: opts.now,
      levelFloor: opts.policy.levelFloor,
      resolver: opts.resolver,
    });
  } catch (e) {
    if (e instanceof VerificationError) {
      return { claimType, ok: false, reason: e.reason, detail: e.message };
    }
    throw e;
  }

  // Revocation (C8).
  const issuedAtSeconds = Math.floor(Date.parse(payload.issued_at) / 1000);
  const revPolicy: RevocationPolicy = {};
  if (opts.policy.allowLevel2SoftFail !== undefined) {
    revPolicy.allowLevel2SoftFail = opts.policy.allowLevel2SoftFail;
  }
  try {
    const rev = await checkRevocation({
      fetcher: opts.fetcher,
      revocationEndpoint: payload.revocation_endpoint,
      endpointUrl: payload.endpoint_url,
      agentDomain,
      idsp: payload.idsp,
      claimType: payload.claim_type,
      level: payload.level,
      issuedAtSeconds,
      now: opts.now,
      policy: revPolicy,
      logger: opts.logger,
      transactionId: opts.transactionId,
    });
    return {
      claimType,
      ok: true,
      level: payload.level,
      idsp: payload.idsp,
      methodDisclosure: payload.method_disclosure,
      failedOpen: rev.failedOpen,
    };
  } catch (e) {
    if (e instanceof VerificationError) {
      return { claimType, ok: false, level: payload.level, idsp: payload.idsp, reason: e.reason, detail: e.message };
    }
    throw e;
  }
}
