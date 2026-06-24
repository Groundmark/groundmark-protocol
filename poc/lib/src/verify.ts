/**
 * Top-level Groundmark verification: Level 0 request authentication (C1–C4) plus
 * optional attestation evaluation (C5–C9) when the relying party's policy
 * requires more than Level 0.
 *
 * Mirrors the core draft's §5.5 step 7 hand-off: verify the request first; only
 * if policy demands attestations do we resolve and evaluate them.
 */

import type { DnssecResolver } from "./dns/resolver.ts";
import type { HttpsFetcher } from "./attestation/fetcher.ts";
import type { AuditLogger } from "./revocation/revocation.ts";
import {
  verifyRequest,
  type VerifyRequestOptions,
  type RequestVerdict,
} from "./verifyRequest.ts";
import {
  evaluateAttestations,
  type AttestationPolicy,
  type AttestationVerdict,
  type EvaluateOptions,
} from "./attestation/evaluate.ts";

export interface VerifyAgentRequestOptions extends VerifyRequestOptions {
  resolver: DnssecResolver;
  /** Attestation policy. Omit (or levelFloor 0 with no required claims) for Level 0 only. */
  policy?: AttestationPolicy;
  /** Required when the policy evaluates attestations. */
  fetcher?: HttpsFetcher;
  /** Required when the policy evaluates attestations (for fail-open audit logging). */
  logger?: AuditLogger;
  /** Identifies the operation for fail-open audit logging (§8.2). */
  transactionId?: string;
}

export interface GroundmarkVerdict {
  /** request ok AND (no attestation policy OR attestation policy satisfied). */
  ok: boolean;
  request: RequestVerdict;
  attestations?: AttestationVerdict;
}

function policyEvaluatesAttestations(p: AttestationPolicy | undefined): p is AttestationPolicy {
  if (!p) return false;
  return p.levelFloor > 0 || (p.requiredClaimTypes?.length ?? 0) > 0;
}

export async function verifyAgentRequest(
  raw: Buffer,
  opts: VerifyAgentRequestOptions,
): Promise<GroundmarkVerdict> {
  // Configuration check (fail at setup, not silently at runtime): the presentation
  // profile's binding spans the request layer (present/covered/parse) AND the
  // attestation layer (claim_type↔DNS, ref↔attestation, claim↔policy). It is never
  // acceptable to run only the request-layer half. So requiring a Groundmark-Claim
  // demands a policy that evaluates attestations, plus a fetcher and logger.
  if (opts.requireGroundmarkClaim) {
    if (!policyEvaluatesAttestations(opts.policy)) {
      throw new Error(
        "requireGroundmarkClaim demands an attestation policy that evaluates claims " +
          "(levelFloor > 0 or a non-empty requiredClaimTypes); otherwise the binding " +
          "would only be half-checked",
      );
    }
    if (!opts.fetcher || !opts.logger) {
      throw new Error("requireGroundmarkClaim demands both a fetcher and a logger");
    }
  }

  const reqOpts: VerifyRequestOptions = { now: opts.now };
  if (opts.maxClockSkewSeconds !== undefined) reqOpts.maxClockSkewSeconds = opts.maxClockSkewSeconds;
  if (opts.label !== undefined) reqOpts.label = opts.label;
  if (opts.requireNonce !== undefined) reqOpts.requireNonce = opts.requireNonce;
  if (opts.nonceStore !== undefined) reqOpts.nonceStore = opts.nonceStore;
  if (opts.scheme !== undefined) reqOpts.scheme = opts.scheme;
  if (opts.requireGroundmarkClaim !== undefined) reqOpts.requireGroundmarkClaim = opts.requireGroundmarkClaim;

  const request = await verifyRequest(raw, opts.resolver, reqOpts);
  if (!request.ok) return { ok: false, request };

  if (!policyEvaluatesAttestations(opts.policy)) {
    return { ok: true, request };
  }

  if (!opts.fetcher || !opts.logger) {
    throw new Error("attestation policy requires both a fetcher and a logger");
  }

  const evalOpts: EvaluateOptions = {
    resolver: opts.resolver,
    fetcher: opts.fetcher,
    now: opts.now,
    policy: opts.policy,
    logger: opts.logger,
    transactionId: opts.transactionId ?? "unspecified",
  };
  // Bind the signature-covered Groundmark-Claim (if presented) to the DNS-
  // authoritative claim set and the fetched attestation (binding steps 3–4).
  if (request.groundmarkClaim !== undefined) evalOpts.presentedClaim = request.groundmarkClaim;

  const attestations = await evaluateAttestations(request.agentDomain, evalOpts);

  return { ok: attestations.policySatisfied, request, attestations };
}
