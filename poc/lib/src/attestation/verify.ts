/**
 * Components 6 + 7 (verification) — attestation validation and signature
 * verification per attestation draft §7.1, steps 1–7. Step 8 (revocation) is the
 * revocation engine (C8); the policy floor (step 4) is applied here per the
 * spec's ordering and again, holistically, by the verdict layer (C9).
 */

import type { DnssecResolver } from "../dns/resolver.ts";
import { parseAttestation, type AttestationPayload, type ParsedAttestation } from "./payload.ts";
import { jcsBytes } from "./canonical.ts";
import { resolveIdspKey } from "../idsp/idspKeyResolver.ts";
import { verifyEd25519 } from "../crypto/ed25519.ts";
import { base64urlToBytes } from "../encoding.ts";
import { VerificationError } from "../errors.ts";

const SUPPORTED_SCHEMA_VERSIONS = new Set(["1.0"]);

export interface AttestationVerifyContext {
  /** The agent domain the claim was resolved for; subject MUST equal this. */
  agentDomain: string;
  /** The ref= URL the attestation was fetched from; endpoint_url MUST equal this. */
  refUrl: string;
  /** Current time as UNIX seconds. */
  now: number;
  /** Policy level floor; attestation level MUST be >= this. */
  levelFloor: number;
  resolver: DnssecResolver;
}

/** RFC 3339 timestamp -> UNIX seconds; throws attestation_malformed if unparseable. */
function rfc3339Seconds(ts: string, field: string): number {
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) {
    throw new VerificationError("attestation_malformed", `${field} is not a valid RFC 3339 timestamp`);
  }
  return Math.floor(ms / 1000);
}

/**
 * Validate and cryptographically verify an attestation (steps 1–7). Returns the
 * verified payload; throws VerificationError with a specific reason on failure.
 */
export async function verifyAttestation(
  parsed: ParsedAttestation,
  ctx: AttestationVerifyContext,
): Promise<AttestationPayload> {
  const { payload, raw } = parsed;

  // Step 1: schema_version understood.
  if (!SUPPORTED_SCHEMA_VERSIONS.has(payload.schema_version)) {
    throw new VerificationError("unknown_schema_version", `unsupported schema_version ${payload.schema_version}`);
  }

  // Step 2: expires_at in the future (and issued_at well-formed).
  rfc3339Seconds(payload.issued_at, "issued_at");
  if (rfc3339Seconds(payload.expires_at, "expires_at") <= ctx.now) {
    throw new VerificationError("attestation_expired", "attestation expires_at is in the past");
  }

  // Step 3: endpoint_url binding (anti-portability, §9.1).
  if (payload.endpoint_url !== ctx.refUrl) {
    // Do NOT log either URL (§7): reference by claim_type + subject only.
    throw new VerificationError(
      "endpoint_mismatch",
      `endpoint_url does not match the ref it was served from (claim ${payload.claim_type} for ${payload.subject})`,
    );
  }

  // Subject binding: the attestation must be about the agent we resolved it for.
  if (payload.subject.toLowerCase() !== ctx.agentDomain.toLowerCase()) {
    throw new VerificationError(
      "wrong_subject",
      `subject (${payload.subject}) does not match agent domain (${ctx.agentDomain})`,
    );
  }

  // Step 4: policy level floor.
  if (payload.level < ctx.levelFloor) {
    throw new VerificationError(
      "below_policy_level",
      `attestation level ${payload.level} is below the policy floor ${ctx.levelFloor}`,
    );
  }

  // Step 5: resolve the IDSP signing key (DNSSEC required).
  const idspKey = await resolveIdspKey(ctx.resolver, payload.idsp, payload.signing_key_id);

  // Step 6: canonical serialization of the payload with `signature` removed.
  const { signature: _omit, ...unsigned } = raw;
  const canonical = jcsBytes(unsigned);

  // Step 7: verify the Ed25519 signature.
  let sigBytes: Buffer;
  try {
    sigBytes = base64urlToBytes(payload.signature);
  } catch {
    throw new VerificationError("attestation_signature_invalid", "signature is not valid base64url");
  }
  if (!verifyEd25519(idspKey, canonical, sigBytes)) {
    throw new VerificationError("attestation_signature_invalid", "attestation Ed25519 signature is invalid");
  }

  return payload;
}
