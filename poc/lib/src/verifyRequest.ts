/**
 * Component 4 — Request-signature verifier (Level 0 core).
 *
 * Implements the verification steps of core draft §5.5 in order:
 *   1. parse Signature-Input / Signature; confirm required components & params
 *   2. freshness: |created - now| <= 300s; expires (if present) in the future
 *   3. resolve the agent key via DNSSEC (keyid -> _agentid)
 *   4. verify Content-Digest against the body (bodied requests)
 *   5. reconstruct the signature base
 *   6. verify the Ed25519 signature
 *
 * Output of C1–C4 is a self-standing Level 0 verifier: it establishes that a
 * request came from a party controlling the DNSSEC-protected agent domain's key,
 * and nothing more.
 */

import type { DnssecResolver } from "./dns/resolver.ts";
import type { HttpRequestMessage } from "./rfc9421/message.ts";
import { parseHttpRequest } from "./rfc9421/message.ts";
import {
  parseSignatureInput,
  parseSignature,
  paramString,
  paramInteger,
  type SignatureInputEntry,
} from "./rfc9421/parse.ts";
import { buildSignatureBase } from "./rfc9421/signatureBase.ts";
import { verifyContentDigest } from "./rfc9421/contentDigest.ts";
import { resolveAgentKey, parseKeyId } from "./agent/keyResolver.ts";
import { verifyEd25519 } from "./crypto/ed25519.ts";
import { parseGroundmarkClaim, type PresentedClaim } from "./presentation/groundmarkClaim.ts";
import { VerificationError, type VerifyFailureReason } from "./errors.ts";

/** Replay-protection store for nonces (relying-party state, core §5.4). */
export interface NonceStore {
  /**
   * Atomically consume `nonce` if it has not been seen. Returns true only for the
   * one request that wins. `expiresAt` is a UNIX second expiry derived from the
   * signed request freshness window; implementations store only a nonce digest in
   * production.
   */
  consumeOnce(nonce: string, expiresAt: number): Promise<boolean>;
}

export interface VerifyRequestOptions {
  /** Current time as UNIX seconds. Injected so the suite can pin to signing time. */
  now: number;
  /** Max allowed |created - now| skew, seconds (default 300, per §5.4). */
  maxClockSkewSeconds?: number;
  /** Which signature label to verify. Defaults to the sole label present. */
  label?: string;
  /** Require a nonce parameter and enforce replay protection (§5.4, high-risk). */
  requireNonce?: boolean;
  /** Nonce store; required when requireNonce is set. */
  nonceStore?: NonceStore;
  /** Scheme for @target-uri when parsing a raw HTTP request (default "https"). */
  scheme?: string;
  /**
   * Presentation profile (holder spec §6): require a `Groundmark-Claim` header,
   * bound into the signature. Enforces the structural binding (present, covered,
   * parseable); the claim_type↔DNS and ref↔attestation checks run in the
   * attestation/policy layer (see evaluateAttestations).
   */
  requireGroundmarkClaim?: boolean;
}

export interface RequestVerdictOk {
  ok: true;
  agentDomain: string;
  keyid: string;
  kid?: string;
  created: number;
  expires?: number;
  /**
   * Signature-verified nonce. It is returned so a composite verifier can commit
   * it at the final acceptance boundary; callers MUST NOT log raw nonce values.
   */
  nonce?: string;
  /** Expiry to pass to NonceStore.consumeOnce for this nonce. */
  nonceExpiresAt?: number;
  /** DNS TTL (seconds) of the _agentid answer — the cache ceiling for this key. */
  ttl: number;
  /**
   * The parsed, signature-covered `Groundmark-Claim` (present only when the
   * presentation profile is active). Passed to the attestation layer for the
   * claim_type↔DNS and ref↔attestation binding checks.
   */
  groundmarkClaim?: PresentedClaim;
}

export interface RequestVerdictFail {
  ok: false;
  reason: VerifyFailureReason;
  message: string;
}

export type RequestVerdict = RequestVerdictOk | RequestVerdictFail;

const REQUIRED_DERIVED = ["@method", "@authority", "@target-uri"] as const;

/** Verify a parsed HTTP request message. */
export async function verifyRequestMessage(
  msg: HttpRequestMessage,
  resolver: DnssecResolver,
  opts: VerifyRequestOptions,
): Promise<RequestVerdict> {
  try {
    const verdict = await run(msg, resolver, opts, { commitNonce: true });
    return verdict;
  } catch (e) {
    if (e instanceof VerificationError) {
      return { ok: false, reason: e.reason, message: e.message };
    }
    throw e;
  }
}

/** Verify a raw HTTP/1.1 request (Buffer). */
export async function verifyRequest(
  raw: Buffer,
  resolver: DnssecResolver,
  opts: VerifyRequestOptions,
): Promise<RequestVerdict> {
  let msg: HttpRequestMessage;
  try {
    msg = parseHttpRequest(raw, opts.scheme !== undefined ? { scheme: opts.scheme } : {});
  } catch (e) {
    return { ok: false, reason: "sig_input_malformed", message: `malformed HTTP request: ${(e as Error).message}` };
  }
  return verifyRequestMessage(msg, resolver, opts);
}

/**
 * Internal top-level verifier entry point. It verifies the Level 0 request but
 * leaves a verified nonce uncommitted so the composite attestation/policy layer
 * can commit it immediately before returning final acceptance.
 */
export async function verifyRequestUncommitted(
  raw: Buffer,
  resolver: DnssecResolver,
  opts: VerifyRequestOptions,
): Promise<RequestVerdict> {
  let msg: HttpRequestMessage;
  try {
    msg = parseHttpRequest(raw, opts.scheme !== undefined ? { scheme: opts.scheme } : {});
  } catch (e) {
    return { ok: false, reason: "sig_input_malformed", message: `malformed HTTP request: ${(e as Error).message}` };
  }
  try {
    return await run(msg, resolver, opts, { commitNonce: false });
  } catch (e) {
    if (e instanceof VerificationError) {
      return { ok: false, reason: e.reason, message: e.message };
    }
    throw e;
  }
}

export async function commitRequestNonce(
  request: RequestVerdictOk,
  nonceStore: NonceStore | undefined,
): Promise<RequestVerdictFail | undefined> {
  if (request.nonce === undefined) return undefined;
  if (nonceStore === undefined) {
    throw new Error("verified request carried a nonce but no nonceStore was provided");
  }
  const expiresAt = request.nonceExpiresAt;
  if (expiresAt === undefined) {
    throw new Error("verified request carried a nonce without a nonce expiry");
  }
  const consumed = await nonceStore.consumeOnce(request.nonce, expiresAt);
  if (!consumed) {
    return { ok: false, reason: "nonce_replayed", message: "nonce has already been observed" };
  }
  return undefined;
}

async function run(
  msg: HttpRequestMessage,
  resolver: DnssecResolver,
  opts: VerifyRequestOptions,
  commit: { commitNonce: boolean },
): Promise<RequestVerdict> {
  const skew = opts.maxClockSkewSeconds ?? 300;

  // --- Step 1: parse and confirm structure (§5.5.1) ---
  const sigInputRaw = firstHeader(msg, "signature-input");
  if (sigInputRaw === undefined) {
    throw new VerificationError("sig_input_missing", "no Signature-Input header");
  }
  const sigRaw = firstHeader(msg, "signature");
  if (sigRaw === undefined) {
    throw new VerificationError("sig_missing", "no Signature header");
  }

  const { entries } = parseSignatureInput(sigInputRaw);
  const { signatures } = parseSignature(sigRaw);

  const label = selectLabel(entries, opts.label);
  const entry = entries.get(label)!;
  const signature = signatures.get(label);
  if (signature === undefined) {
    throw new VerificationError("label_mismatch", `Signature has no member for label "${label}"`);
  }

  const covered = new Set(entry.components.map((c) => c.name));
  for (const required of REQUIRED_DERIVED) {
    if (!covered.has(required)) {
      throw new VerificationError("missing_covered_component", `signature must cover ${required}`);
    }
  }
  const hasBody = msg.body !== undefined && msg.body.length > 0;
  if (hasBody && !covered.has("content-digest")) {
    throw new VerificationError("missing_covered_component", "bodied request must cover content-digest");
  }

  // --- Presentation profile: Groundmark-Claim structural binding (§6.1/§6.2) ---
  // Runs before signature verification so a missing/uncovered/malformed header is
  // reported with its specific reason rather than as a generic signature failure.
  let groundmarkClaim: PresentedClaim | undefined;
  if (opts.requireGroundmarkClaim) {
    const claimHeaders = msg.headers.get("groundmark-claim");
    if (claimHeaders === undefined || claimHeaders.length === 0) {
      throw new VerificationError("groundmark_claim_missing", "presentation requires a Groundmark-Claim header");
    }
    // Phase 0 permits exactly one presented claim. Multiple headers are rejected
    // rather than silently taking the first — the others would be unbound. NOTE:
    // multi-claim presentation is deferred to a later phase, which will define an
    // explicit signing rule (each header covered) and an RP selection rule.
    if (claimHeaders.length > 1) {
      throw new VerificationError(
        "groundmark_claim_duplicate",
        "multiple Groundmark-Claim headers present; exactly one is permitted in Phase 0",
      );
    }
    if (!covered.has("groundmark-claim")) {
      // Present but unsigned — it could have been injected/altered in transit.
      throw new VerificationError(
        "groundmark_claim_not_covered",
        "Groundmark-Claim header is not covered by the signature",
      );
    }
    groundmarkClaim = parseGroundmarkClaim(claimHeaders[0]!);
  }

  const created = paramInteger(entry.params, "created");
  if (created === undefined) {
    throw new VerificationError("missing_signature_param", "created parameter is required");
  }
  const keyidStr = paramString(entry.params, "keyid");
  if (keyidStr === undefined) {
    throw new VerificationError("missing_signature_param", "keyid parameter is required");
  }
  const algParam = paramString(entry.params, "alg");
  if (algParam === undefined) {
    throw new VerificationError("missing_signature_param", "alg parameter is required");
  }
  const expires = paramInteger(entry.params, "expires");

  // --- Step 2: freshness / replay (§5.5.2, §5.4) ---
  if (Math.abs(created - opts.now) > skew) {
    throw new VerificationError(
      "created_out_of_window",
      `created (${created}) is more than ${skew}s from now (${opts.now})`,
    );
  }
  if (expires !== undefined && expires <= opts.now) {
    throw new VerificationError("expires_in_past", `expires (${expires}) is not in the future`);
  }
  // A nonce is required/parsed here, but it is atomically consumed only at the
  // final acceptance boundary: here for Level 0-only verification, or by the
  // composite verifier after attestation policy succeeds.
  let verifiedNonce: string | undefined;
  let nonceExpiresAt: number | undefined;
  if (opts.requireNonce) {
    const nonce = paramString(entry.params, "nonce");
    if (nonce === undefined) {
      throw new VerificationError("nonce_missing", "nonce parameter is required by policy");
    }
    if (!opts.nonceStore) {
      throw new Error("requireNonce set but no nonceStore provided");
    }
    verifiedNonce = nonce;
    nonceExpiresAt = expires ?? created + skew;
  }

  // --- Step 3: resolve the agent key via DNSSEC (§5.5.3) ---
  const keyid = parseKeyId(keyidStr);
  const resolved = await resolveAgentKey(resolver, keyid);
  if (algParam !== resolved.alg) {
    throw new VerificationError(
      "alg_mismatch",
      `signature alg (${algParam}) does not match key algorithm (${resolved.alg})`,
    );
  }

  // --- Step 4: Content-Digest on bodied requests (§5.5.4, §5.3) ---
  if (hasBody) {
    const cd = firstHeader(msg, "content-digest");
    if (cd === undefined) {
      throw new VerificationError("content_digest_missing", "bodied request lacks Content-Digest");
    }
    verifyContentDigest(cd, msg.body!);
  }

  // --- Step 5: reconstruct the signature base (§5.5.5) ---
  const base = buildSignatureBase(entry, msg);

  // --- Step 6: verify the signature (§5.5.6) ---
  if (!verifyEd25519(resolved.publicKey, Buffer.from(base, "utf8"), signature)) {
    throw new VerificationError("signature_invalid", "Ed25519 signature verification failed");
  }

  const out: RequestVerdictOk = {
    ok: true,
    agentDomain: resolved.domain,
    keyid: keyidStr,
    created,
    ttl: resolved.ttl,
  };
  if (resolved.kid !== undefined) out.kid = resolved.kid;
  if (expires !== undefined) out.expires = expires;
  if (verifiedNonce !== undefined) out.nonce = verifiedNonce;
  if (nonceExpiresAt !== undefined) out.nonceExpiresAt = nonceExpiresAt;
  if (groundmarkClaim !== undefined) out.groundmarkClaim = groundmarkClaim;
  if (commit.commitNonce) {
    const nonceFailure = await commitRequestNonce(out, opts.nonceStore);
    if (nonceFailure !== undefined) return nonceFailure;
  }
  return out;
}

function firstHeader(msg: HttpRequestMessage, name: string): string | undefined {
  const v = msg.headers.get(name);
  return v && v.length > 0 ? v[0] : undefined;
}

function selectLabel(
  entries: Map<string, SignatureInputEntry>,
  requested: string | undefined,
): string {
  if (requested !== undefined) {
    if (!entries.has(requested)) {
      throw new VerificationError("label_mismatch", `no Signature-Input member for label "${requested}"`);
    }
    return requested;
  }
  if (entries.size !== 1) {
    throw new VerificationError(
      "sig_input_malformed",
      "multiple signatures present; specify which label to verify",
    );
  }
  return [...entries.keys()][0]!;
}
