/**
 * Stable failure-reason codes.
 *
 * The acceptance bar (instruction §4) requires asserting the SPECIFIC failure,
 * not merely that verification was rejected. Every rejection carries one of
 * these codes so tests can pin the intended check.
 *
 * Hygiene (instruction §7): error messages MUST NEVER include a `ref=` URL.
 * Reference claims by claim_type + subject only. These Level-0 codes touch no
 * `ref=` material; the attestation layer codes (added later) must uphold this.
 */
export type VerifyFailureReason =
  // --- RFC 9421 structure (C1) ---
  | "sig_input_missing"
  | "sig_missing"
  | "sig_input_malformed"
  | "sig_malformed"
  | "label_mismatch"
  | "missing_covered_component"
  | "missing_signature_param"
  // --- freshness / replay (C4) ---
  | "created_out_of_window"
  | "expires_in_past"
  | "nonce_missing"
  | "nonce_replayed"
  // --- body integrity (C4) ---
  | "content_digest_missing"
  | "content_digest_unsupported_alg"
  | "content_digest_mismatch"
  // --- DNS / key resolution (C2/C3) ---
  | "dnssec_validation_failed"
  | "agentid_not_found"
  | "agentid_ambiguous"
  | "agentid_missing_kid"
  | "agentid_duplicate_kid"
  | "agentid_malformed"
  | "unsupported_key_alg"
  | "keyid_no_match"
  | "alg_mismatch"
  // --- signature (C4) ---
  | "signature_invalid";

/** Internal control-flow error. Top-level verifiers convert this to a verdict. */
export class VerificationError extends Error {
  readonly reason: VerifyFailureReason;
  constructor(reason: VerifyFailureReason, message: string) {
    super(message);
    this.name = "VerificationError";
    this.reason = reason;
  }
}
