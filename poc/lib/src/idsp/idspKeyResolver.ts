/**
 * Component 7 (part 1) — IDSP signing-key resolver (attestation draft §7.1 step 5).
 *
 * Resolves `_agentid.<idsp>` via the DNSSEC seam (DNSSEC REQUIRED) and selects
 * the key whose `kid=` matches the attestation's `signing_key_id`. Reuses the
 * shared `_agentid` parsing and multi-record validity rules, mapping failures to
 * IDSP-specific reason codes.
 */

import type { KeyObject } from "node:crypto";
import type { DnssecResolver } from "../dns/resolver.ts";
import { isSecure } from "../dns/resolver.ts";
import { parseAgentIdRecord, assertMultiRecordValidity } from "../dns/agentidRecord.ts";
import { ed25519PublicKeyFromBase64url } from "../crypto/ed25519.ts";
import { VerificationError } from "../errors.ts";

export async function resolveIdspKey(
  resolver: DnssecResolver,
  idspDomain: string,
  signingKeyId: string,
): Promise<KeyObject> {
  const res = await resolver.resolveTxt(`_agentid.${idspDomain.toLowerCase()}`);
  if (!isSecure(res)) {
    // §7.1 step 5: reject if DNSSEC validation fails or the IDSP zone is unsigned.
    throw new VerificationError(
      "idsp_dnssec_validation_failed",
      `IDSP _agentid lookup not DNSSEC-secure (status=${res.status})`,
    );
  }
  if (res.records.length === 0) {
    throw new VerificationError("idsp_key_unresolved", "no _agentid record at the IDSP domain");
  }

  let records;
  try {
    records = res.records.map(parseAgentIdRecord);
    assertMultiRecordValidity(records);
  } catch {
    // Any malformed/invalid IDSP record set means the signing key is unusable.
    throw new VerificationError("idsp_key_unresolved", "IDSP _agentid record set is invalid");
  }

  const selected = records.find((r) => r.kid === signingKeyId);
  if (!selected) {
    throw new VerificationError(
      "signing_key_id_no_match",
      "no IDSP _agentid record matches the attestation signing_key_id",
    );
  }
  if (selected.alg !== "ed25519") {
    throw new VerificationError("idsp_key_unresolved", `unsupported IDSP key algorithm: ${selected.alg}`);
  }
  try {
    return ed25519PublicKeyFromBase64url(selected.publicKeyB64url);
  } catch (e) {
    throw new VerificationError("idsp_key_unresolved", `invalid IDSP public key: ${(e as Error).message}`);
  }
}
