/**
 * Component 10 — `Groundmark-Claim` presentation header parser + binding.
 *
 * A holder agent presents an attestation by carrying a `Groundmark-Claim` header
 * (holder spec §6.1) and binding it into the RFC 9421 signature by listing
 * `groundmark-claim` among the covered components (§6.2). The verifier learns its
 * authoritative claim set from DNS (`_agentclaim`); this header is a binding +
 * optimization layer over that authoritative evaluation, NOT a replacement.
 *
 * Header format (holder spec §6.1):
 *   Groundmark-Claim: claim-type="<claim_type>"; ref="<ref-url>"
 *
 * The binding the verifier enforces (instruction §2):
 *   1. structural — header present and parseable
 *   2. covered    — `groundmark-claim` is in the signature's covered components,
 *                   so it could not have been added/modified in transit
 *   3. claim_type — matches at least one `_agentclaim` DNS record for the agent
 *   4. ref        — matches the `endpoint_url` of the fetched, verified attestation
 *
 * Hygiene (§7): the `ref=` value is a confidential bearer reference. It is carried
 * here for binding but MUST NEVER be logged; error detail strings reference the
 * claim_type only.
 */

import { VerificationError } from "../errors.ts";

export interface PresentedClaim {
  /** The asserted claim type, e.g. "operator-verified". */
  claimType: string;
  /** The attestation reference URL the holder asserts (confidential — never log). */
  ref: string;
}

// A single `key="value"` member; the value is a quoted string. `ref`'s URL value
// contains no `;`, so splitting members on `;` is correct (same caveat as the
// `_agentclaim` parser).
const MEMBER_RE = /^([A-Za-z][A-Za-z0-9-]*)="(.*)"$/;

/**
 * Parse a `Groundmark-Claim` header value into its claim_type and ref. Throws
 * `groundmark_claim_malformed` if the structure is not exactly the two quoted
 * members (unknown extra members are tolerated for forward-compatibility).
 */
export function parseGroundmarkClaim(value: string): PresentedClaim {
  let claimType: string | undefined;
  let ref: string | undefined;

  for (const segRaw of value.split(";")) {
    const seg = segRaw.trim();
    if (seg === "") continue;
    const m = MEMBER_RE.exec(seg);
    if (!m) {
      throw new VerificationError("groundmark_claim_malformed", "malformed Groundmark-Claim member");
    }
    const key = m[1]!.toLowerCase();
    const v = m[2]!;
    if (key === "claim-type") claimType = v;
    else if (key === "ref") ref = v;
    // unknown members tolerated (forward-compat)
  }

  if (claimType === undefined || claimType === "" || ref === undefined || ref === "") {
    throw new VerificationError(
      "groundmark_claim_malformed",
      "Groundmark-Claim must carry non-empty claim-type and ref",
    );
  }
  return { claimType, ref };
}
