/**
 * Component 5 (part 1) — `_agentclaim` record parsing (core draft §4.2).
 *
 * Two valid shapes:
 *   - ref-form: claim=, idsp=, ref=<https-url>, optional exp=
 *   - val-form: claim=, val=, optional exp=  (idsp/ref MUST NOT be present)
 * A record satisfying neither shape is IGNORED (returns null), not an error
 * (§4.2.2). Unrecognized claim= values are NOT rejected here; selecting which
 * claims matter is a policy-layer decision (§4.2.2 forward-compat rule).
 *
 * Hygiene (§7): the parsed ref URL is a confidential bearer reference. It is
 * carried in the returned record for fetching but MUST NEVER be logged.
 */

export interface RefClaimRecord {
  kind: "ref";
  claimType: string;
  idsp: string;
  ref: string;
  exp?: string;
}

export interface ValClaimRecord {
  kind: "val";
  claimType: string;
  value: string;
  exp?: string;
}

export type ClaimRecord = RefClaimRecord | ValClaimRecord;

/**
 * Parse a single `_agentclaim` TXT value. Returns the parsed record, or null if
 * the record does not satisfy a valid shape (and must be ignored).
 *
 * NOTE on the ABNF ambiguity: `ref=` (`https-url`) technically admits `;`, but
 * records are `;`-delimited. The fixtures (and the generator) never place `;` in
 * a URL, and `ref=` is not the trailing field, so `;`-splitting is correct here.
 * Flagged for the -01 drafts rather than worked around silently.
 */
export function parseAgentClaim(value: string): ClaimRecord | null {
  const parts = value.split(";").map((p) => p.trim());
  if (parts[0] !== "v=gm1") return null;

  let claim: string | undefined;
  let idsp: string | undefined;
  let ref: string | undefined;
  let val: string | undefined;
  let exp: string | undefined;

  for (const part of parts.slice(1)) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    if (eq < 0) return null; // malformed param -> ignore the record
    const key = part.slice(0, eq);
    const v = part.slice(eq + 1);
    switch (key) {
      case "claim": claim = v; break;
      case "idsp": idsp = v; break;
      case "ref": ref = v; break;
      case "val": val = v; break;
      case "exp": exp = v; break;
      // unknown ext-params tolerated
    }
  }

  if (claim === undefined || claim === "") return null;

  if (ref !== undefined) {
    // ref-form: idsp REQUIRED, val MUST NOT be present, ref MUST be https
    if (val !== undefined || idsp === undefined || idsp === "") return null;
    if (!ref.startsWith("https://")) return null;
    const rec: RefClaimRecord = { kind: "ref", claimType: claim, idsp, ref };
    if (exp !== undefined) rec.exp = exp;
    return rec;
  }

  if (val !== undefined) {
    // val-form: ref and idsp MUST NOT be present
    if (idsp !== undefined) return null;
    const rec: ValClaimRecord = { kind: "val", claimType: claim, value: val };
    if (exp !== undefined) rec.exp = exp;
    return rec;
  }

  // neither ref nor val -> ignore
  return null;
}
