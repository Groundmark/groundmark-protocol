/**
 * Shared `_agentid` record parsing (core draft §4.1.1/§4.1.2), used for both
 * agent keys and IDSP signing keys.
 */

import { VerificationError } from "../errors.ts";

export interface AgentIdRecord {
  alg: string;
  publicKeyB64url: string;
  kid?: string;
  purpose?: string;
}

const KID_RE = /^[A-Za-z0-9._-]+$/;

/** Parse one `_agentid` record value. Throws agentid_malformed on any defect. */
export function parseAgentIdRecord(value: string): AgentIdRecord {
  const parts = value.split(";").map((p) => p.trim());
  if (parts[0] !== "v=gm1") {
    throw new VerificationError("agentid_malformed", "version tag v=gm1 must appear first");
  }
  let alg: string | undefined;
  let p: string | undefined;
  let kid: string | undefined;
  let purpose: string | undefined;
  const seen=new Set<string>();
  for (const part of parts.slice(1)) {
    if (part === "") throw new VerificationError("agentid_malformed", "empty parameter");
    const eq = part.indexOf("=");
    if (eq < 0) throw new VerificationError("agentid_malformed", "parameter without value");
    const key = part.slice(0, eq);
    const val = part.slice(eq + 1);
    if(seen.has(key)) throw new VerificationError("agentid_malformed","duplicate parameter");
    seen.add(key);
    if (key === "k") alg = val;
    else if (key === "p") p = val;
    else if (key === "kid") {
      if (!KID_RE.test(val)) throw new VerificationError("agentid_malformed", "invalid kid");
      kid = val;
    }
    else if (key === "purpose") purpose = val;
    // unknown ext-params are tolerated (forward compatibility)
  }
  if (alg === undefined) throw new VerificationError("agentid_malformed", "k= is required");
  if (p === undefined) throw new VerificationError("agentid_malformed", "p= is required");
  const rec: AgentIdRecord = { alg, publicKeyB64url: p };
  if (kid !== undefined) rec.kid = kid;
  if (purpose !== undefined) rec.purpose = purpose;
  return rec;
}

/** Apply the multi-record validity rules of §4.1.2. Throws on violation. */
export function assertMultiRecordValidity(records: AgentIdRecord[]): void {
  if (records.length <= 1) return;
  if (records.some((r) => r.kid === undefined)) {
    throw new VerificationError(
      "agentid_missing_kid",
      "multiple _agentid records present and at least one lacks kid=",
    );
  }
  const kids = new Set<string>();
  for (const r of records) {
    if (kids.has(r.kid!)) {
      throw new VerificationError("agentid_duplicate_kid", "multiple _agentid records share a kid=");
    }
    kids.add(r.kid!);
  }
}
