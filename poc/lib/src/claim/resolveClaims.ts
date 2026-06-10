/**
 * Component 5 (part 2) — resolve `_agentclaim.<agent-domain>` records.
 *
 * Per core draft §4.2.2: a response that fails DNSSEC validation MUST be treated
 * as an ABSENT record (not an error) — so a non-secure status yields an empty
 * list, the same as no records. Records that do not parse to a valid shape are
 * silently ignored (§4.2.2). Multiple stacked claims are all returned.
 */

import type { DnssecResolver } from "../dns/resolver.ts";
import { isSecure } from "../dns/resolver.ts";
import { parseAgentClaim, type ClaimRecord } from "./parseAgentClaim.ts";

export async function resolveClaims(
  resolver: DnssecResolver,
  agentDomain: string,
): Promise<ClaimRecord[]> {
  const res = await resolver.resolveTxt(`_agentclaim.${agentDomain.toLowerCase()}`);
  if (!isSecure(res)) return []; // §4.2.2: not DNSSEC-secure -> absent
  const claims: ClaimRecord[] = [];
  for (const record of res.records) {
    const parsed = parseAgentClaim(record);
    if (parsed) claims.push(parsed);
  }
  return claims;
}
