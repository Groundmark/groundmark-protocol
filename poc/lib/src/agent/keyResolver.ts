/**
 * Component 3 — Agent key resolver.
 *
 * Resolves `_agentid.<agent-domain>` through the DNSSEC-validating resolver and
 * returns the Ed25519 public key selected by the request's keyid, enforcing the
 * core draft's multi-record and `kid=` validity rules (§4.1.2, §5.2).
 */

import type { KeyObject } from "node:crypto";
import type { DnssecResolver } from "../dns/resolver.ts";
import { isSecure } from "../dns/resolver.ts";
import { parseAgentIdRecord, assertMultiRecordValidity, type AgentIdRecord } from "../dns/agentidRecord.ts";
import { ed25519PublicKeyFromBase64url } from "../crypto/ed25519.ts";
import { VerificationError } from "../errors.ts";

export interface ParsedKeyId {
  /** Agent FQDN, lowercased, no trailing dot. */
  domain: string;
  /** Opaque key id after `#`, if the FQDN#kid form was used. */
  kid?: string;
}

/** Parse a keyid signature parameter (core draft §5.2). */
export function parseKeyId(keyid: string): ParsedKeyId {
  const hash = keyid.indexOf("#");
  if (hash < 0) {
    return { domain: keyid.toLowerCase() };
  }
  const domain = keyid.slice(0, hash).toLowerCase();
  const kid = keyid.slice(hash + 1);
  if (domain === "" || kid === "") {
    throw new VerificationError("agentid_malformed", "malformed keyid");
  }
  return { domain, kid };
}

export interface ResolvedAgentKey {
  domain: string;
  alg: string;
  publicKey: KeyObject;
  kid?: string;
  /** Cache ceiling (seconds) from the DNS answer's TTL. */
  ttl: number;
}

/**
 * Resolve and select the agent signing key for a parsed keyid.
 *
 * Enforces, in order: DNSSEC ("secure") only; presence; multi-record validity
 * (every record needs a distinct kid); keyid-based selection (bare FQDN ⇒
 * exactly one record; FQDN#kid ⇒ match by kid); supported algorithm.
 */
export async function resolveAgentKey(
  resolver: DnssecResolver,
  keyid: ParsedKeyId,
): Promise<ResolvedAgentKey> {
  const name = `_agentid.${keyid.domain}`;
  const res = await resolver.resolveTxt(name);
  if (!isSecure(res)) {
    // §4.1.2: a response that fails DNSSEC validation MUST be an invalid identity.
    throw new VerificationError(
      "dnssec_validation_failed",
      `_agentid lookup not DNSSEC-secure (status=${res.status})`,
    );
  }
  if (res.records.length === 0) {
    throw new VerificationError("agentid_not_found", "no _agentid record at the label");
  }

  const records = res.records.map(parseAgentIdRecord);
  assertMultiRecordValidity(records); // §4.1.2

  // Key selection (§5.2).
  let selected: AgentIdRecord;
  if (keyid.kid === undefined) {
    // Bare FQDN form: valid only when exactly one record is present.
    if (records.length !== 1) {
      throw new VerificationError(
        "agentid_ambiguous",
        "bare-FQDN keyid but multiple _agentid records present (use FQDN#kid)",
      );
    }
    selected = records[0]!;
  } else {
    const match = records.find((r) => r.kid === keyid.kid);
    if (!match) {
      throw new VerificationError("keyid_no_match", "no _agentid record matches the keyid kid");
    }
    selected = match;
  }

  if (selected.alg !== "ed25519") {
    throw new VerificationError("unsupported_key_alg", `unsupported key algorithm: ${selected.alg}`);
  }

  let publicKey: KeyObject;
  try {
    publicKey = ed25519PublicKeyFromBase64url(selected.publicKeyB64url);
  } catch (e) {
    throw new VerificationError("agentid_malformed", `invalid public key: ${(e as Error).message}`);
  }

  const out: ResolvedAgentKey = {
    domain: keyid.domain,
    alg: selected.alg,
    publicKey,
    ttl: res.ttl,
  };
  if (selected.kid !== undefined) out.kid = selected.kid;
  return out;
}
