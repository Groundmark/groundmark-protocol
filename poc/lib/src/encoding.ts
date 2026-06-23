/**
 * Encoding helpers.
 *
 * Two distinct base64 variants appear in Groundmark, and they MUST NOT be
 * confused (see poc/README "Two base64 variants"):
 *
 *  - base64url WITHOUT padding (RFC 4648 §5) — `_agentid` `p=`, the attestation
 *    `signature` field, and `kid`-adjacent material.
 *  - standard base64 (RFC 4648 §4, padded) — the RFC 9421 `Signature` value and
 *    RFC 9530 `Content-Digest` sf-binary, both serialized as `:<b64>:`.
 */

/** Decode base64url (padding optional/absent) to bytes. Rejects non-alphabet input. */
export function base64urlToBytes(s: string): Buffer {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) {
    throw new Error("invalid base64url");
  }
  // Buffer's base64url decoder tolerates missing padding.
  return Buffer.from(s, "base64url");
}

/** Encode bytes as base64url WITHOUT padding (RFC 4648). */
export function bytesToBase64url(b: Buffer): string {
  return b.toString("base64url");
}

/** Decode standard (padded) base64 to bytes. Rejects non-alphabet input. */
export function base64ToBytes(s: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error("invalid base64");
  }
  const out = Buffer.from(s, "base64");
  // Node's base64 decoder is lenient; round-trip to reject malformed input.
  if (out.toString("base64") !== withPadding(s)) {
    throw new Error("invalid base64");
  }
  return out;
}

function withPadding(s: string): string {
  const rem = s.length % 4;
  return rem === 0 ? s : s + "=".repeat(4 - rem);
}
