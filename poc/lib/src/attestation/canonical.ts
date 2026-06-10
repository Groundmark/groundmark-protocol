/**
 * RFC 8785 (JCS) canonicalization for attestation signatures.
 *
 * Per instruction §5, this uses a real, maintained JCS implementation
 * (`canonicalize`) rather than a hand-rolled serializer — the generator's
 * sort_keys shortcut is only valid for ASCII-keyed, float-free payloads, but the
 * library must be correct in general.
 */

import canonicalize from "canonicalize";

/**
 * Canonicalize `obj` per RFC 8785 and return the UTF-8 bytes. The attestation
 * signature is computed/verified over the canonical form of the payload with the
 * `signature` field removed (attestation draft §7).
 */
export function jcsBytes(obj: unknown): Buffer {
  const s = canonicalize(obj);
  if (typeof s !== "string") {
    throw new Error("JCS canonicalization produced no output");
  }
  return Buffer.from(s, "utf8");
}
