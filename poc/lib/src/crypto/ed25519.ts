/**
 * Ed25519 (RFC 8032) primitives via Node's native node:crypto (instruction §5:
 * native node:crypto is acceptable). The raw 32-byte public key from an
 * `_agentid` `p=` value is imported as an OKP JWK, which takes the base64url key
 * directly with no manual SPKI wrapping.
 */

import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { base64urlToBytes } from "../encoding.ts";

/** Build an Ed25519 public KeyObject from a base64url-encoded raw 32-byte key. */
export function ed25519PublicKeyFromBase64url(p: string): KeyObject {
  const raw = base64urlToBytes(p);
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  // JWK `x` is base64url without padding — re-encode the validated bytes.
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

/** Verify an Ed25519 signature over `message`. Ed25519 uses no prehash, so the
 *  algorithm argument to crypto.verify is null. */
export function verifyEd25519(key: KeyObject, message: Buffer, signature: Buffer): boolean {
  if (signature.length !== 64) return false;
  return verify(null, message, key, signature);
}
