/**
 * RFC 9530 Content-Digest verification.
 *
 * Content-Digest is an sf-dictionary mapping a hash-algorithm key to a
 * byte-sequence digest, e.g. `sha-256=:<base64>:`. Per core draft §5.3, sha-256
 * is mandatory to implement for verifiers; we verify the sha-256 entry against
 * the received body.
 */

import { createHash } from "node:crypto";
import { base64ToBytes } from "../encoding.ts";
import { VerificationError } from "../errors.ts";

const KEY_RE = /^[a-z][a-z0-9.-]*$/;

/** Parse a Content-Digest field value into algorithm -> digest bytes. */
export function parseContentDigest(value: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const memberRaw of value.split(",")) {
    const member = memberRaw.trim();
    if (member === "") continue;
    const eq = member.indexOf("=");
    if (eq < 0) {
      throw new VerificationError("content_digest_unsupported_alg", "malformed Content-Digest member");
    }
    const alg = member.slice(0, eq).trim().toLowerCase();
    const rest = member.slice(eq + 1).trim();
    if (!KEY_RE.test(alg)) {
      throw new VerificationError("content_digest_unsupported_alg", "malformed Content-Digest key");
    }
    if (rest.length < 2 || rest[0] !== ":" || rest[rest.length - 1] !== ":") {
      throw new VerificationError("content_digest_unsupported_alg", "Content-Digest value is not sf-binary");
    }
    out.set(alg, base64ToBytes(rest.slice(1, -1)));
  }
  return out;
}

/**
 * Verify a Content-Digest field value against the request body. Throws a
 * VerificationError with a specific reason on any failure.
 */
export function verifyContentDigest(fieldValue: string, body: Buffer): void {
  const digests = parseContentDigest(fieldValue);
  const expected = digests.get("sha-256");
  if (expected === undefined) {
    // No algorithm we support is present; we cannot confirm body integrity.
    throw new VerificationError(
      "content_digest_unsupported_alg",
      "Content-Digest carries no sha-256 entry",
    );
  }
  const actual = createHash("sha256").update(body).digest();
  if (actual.length !== expected.length || !actual.equals(expected)) {
    throw new VerificationError("content_digest_mismatch", "Content-Digest does not match body");
  }
}
