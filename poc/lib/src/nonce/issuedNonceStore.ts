/**
 * A NonceStore that accepts only nonces this relying party issued (core §5.5.2).
 *
 * The core draft says the relying party MUST issue an unpredictable nonce, and
 * the verifier consumes it atomically and once. A store that only checks "not
 * seen before" (consume-if-absent) accepts a nonce the agent made up itself,
 * so a signed request could be prepared in advance and still pass as fresh.
 * This store remembers each nonce it issues and accepts it only if it was
 * issued here, hasn't expired, and hasn't been used.
 *
 * It keeps a SHA-256 digest of each nonce, never the nonce itself. In-memory
 * and single-process: consumeOnce reads and deletes in one synchronous step, so
 * two concurrent requests can't both win. A deployment with several processes
 * needs the same semantics on shared storage (an atomic delete-if-present).
 */

import { createHash, randomBytes } from "node:crypto";
import type { NonceStore } from "../verifyRequest.ts";

/** Core §5.5.2: the nonce lifetime MUST be no more than 300 seconds. */
export const MAX_NONCE_LIFETIME_SECONDS = 300;

export interface IssuedNonceStoreOptions {
  /** Seconds a nonce stays usable after it is issued (default and maximum 300). */
  lifetimeSeconds?: number;
  /** Current time as UNIX seconds (injected for tests). */
  now?: () => number;
  /** Makes a nonce (injected for tests). Default: 128 random bits, base64url. */
  random?: () => string;
}

export interface IssuedNonce {
  nonce: string;
  /** UNIX seconds. */
  expiresAt: number;
}

const digest = (nonce: string): string => createHash("sha256").update(nonce).digest("base64url");

export class IssuedNonceStore implements NonceStore {
  private readonly issued = new Map<string, number>();
  private readonly lifetime: number;
  private readonly now: () => number;
  private readonly random: () => string;

  constructor(opts: IssuedNonceStoreOptions = {}) {
    const lifetime = opts.lifetimeSeconds ?? MAX_NONCE_LIFETIME_SECONDS;
    if (!(lifetime > 0 && lifetime <= MAX_NONCE_LIFETIME_SECONDS)) {
      throw new RangeError(`lifetimeSeconds must be in (0, ${MAX_NONCE_LIFETIME_SECONDS}]`);
    }
    this.lifetime = lifetime;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.random = opts.random ?? (() => randomBytes(16).toString("base64url"));
  }

  /** Issues a nonce, for the Accept-Signature `nonce` parameter of a challenge. */
  issue(): IssuedNonce {
    this.sweep();
    const nonce = this.random();
    const expiresAt = this.now() + this.lifetime;
    this.issued.set(digest(nonce), expiresAt);
    return { nonce, expiresAt };
  }

  /**
   * True only for a nonce issued here, unexpired and unused; it is then gone.
   * The request's own expiry is not used: the nonce's lifetime is this store's.
   */
  async consumeOnce(nonce: string, _expiresAt: number): Promise<boolean> {
    const key = digest(nonce);
    const expiresAt = this.issued.get(key);
    this.issued.delete(key);
    return expiresAt !== undefined && expiresAt > this.now();
  }

  /** Forgets expired nonces. issue() calls it; call it on a timer if issuing is rare. */
  sweep(): void {
    const t = this.now();
    for (const [key, expiresAt] of this.issued) if (expiresAt <= t) this.issued.delete(key);
  }

  /** How many issued nonces are still held (for tests and metrics). */
  get size(): number {
    return this.issued.size;
  }
}
