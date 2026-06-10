/**
 * Component 8 (part 2) — cache TTL computation and a small TTL cache.
 *
 * Per core draft §9.1 / attestation draft §6.1, a cached resource's lifetime is
 * the LESSER of the DNS TTL, the HTTP Cache-Control max-age, and the time until
 * the attestation's `expires_at` — never exceeded (instruction §5).
 */

export interface CacheTtlInputs {
  now: number;
  /** DNS TTL in seconds, if the resource came with one. */
  dnsTtl?: number;
  /** HTTP Cache-Control max-age in seconds, if present. */
  maxAge?: number;
  /** Attestation expires_at as UNIX seconds, if applicable. */
  expiresAtSeconds?: number;
}

/** The cache ceiling (seconds), the minimum of all provided bounds; never < 0. */
export function computeCacheTtl(inputs: CacheTtlInputs): number {
  const bounds: number[] = [];
  if (inputs.dnsTtl !== undefined) bounds.push(inputs.dnsTtl);
  if (inputs.maxAge !== undefined) bounds.push(inputs.maxAge);
  if (inputs.expiresAtSeconds !== undefined) bounds.push(inputs.expiresAtSeconds - inputs.now);
  if (bounds.length === 0) return 0;
  return Math.max(0, Math.min(...bounds));
}

interface Entry<V> {
  value: V;
  /** Absolute expiry as UNIX seconds. */
  expiresAt: number;
}

/**
 * Minimal TTL cache. Time is injected (UNIX seconds) so behaviour is
 * deterministic and testable; callers pass the same clock used elsewhere.
 */
export class TtlCache<V> {
  private readonly store = new Map<string, Entry<V>>();

  get(key: string, now: number): V | undefined {
    const e = this.store.get(key);
    if (!e) return undefined;
    if (now >= e.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return e.value;
  }

  set(key: string, value: V, ttlSeconds: number, now: number): void {
    if (ttlSeconds <= 0) {
      this.store.delete(key);
      return;
    }
    this.store.set(key, { value, expiresAt: now + ttlSeconds });
  }

  get size(): number {
    return this.store.size;
  }
}
