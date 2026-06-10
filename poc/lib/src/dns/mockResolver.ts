/**
 * In-memory DnssecResolver for offline tests (instruction §4: the full suite
 * runs offline against fixture data; the live-DNS path is exercised separately).
 *
 * Construct it with the set of names that resolve "secure", and optionally a set
 * of names whose lookups should fail with a given DNSSEC status — this is how
 * the unsigned-zone / validation-failure cases are exercised at the resolver
 * layer (instruction §4) without a network.
 */

import type {
  DnssecResolver,
  DnssecStatus,
  TxtResolution,
} from "./resolver.ts";

function normalize(name: string): string {
  return name.replace(/\.$/, "").toLowerCase();
}

export interface MockEntry {
  records: string[];
  ttl?: number;
}

export class MockDnssecResolver implements DnssecResolver {
  private readonly secure = new Map<string, { records: string[]; ttl: number }>();
  private readonly failures = new Map<string, Exclude<DnssecStatus, "secure">>();
  /** Names looked up during the test, in order — useful for assertions. */
  readonly queries: string[] = [];

  setSecure(name: string, entry: MockEntry): this {
    this.secure.set(normalize(name), { records: entry.records, ttl: entry.ttl ?? 300 });
    return this;
  }

  /** Force a non-secure status for `name` (e.g. "insecure" for an unsigned zone). */
  setFailure(name: string, status: Exclude<DnssecStatus, "secure">): this {
    this.failures.set(normalize(name), status);
    return this;
  }

  async resolveTxt(name: string): Promise<TxtResolution> {
    const key = normalize(name);
    this.queries.push(key);
    const failure = this.failures.get(key);
    if (failure) return { status: failure, detail: `mock forced ${failure} for ${key}` };
    const hit = this.secure.get(key);
    if (hit) return { status: "secure", records: [...hit.records], ttl: hit.ttl };
    // Validated NODATA: no records at the name (still "secure").
    return { status: "secure", records: [], ttl: 300 };
  }
}
