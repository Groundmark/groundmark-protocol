/**
 * HTTPS fetch seam for attestation payloads and revocation responses.
 *
 * Mockable so the suite runs offline (instruction §4). A production fetcher MUST
 * validate TLS (attestation draft §6.1) and send no credentials — the ref= URL
 * is the only bearer reference. A transport failure (DNS/TLS/timeout/refused)
 * MUST throw `FetchUnavailable`; an HTTP response (including non-2xx) resolves
 * with its status so callers can distinguish "unreachable" from "404/410".
 *
 * Hygiene (§7): implementations MUST NOT log the requested URL.
 */

export interface FetchedResource {
  status: number;
  contentType?: string;
  body: Buffer;
  /** Parsed Cache-Control max-age in seconds, if present. */
  maxAge?: number;
}

/** Thrown when a resource could not be reached at all (vs. a non-2xx HTTP reply). */
export class FetchUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FetchUnavailable";
  }
}

export interface HttpsFetcher {
  get(url: string): Promise<FetchedResource>;
}

interface MockResource {
  status?: number;
  contentType?: string;
  body: Buffer;
  maxAge?: number;
}

/** In-memory fetcher: map URLs to resources; mark URLs as unreachable. */
export class MockHttpsFetcher implements HttpsFetcher {
  private readonly resources = new Map<string, MockResource>();
  private readonly unreachable = new Set<string>();

  setJson(url: string, obj: unknown, opts: { maxAge?: number; status?: number } = {}): this {
    const r: MockResource = {
      body: Buffer.from(JSON.stringify(obj)),
      contentType: "application/json",
    };
    if (opts.maxAge !== undefined) r.maxAge = opts.maxAge;
    if (opts.status !== undefined) r.status = opts.status;
    this.resources.set(url, r);
    return this;
  }

  setRaw(url: string, body: Buffer, opts: { contentType?: string; status?: number; maxAge?: number } = {}): this {
    const r: MockResource = { body };
    if (opts.contentType !== undefined) r.contentType = opts.contentType;
    if (opts.status !== undefined) r.status = opts.status;
    if (opts.maxAge !== undefined) r.maxAge = opts.maxAge;
    this.resources.set(url, r);
    return this;
  }

  setUnreachable(url: string): this {
    this.unreachable.add(url);
    return this;
  }

  async get(url: string): Promise<FetchedResource> {
    if (this.unreachable.has(url)) {
      throw new FetchUnavailable("mock: endpoint unreachable");
    }
    const r = this.resources.get(url);
    if (!r) throw new FetchUnavailable("mock: no resource configured");
    const out: FetchedResource = { status: r.status ?? 200, body: r.body };
    if (r.contentType !== undefined) out.contentType = r.contentType;
    if (r.maxAge !== undefined) out.maxAge = r.maxAge;
    return out;
  }
}
