/**
 * Component 2, concrete: the DnssecResolver chosen in docs/dnssec-resolver.md.
 * A validating resolver (Unbound, Knot Resolver) runs on loopback; this client
 * asks it for TXT records with DNSSEC OK (DO) set and trusts an answer only when
 * the resolver set AD (authenticated data).
 *
 * Node's `dns` module doesn't expose AD, so this speaks DNS wire format itself,
 * over TCP only: a UDP reply could be forged by any local process that guesses
 * the port and ID, and AD in a forged reply would mean nothing. Each answer must
 * echo the query's ID and question. The address must be loopback unless the
 * caller says the channel is otherwise authenticated.
 *
 * Mapping (docs/dnssec-resolver.md):
 *   AD=1, answer        -> secure, with the records and the lowest TTL
 *   AD=1, NODATA/NXDOMAIN -> secure, no records (validated non-existence)
 *   AD=0                -> insecure (unsigned zone, or not validated)
 *   SERVFAIL            -> bogus (what a validator returns when validation fails)
 *   other rcode, timeout, malformed or mismatched answer -> error
 */

import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import net from "node:net";
import type { DnssecResolver, DnssecStatus, TxtResolution } from "./resolver.ts";

const TYPE_TXT = 16;
const CLASS_IN = 1;
const MAX_ANSWER = 65535;

export interface LoopbackDnssecResolverOptions {
  /** The validating resolver's address (default 127.0.0.1). */
  host?: string;
  /** Default 53. */
  port?: number;
  /** Default 8000. */
  timeoutMs?: number;
  /**
   * Set only when the path to a non-loopback resolver is otherwise
   * authenticated (docs/dnssec-resolver.md: never a plaintext path to an
   * untrusted recursive resolver).
   */
  allowNonLoopback?: boolean;
}

/** What one lookup saw: the resolver contract's result plus the raw flags, for diagnostics. */
export type LookupDetail = TxtResolution & { rcode?: number; ad?: boolean };

const isLoopback = (host: string): boolean =>
  host === "localhost" || (isIP(host) === 4 && host.startsWith("127.")) || host === "::1";

function normalize(name: string): string {
  return name.replace(/\.$/, "").toLowerCase();
}

/** A TXT query with RD, AD and EDNS0 DO set (exported for tests). */
export function buildQuery(name: string, id: Buffer): Buffer {
  const labels = normalize(name).split(".");
  if (labels.some((l) => l.length === 0 || l.length > 63)) throw new Error(`bad name: ${name}`);
  const head = Buffer.from([id[0] ?? 0, id[1] ?? 0, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1]);
  const qname = Buffer.concat([
    ...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "latin1")])),
    Buffer.from([0]),
  ]);
  const question = Buffer.concat([qname, Buffer.from([0, TYPE_TXT, 0, CLASS_IN])]);
  // OPT RR: root name, type 41, UDP payload 1232, extended rcode/version 0, flags DO, no options.
  const opt = Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
  return Buffer.concat([head, question, opt]);
}

/** Reads a (possibly compressed) name; returns its labels and the offset after it in the record. */
function readName(buf: Buffer, start: number): [string[], number] {
  const labels: string[] = [];
  let off = start;
  let next = -1;
  for (let hops = 0; ; ) {
    const len = buf.readUInt8(off);
    if (len === 0) {
      if (next < 0) next = off + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (++hops > 20) throw new Error("too many compression pointers");
      if (next < 0) next = off + 2;
      off = ((len & 0x3f) << 8) | buf.readUInt8(off + 1);
      continue;
    }
    if (len > 63 || off + 1 + len > buf.length) throw new Error("bad label");
    labels.push(buf.subarray(off + 1, off + 1 + len).toString("latin1").toLowerCase());
    off += 1 + len;
  }
  return [labels, next];
}

/** Label by label, so a single label containing "." never equals several labels. */
const sameName = (a: string[], b: string[]): boolean => a.length === b.length && a.every((l, i) => l === b[i]);

/** Skips one resource record (bounds-checked); returns its owner, type, class, TTL, data and the next offset. */
function readRecord(buf: Buffer, start: number) {
  const [owner, off] = readName(buf, start);
  if (off + 10 > buf.length) throw new Error("truncated record");
  const type = buf.readUInt16BE(off);
  const cls = buf.readUInt16BE(off + 2);
  const ttl = buf.readUInt32BE(off + 4);
  const len = buf.readUInt16BE(off + 8);
  if (off + 10 + len > buf.length) throw new Error("truncated record data");
  return { owner, type, cls, ttl, data: buf.subarray(off + 10, off + 10 + len), next: off + 10 + len };
}

interface Parsed {
  rcode: number;
  ad: boolean;
  records: string[];
  ttl: number;
}

/** Parses an answer to `buildQuery(name, id)`; throws if it's malformed or answers something else. */
export function parseAnswer(buf: Buffer, id: Buffer, name: string): Parsed {
  if (buf.length < 12) throw new Error("short answer");
  if (buf.readUInt16BE(0) !== id.readUInt16BE(0)) throw new Error("answer to another query (ID)");
  const flags = buf.readUInt16BE(2);
  if (!(flags & 0x8000)) throw new Error("not a response");
  if ((flags >> 11) & 0x0f) throw new Error("not a standard query response (opcode)");
  if (flags & 0x0200) throw new Error("truncated response (TC)");
  const rcode = flags & 0x0f;
  const ad = Boolean(flags & 0x0020);
  if (buf.readUInt16BE(4) !== 1) throw new Error("answer must echo exactly one question");
  const ancount = buf.readUInt16BE(6);
  const nscount = buf.readUInt16BE(8);
  const arcount = buf.readUInt16BE(10);
  const want = normalize(name).split(".");
  const [qname, afterQ] = readName(buf, 12);
  if (afterQ + 4 > buf.length || !sameName(qname, want) || buf.readUInt16BE(afterQ) !== TYPE_TXT || buf.readUInt16BE(afterQ + 2) !== CLASS_IN) {
    throw new Error("answer to another question (name/type/class)");
  }
  let off = afterQ + 4;
  const records: string[] = [];
  let ttl = Number.POSITIVE_INFINITY;
  for (let i = 0; i < ancount; i++) {
    const { owner, type, cls, ttl: rrTtl, data, next } = readRecord(buf, off);
    off = next;
    // Only TXT at the asked name counts (a CNAME chain's other records, RRSIGs, etc. are skipped).
    if (type !== TYPE_TXT || cls !== CLASS_IN || !sameName(owner, want)) continue;
    let txt = "";
    for (let p = 0; p < data.length; ) {
      const l = data.readUInt8(p);
      if (p + 1 + l > data.length) throw new Error("bad TXT character-string");
      txt += data.subarray(p + 1, p + 1 + l).toString("utf8");
      p += 1 + l;
    }
    records.push(txt);
    ttl = Math.min(ttl, rrTtl);
  }
  // The authority and additional sections must be there as declared, and nothing after them.
  for (let i = 0; i < nscount + arcount; i++) off = readRecord(buf, off).next;
  if (off !== buf.length) throw new Error("bytes after the declared records");
  return { rcode, ad, records, ttl: ttl === Number.POSITIVE_INFINITY ? 0 : ttl };
}

export class LoopbackDnssecResolver implements DnssecResolver {
  private readonly host: string;
  private readonly port: number;
  private readonly timeoutMs: number;

  constructor(opts: LoopbackDnssecResolverOptions = {}) {
    this.host = opts.host ?? "127.0.0.1";
    this.port = opts.port ?? 53;
    this.timeoutMs = opts.timeoutMs ?? 8000;
    if (!isLoopback(this.host) && !opts.allowNonLoopback) {
      throw new Error(`${this.host} is not loopback: AD from a resolver over an unauthenticated path can't be trusted`);
    }
  }

  async resolveTxt(name: string): Promise<TxtResolution> {
    const r = await this.lookup(name);
    return r.status === "secure"
      ? { status: "secure", records: r.records, ttl: r.ttl }
      : { status: r.status, detail: r.detail };
  }

  /** Like resolveTxt, with the rcode and AD flag seen (for logs and diagnostics). */
  async lookup(name: string): Promise<LookupDetail> {
    const id = randomBytes(2);
    let p: Parsed;
    try {
      p = parseAnswer(await this.exchange(buildQuery(name, id)), id, name);
    } catch (e) {
      return { status: "error", detail: (e as Error).message };
    }
    const fail = (status: Exclude<DnssecStatus, "secure">, detail: string): LookupDetail => ({ status, detail, rcode: p.rcode, ad: p.ad });
    if (p.rcode === 2) return fail("bogus", "SERVFAIL from the validating resolver");
    if (p.rcode !== 0 && p.rcode !== 3) return fail("error", `rcode ${p.rcode}`);
    if (!p.ad) return fail("insecure", "answer not authenticated (AD not set): unsigned zone or not validated");
    return { status: "secure", records: p.rcode === 3 ? [] : p.records, ttl: p.ttl, rcode: p.rcode, ad: true };
  }

  /** One query over TCP (RFC 7766: two-byte length prefix). */
  private exchange(query: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const c = net.createConnection({ host: this.host, port: this.port }, () => {
        const len = Buffer.alloc(2);
        len.writeUInt16BE(query.length);
        c.write(Buffer.concat([len, query]));
      });
      let buf = Buffer.alloc(0);
      c.setTimeout(this.timeoutMs, () => c.destroy(new Error("DNS timeout")));
      c.on("data", (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        if (buf.length > MAX_ANSWER + 2) return void c.destroy(new Error("answer too long"));
        if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
          c.end();
          resolve(buf.subarray(2, 2 + buf.readUInt16BE(0)));
        }
      });
      c.on("error", reject);
      c.on("close", () => reject(new Error("connection closed before a full answer")));
    });
  }
}
