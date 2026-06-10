import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { MockDnssecResolver } from "../src/dns/mockResolver.ts";

const here = dirname(fileURLToPath(import.meta.url));
/** poc/ root (test/ is under poc/lib/test). */
export const POC_ROOT = join(here, "..", "..");

export function pocPath(...parts: string[]): string {
  return join(POC_ROOT, ...parts);
}

export function readPoc(...parts: string[]): Buffer {
  return readFileSync(pocPath(...parts));
}

export function readPocText(...parts: string[]): string {
  return readFileSync(pocPath(...parts), "utf8");
}

/** One TXT RR parsed from a zone fixture line. */
interface ZoneRecord {
  name: string;
  ttl: number;
  value: string;
}

const RR_RE = /^(\S+?)\.?\s+(\d+)\s+IN\s+TXT\s+"(.*)"\s*$/;

/** Parse a `poc/dns/*.txt` zone fixture into its TXT records. */
export function parseZoneFile(text: string): ZoneRecord[] {
  const out: ZoneRecord[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const m = RR_RE.exec(line);
    if (!m) throw new Error(`unparseable zone line: ${line}`);
    out.push({ name: m[1]!.toLowerCase(), ttl: Number(m[2]), value: m[3]! });
  }
  return out;
}

/**
 * Build a MockDnssecResolver pre-loaded with all `poc/dns/*.txt` fixtures —
 * the agent `_agentid`, IDSP `_agentid`, and agent `_agentclaim` records — each
 * resolving "secure" (DNSSEC-validated), grouping multiple RRs at one name.
 */
export function fixtureResolver(): MockDnssecResolver {
  const r = new MockDnssecResolver();
  const files = [
    "_agentid.agent.groundmark-poc.example.txt",
    "_agentid.idsp.groundmark-poc.example.txt",
    "_agentclaim.agent.groundmark-poc.example.txt",
  ];
  const byName = new Map<string, { records: string[]; ttl: number }>();
  for (const file of files) {
    for (const rr of parseZoneFile(readPocText("dns", file))) {
      const existing = byName.get(rr.name);
      if (existing) {
        existing.records.push(rr.value);
        existing.ttl = Math.min(existing.ttl, rr.ttl);
      } else {
        byName.set(rr.name, { records: [rr.value], ttl: rr.ttl });
      }
    }
  }
  for (const [name, entry] of byName) r.setSecure(name, entry);
  return r;
}
