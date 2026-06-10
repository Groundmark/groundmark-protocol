import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

import { MockDnssecResolver } from "../src/dns/mockResolver.ts";
import type { HttpRequestMessage } from "../src/rfc9421/message.ts";

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

// --- ephemeral signing, for parametric request-verifier tests --------------
// Private key material is generated at test time and never persisted (§7).

export interface SignRequestSpec {
  agentDomain: string;
  kid?: string;
  created: number;
  expires?: number;
  nonce?: string;
  method?: string;
  url?: string;
  authority?: string;
  body?: Buffer;
}

export interface SignedRequest {
  message: HttpRequestMessage;
  publicKeyB64url: string;
}

/** Build a validly signed HttpRequestMessage with a freshly generated key. */
export function signRequest(spec: SignRequestSpec): SignedRequest {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;

  const method = spec.method ?? "POST";
  const authority = (spec.authority ?? "api.supplier.example").toLowerCase();
  const url = spec.url ?? `https://${authority}/orders`;
  const body = spec.body;

  const headers = new Map<string, string[]>();
  headers.set("host", [authority]);

  const components: string[] = ['"@method"', '"@authority"', '"@target-uri"'];
  const baseLines: string[] = [
    `"@method": ${method.toUpperCase()}`,
    `"@authority": ${authority}`,
    `"@target-uri": ${url}`,
  ];

  if (body && body.length > 0) {
    const digest = createHash("sha256").update(body).digest().toString("base64");
    const cd = `sha-256=:${digest}:`;
    headers.set("content-type", ["application/json"]);
    headers.set("content-digest", [cd]);
    components.push('"content-digest"');
    baseLines.push(`"content-digest": ${cd}`);
  }

  const keyid = spec.kid ? `${spec.agentDomain}#${spec.kid}` : spec.agentDomain;
  let params = `${components.join(" ")});created=${spec.created}`;
  params = `(${params}`;
  if (spec.expires !== undefined) params += `;expires=${spec.expires}`;
  params += `;keyid="${keyid}";alg="ed25519"`;
  if (spec.nonce !== undefined) params += `;nonce="${spec.nonce}"`;

  baseLines.push(`"@signature-params": ${params}`);
  const base = baseLines.join("\n");
  const sig = cryptoSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64");

  headers.set("signature-input", [`gm=${params}`]);
  headers.set("signature", [`gm=:${sig}:`]);

  const message: HttpRequestMessage = { method, url, authority, headers };
  if (body && body.length > 0) message.body = body;
  return { message, publicKeyB64url: x };
}

/** A MockDnssecResolver publishing a single agent key (optionally with a kid). */
export function resolverForKey(agentDomain: string, publicKeyB64url: string, kid?: string): MockDnssecResolver {
  const rec = kid
    ? `v=gm1; k=ed25519; kid=${kid}; p=${publicKeyB64url}`
    : `v=gm1; k=ed25519; p=${publicKeyB64url}`;
  return new MockDnssecResolver().setSecure(`_agentid.${agentDomain}`, { records: [rec] });
}

export type { KeyObject };
