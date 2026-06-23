/**
 * Component 1 — RFC 9421 HTTP Message Signatures parser.
 *
 * Scope: a focused Structured Field Values (RFC 8941) parser for the two
 * dictionary shapes Groundmark uses — `Signature-Input` (dictionary of inner
 * lists with parameters) and `Signature` (dictionary of byte sequences). The
 * instruction (§8/§7) blesses hand-built RFC 9421 parsing in lieu of a runtime
 * dependency; this parser is deliberately narrow and exhaustively tested rather
 * than a general SFV implementation.
 *
 * Key robustness choice: for the `@signature-params` line of the signature base
 * we DO NOT re-serialize the parsed structure (canonical SFV re-serialization is
 * the error-prone part). Instead we capture the verbatim value substring of the
 * chosen dictionary member and reuse it. RFC 9421 §2.3 defines the
 * `@signature-params` value as that exact serialization, so a verbatim copy is
 * correct by construction and immune to re-serialization drift.
 */

import { base64ToBytes } from "../encoding.ts";
import { VerificationError } from "../errors.ts";

export type SfValue =
  | { type: "integer"; value: number }
  | { type: "decimal"; value: number }
  | { type: "string"; value: string }
  | { type: "token"; value: string }
  | { type: "boolean"; value: boolean }
  | { type: "bytes"; value: Buffer };

export interface CoveredComponent {
  /** Lowercased bare component name, e.g. "@method", "content-digest". */
  name: string;
  /** Verbatim serialized identifier incl. any component params, e.g. `"@method"`. */
  raw: string;
}

export interface SignatureInputEntry {
  label: string;
  components: CoveredComponent[];
  params: Map<string, SfValue>;
  /** Verbatim inner-list-plus-parameters serialization — the `@signature-params` value. */
  rawParamsValue: string;
}

export interface ParsedSignatureInput {
  entries: Map<string, SignatureInputEntry>;
}

export interface ParsedSignature {
  /** label -> raw signature bytes (decoded from the sf-binary byte sequence). */
  signatures: Map<string, Buffer>;
}

// --- low-level splitting that respects quoted strings, byte seqs, and parens ---

/** Split `s` on top-level occurrences of `delim` (single char), honoring
 *  double-quoted strings (with `\` escapes), `:...:` byte sequences, and
 *  parenthesized inner lists. */
function splitTopLevel(s: string, delim: string): string[] {
  const out: string[] = [];
  let buf = "";
  let inStr = false;
  let inBytes = false;
  let escaped = false;
  let depth = 0;
  for (const ch of s) {
    if (inStr) {
      buf += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (inBytes) {
      buf += ch;
      if (ch === ":") inBytes = false;
      continue;
    }
    if (ch === '"') { inStr = true; buf += ch; continue; }
    if (ch === ":") { inBytes = true; buf += ch; continue; }
    if (ch === "(") { depth++; buf += ch; continue; }
    if (ch === ")") { depth--; buf += ch; continue; }
    if (ch === delim && depth === 0) { out.push(buf); buf = ""; continue; }
    buf += ch;
  }
  out.push(buf);
  return out;
}

const KEY_RE = /^[a-z*][a-z0-9._*-]*$/;

/** Split a dictionary into [label, rawValue] members, preserving verbatim values. */
function parseDictionaryMembers(
  raw: string,
  malformedReason: "sig_input_malformed" | "sig_malformed",
): Array<{ label: string; rawValue: string }> {
  const trimmed = raw.trim();
  if (trimmed === "") {
    throw new VerificationError(malformedReason, "empty structured field");
  }
  const members: Array<{ label: string; rawValue: string }> = [];
  for (const memberRaw of splitTopLevel(trimmed, ",")) {
    const member = memberRaw.trim();
    if (member === "") {
      throw new VerificationError(malformedReason, "empty dictionary member");
    }
    const eq = member.indexOf("=");
    if (eq < 0) {
      // A bare key (boolean true) is legal SFV but never valid in these fields.
      throw new VerificationError(malformedReason, "dictionary member without a value");
    }
    const label = member.slice(0, eq);
    if (!KEY_RE.test(label)) {
      throw new VerificationError(malformedReason, "invalid dictionary key");
    }
    members.push({ label, rawValue: member.slice(eq + 1) });
  }
  return members;
}

// --- parameter parsing ---

function parseQuotedString(s: string, reason: "sig_input_malformed" | "sig_malformed"): string {
  // s must start and end with an unescaped double quote.
  if (s.length < 2 || s[0] !== '"' || s[s.length - 1] !== '"') {
    throw new VerificationError(reason, "malformed quoted string");
  }
  let out = "";
  let escaped = false;
  for (let i = 1; i < s.length - 1; i++) {
    const ch = s[i]!;
    if (escaped) {
      if (ch !== '"' && ch !== "\\") {
        throw new VerificationError(reason, "invalid escape in quoted string");
      }
      out += ch;
      escaped = false;
    } else if (ch === "\\") {
      escaped = true;
    } else if (ch === '"') {
      throw new VerificationError(reason, "unescaped quote in quoted string");
    } else {
      out += ch;
    }
  }
  if (escaped) throw new VerificationError(reason, "dangling escape in quoted string");
  return out;
}

function parseBareValue(
  raw: string,
  reason: "sig_input_malformed" | "sig_malformed",
): SfValue {
  const s = raw.trim();
  if (s === "") throw new VerificationError(reason, "empty value");
  if (s[0] === '"') return { type: "string", value: parseQuotedString(s, reason) };
  if (s[0] === ":") {
    if (s.length < 2 || s[s.length - 1] !== ":") {
      throw new VerificationError(reason, "malformed byte sequence");
    }
    return { type: "bytes", value: base64ToBytes(s.slice(1, -1)) };
  }
  if (s[0] === "?") {
    if (s === "?1") return { type: "boolean", value: true };
    if (s === "?0") return { type: "boolean", value: false };
    throw new VerificationError(reason, "malformed boolean");
  }
  if (/^-?\d+$/.test(s)) {
    const value = Number(s);
    if (!Number.isSafeInteger(value)) {
      throw new VerificationError(reason, "integer out of safe range");
    }
    return { type: "integer", value };
  }
  if (/^-?\d+\.\d+$/.test(s)) return { type: "decimal", value: Number(s) };
  if (/^[a-zA-Z*][a-zA-Z0-9:/._*-]*$/.test(s)) return { type: "token", value: s };
  throw new VerificationError(reason, "unrecognized bare value");
}

/** Parse a leading `;k=v;k2;...` parameter string into a map. The string MUST
 *  begin with `;` or be empty. Returns parsed params. */
function parseParams(
  paramsRaw: string,
  reason: "sig_input_malformed" | "sig_malformed",
): Map<string, SfValue> {
  const params = new Map<string, SfValue>();
  if (paramsRaw === "") return params;
  if (paramsRaw[0] !== ";") {
    throw new VerificationError(reason, "trailing data after value");
  }
  for (const segRaw of splitTopLevel(paramsRaw.slice(1), ";")) {
    const seg = segRaw.trim();
    if (seg === "") throw new VerificationError(reason, "empty parameter");
    const eq = seg.indexOf("=");
    if (eq < 0) {
      if (!KEY_RE.test(seg)) throw new VerificationError(reason, "invalid parameter key");
      params.set(seg, { type: "boolean", value: true });
    } else {
      const key = seg.slice(0, eq);
      if (!KEY_RE.test(key)) throw new VerificationError(reason, "invalid parameter key");
      params.set(key, parseBareValue(seg.slice(eq + 1), reason));
    }
  }
  return params;
}

// --- public: Signature-Input ---

export function parseSignatureInput(raw: string): ParsedSignatureInput {
  const entries = new Map<string, SignatureInputEntry>();
  for (const { label, rawValue } of parseDictionaryMembers(raw, "sig_input_malformed")) {
    const v = rawValue.trim();
    if (v[0] !== "(") {
      throw new VerificationError("sig_input_malformed", "Signature-Input member is not an inner list");
    }
    const close = matchParen(v);
    if (close < 0) {
      throw new VerificationError("sig_input_malformed", "unterminated inner list");
    }
    const listBody = v.slice(1, close);
    const paramsRaw = v.slice(close + 1);
    const components = parseInnerList(listBody);
    const params = parseParams(paramsRaw, "sig_input_malformed");
    // rawParamsValue = verbatim inner-list + params; this IS the @signature-params value.
    entries.set(label, { label, components, params, rawParamsValue: v });
  }
  return { entries };
}

function matchParen(s: string): number {
  // s[0] === "(" guaranteed by caller; find its matching ")" honoring quotes/bytes.
  let inStr = false;
  let inBytes = false;
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (inStr) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (inBytes) {
      if (ch === ":") inBytes = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === ":") inBytes = true;
    else if (ch === ")" && i > 0) return i;
  }
  return -1;
}

function parseInnerList(body: string): CoveredComponent[] {
  const components: CoveredComponent[] = [];
  const trimmed = body.trim();
  if (trimmed === "") return components; // empty list is structurally legal
  for (const memberRaw of splitTopLevel(trimmed, " ")) {
    const member = memberRaw.trim();
    if (member === "") continue; // collapse runs of whitespace
    // member = quoted-string [ ;params ]
    if (member[0] !== '"') {
      throw new VerificationError("sig_input_malformed", "covered component is not a string");
    }
    // find the closing quote of the name
    let i = 1;
    let escaped = false;
    for (; i < member.length; i++) {
      const ch = member[i]!;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') break;
    }
    if (i >= member.length) {
      throw new VerificationError("sig_input_malformed", "unterminated component name");
    }
    const name = parseQuotedString(member.slice(0, i + 1), "sig_input_malformed");
    // validate any component params parse, but we don't interpret them here
    parseParams(member.slice(i + 1), "sig_input_malformed");
    components.push({ name: name.toLowerCase(), raw: member });
  }
  return components;
}

// --- public: Signature ---

export function parseSignature(raw: string): ParsedSignature {
  const signatures = new Map<string, Buffer>();
  for (const { label, rawValue } of parseDictionaryMembers(raw, "sig_malformed")) {
    const parsed = parseBareValue(rawValue, "sig_malformed");
    if (parsed.type !== "bytes") {
      throw new VerificationError("sig_malformed", "Signature member is not a byte sequence");
    }
    signatures.set(label, parsed.value);
  }
  return signatures.size === 0
    ? (() => { throw new VerificationError("sig_malformed", "no signatures"); })()
    : { signatures };
}

// --- typed param accessors ---

export function paramString(params: Map<string, SfValue>, key: string): string | undefined {
  const v = params.get(key);
  if (v === undefined) return undefined;
  if (v.type === "string" || v.type === "token") return v.value;
  return undefined;
}

export function paramInteger(params: Map<string, SfValue>, key: string): number | undefined {
  const v = params.get(key);
  if (v === undefined) return undefined;
  if (v.type === "integer") return v.value;
  return undefined;
}
