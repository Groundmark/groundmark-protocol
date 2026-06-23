/**
 * Minimal HTTP request representation for signature verification, plus a parser
 * for the raw HTTP/1.1 request fixtures (poc/fixtures/request/*.http).
 *
 * Note on `@target-uri` / scheme: an HTTP/1.1 request line carries only an
 * origin-form path, not the scheme or authority of the *effective request URI*
 * that RFC 9421 `@target-uri` requires. The scheme therefore cannot be recovered
 * from the wire bytes alone; the caller supplies it (default "https", which is
 * the only scheme Groundmark agents are expected to use). The authority comes
 * from the Host header.
 */

export interface HttpRequestMessage {
  method: string;
  /** Absolute effective request URI (used for @target-uri). */
  url: string;
  /** Authority (host[:port]); used for @authority. */
  authority: string;
  /** Lowercased field name -> ordered field line values. */
  headers: Map<string, string[]>;
  /** Raw request body, if any. */
  body?: Buffer;
}

export interface ParseHttpOptions {
  /** Scheme for the effective request URI. Defaults to "https". */
  scheme?: string;
}

/** Parse a raw HTTP/1.1 request (CRLF or LF line endings) into a message. */
export function parseHttpRequest(raw: Buffer, opts: ParseHttpOptions = {}): HttpRequestMessage {
  const scheme = opts.scheme ?? "https";
  // Split headers from body at the first blank line (CRLFCRLF or LFLF).
  const sep = findHeaderBodySeparator(raw);
  const headPart = raw.subarray(0, sep.headerEnd).toString("utf8");
  const body = sep.bodyStart < raw.length ? raw.subarray(sep.bodyStart) : undefined;

  const lines = headPart.split(/\r\n|\n/);
  const requestLine = lines.shift();
  if (!requestLine) throw new Error("empty HTTP request");
  const m = /^(\S+)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/.exec(requestLine.trim());
  if (!m) throw new Error(`malformed request line: ${requestLine}`);
  const method = m[1]!;
  const requestTarget = m[2]!;

  const headers = new Map<string, string[]>();
  for (const line of lines) {
    if (line.trim() === "") continue;
    const idx = line.indexOf(":");
    if (idx < 0) throw new Error(`malformed header line: ${line}`);
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    const existing = headers.get(name);
    if (existing) existing.push(value);
    else headers.set(name, [value]);
  }

  const hostValues = headers.get("host");
  const authority = hostValues && hostValues[0] ? hostValues[0].toLowerCase() : "";
  const url = `${scheme}://${authority}${requestTarget}`;

  const msg: HttpRequestMessage = { method, url, authority, headers };
  if (body !== undefined && body.length > 0) msg.body = body;
  return msg;
}

function findHeaderBodySeparator(raw: Buffer): { headerEnd: number; bodyStart: number } {
  for (let i = 0; i < raw.length - 1; i++) {
    if (raw[i] === 0x0a && raw[i + 1] === 0x0a) {
      return { headerEnd: i, bodyStart: i + 2 };
    }
    if (
      i < raw.length - 3 &&
      raw[i] === 0x0d && raw[i + 1] === 0x0a && raw[i + 2] === 0x0d && raw[i + 3] === 0x0a
    ) {
      return { headerEnd: i, bodyStart: i + 4 };
    }
  }
  return { headerEnd: raw.length, bodyStart: raw.length };
}
