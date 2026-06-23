/**
 * Reconstruct the RFC 9421 signature base (§2.5) from a parsed Signature-Input
 * entry and the HTTP request message.
 *
 * One line per covered component (`<identifier>: <value>`), in the order given
 * by Signature-Input, followed by the `@signature-params` line whose value is
 * the verbatim inner-list serialization captured at parse time.
 */

import type { HttpRequestMessage } from "./message.ts";
import type { SignatureInputEntry } from "./parse.ts";
import { VerificationError } from "../errors.ts";

/** Resolve the value of a single covered component for the signature base. */
function componentValue(name: string, msg: HttpRequestMessage): string {
  if (name.startsWith("@")) {
    switch (name) {
      case "@method":
        return msg.method.toUpperCase();
      case "@authority":
        return msg.authority.toLowerCase();
      case "@target-uri":
        return msg.url;
      case "@scheme":
        return new URL(msg.url).protocol.replace(/:$/, "");
      case "@path":
        return new URL(msg.url).pathname;
      case "@query": {
        const q = new URL(msg.url).search;
        return q === "" ? "?" : q;
      }
      case "@request-target": {
        const u = new URL(msg.url);
        return `${u.pathname}${u.search}`;
      }
      default:
        throw new VerificationError(
          "missing_covered_component",
          `unsupported derived component: ${name}`,
        );
    }
  }
  // HTTP field: combine field-line values with ", " and trim OWS (RFC 9421 §2.1).
  const values = msg.headers.get(name);
  if (!values || values.length === 0) {
    throw new VerificationError(
      "missing_covered_component",
      `covered field not present in request: ${name}`,
    );
  }
  return values.map((v) => v.trim()).join(", ");
}

/** Build the signature base string for the given Signature-Input entry. */
export function buildSignatureBase(entry: SignatureInputEntry, msg: HttpRequestMessage): string {
  const lines: string[] = [];
  for (const component of entry.components) {
    lines.push(`${component.raw}: ${componentValue(component.name, msg)}`);
  }
  lines.push(`"@signature-params": ${entry.rawParamsValue}`);
  return lines.join("\n");
}
