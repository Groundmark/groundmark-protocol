/**
 * Groundmark relying-party verifier — public API.
 *
 * Level 0 core (components 1–4): given an HTTP request from an agent, verify it
 * came from a party controlling the DNSSEC-protected agent domain's signing key.
 * The attestation layer (components 5–9) builds on this and is added later.
 */

// Component 4 — request verification entry points
export { verifyRequest, verifyRequestMessage } from "./verifyRequest.ts";
export type {
  VerifyRequestOptions,
  RequestVerdict,
  RequestVerdictOk,
  RequestVerdictFail,
  NonceStore,
} from "./verifyRequest.ts";

// Component 2 — the resolver seam (supply a concrete implementation)
export type {
  DnssecResolver,
  TxtResolution,
  TxtRecordSet,
  TxtResolutionFailure,
  DnssecStatus,
} from "./dns/resolver.ts";
export { isSecure } from "./dns/resolver.ts";
export { MockDnssecResolver } from "./dns/mockResolver.ts";

// Component 3 — agent key resolution
export { resolveAgentKey, parseKeyId } from "./agent/keyResolver.ts";
export type { ResolvedAgentKey, ParsedKeyId } from "./agent/keyResolver.ts";

// Component 1 — RFC 9421 building blocks (exposed for advanced callers/tests)
export { parseSignatureInput, parseSignature } from "./rfc9421/parse.ts";
export { parseHttpRequest } from "./rfc9421/message.ts";
export type { HttpRequestMessage } from "./rfc9421/message.ts";
export { buildSignatureBase } from "./rfc9421/signatureBase.ts";

// Failure reasons
export { VerificationError } from "./errors.ts";
export type { VerifyFailureReason } from "./errors.ts";
