/**
 * Groundmark relying-party verifier — public API.
 *
 * Level 0 core (components 1–4): given an HTTP request from an agent, verify it
 * came from a party controlling the DNSSEC-protected agent domain's signing key.
 * The attestation layer (components 5–9) builds on this and is added later.
 */

// Top-level entry point — Level 0 request + optional attestation policy
export { verifyAgentRequest } from "./verify.ts";
export type { VerifyAgentRequestOptions, GroundmarkVerdict } from "./verify.ts";

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

// Components 5–9 — attestation layer
export { resolveClaims } from "./claim/resolveClaims.ts";
export { parseAgentClaim } from "./claim/parseAgentClaim.ts";
export type { ClaimRecord, RefClaimRecord, ValClaimRecord } from "./claim/parseAgentClaim.ts";
export { parseAttestation } from "./attestation/payload.ts";
export type { AttestationPayload, MethodDisclosure } from "./attestation/payload.ts";
export { verifyAttestation } from "./attestation/verify.ts";
export type { AttestationVerifyContext } from "./attestation/verify.ts";
export { resolveIdspKey } from "./idsp/idspKeyResolver.ts";
export { checkRevocation } from "./revocation/revocation.ts";
export type {
  RevocationPolicy,
  AuditLogger,
  FailOpenAuditEntry,
} from "./revocation/revocation.ts";
export { computeCacheTtl, TtlCache } from "./cache/ttl.ts";
export { evaluateAttestations } from "./attestation/evaluate.ts";
export type {
  AttestationPolicy,
  AttestationVerdict,
  ClaimVerdict,
  ClaimBindingVerdict,
  EvaluateOptions,
} from "./attestation/evaluate.ts";

// Component 10 — Groundmark-Claim presentation header + binding
export { parseGroundmarkClaim } from "./presentation/groundmarkClaim.ts";
export type { PresentedClaim } from "./presentation/groundmarkClaim.ts";
export {
  MockHttpsFetcher,
  FetchUnavailable,
} from "./attestation/fetcher.ts";
export type { HttpsFetcher, FetchedResource } from "./attestation/fetcher.ts";

// Component 1 — RFC 9421 building blocks (exposed for advanced callers/tests)
export { parseSignatureInput, parseSignature } from "./rfc9421/parse.ts";
export { parseHttpRequest } from "./rfc9421/message.ts";
export type { HttpRequestMessage } from "./rfc9421/message.ts";
export { buildSignatureBase } from "./rfc9421/signatureBase.ts";

// Failure reasons
export { VerificationError } from "./errors.ts";
export type { VerifyFailureReason } from "./errors.ts";

// Building blocks for composite verifiers and issuance-side implementations.
// An IDSP verifying proof-of-possession, or a holder agent constructing a
// signed presentation, needs the same primitives the verifier is built from —
// exporting them keeps signer and verifier from drifting. The uncommitted
// entry point + commitRequestNonce pair exists precisely so a composite flow
// can consume the nonce at its own final acceptance boundary (see
// verifyRequest.ts).
export { verifyRequestUncommitted, commitRequestNonce } from "./verifyRequest.ts";
export { jcsBytes } from "./attestation/canonical.ts";
export { ed25519PublicKeyFromBase64url, verifyEd25519 } from "./crypto/ed25519.ts";
export { base64urlToBytes, bytesToBase64url, base64ToBytes } from "./encoding.ts";
export { parseAgentIdRecord, assertMultiRecordValidity } from "./dns/agentidRecord.ts";
export type { AgentIdRecord } from "./dns/agentidRecord.ts";
export type { SignatureInputEntry } from "./rfc9421/parse.ts";
