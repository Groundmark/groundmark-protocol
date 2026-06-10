/**
 * Component 6 (part 1) — attestation payload types and structural validation
 * (attestation draft §6.2/§6.3).
 */

import { VerificationError } from "../errors.ts";

export interface MethodDisclosure {
  methods: string[];
  method_detail?: string;
  subcontractors?: string[];
  evidence_class?: string[];
}

export interface AttestationPayload {
  schema_version: string;
  subject: string;
  claim_type: string;
  claim_value: Record<string, unknown>;
  level: number;
  idsp: string;
  issued_at: string;
  expires_at: string;
  method_disclosure: MethodDisclosure;
  endpoint_url: string;
  revocation_endpoint: string;
  signing_key_id: string;
  signature: string;
  jurisdiction?: string;
  framework?: string;
  short_lived_token?: Record<string, unknown>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function reqString(o: Record<string, unknown>, key: string): string {
  const v = o[key];
  if (typeof v !== "string") {
    throw new VerificationError("attestation_malformed", `field ${key} must be a string`);
  }
  return v;
}

export interface ParsedAttestation {
  /** Typed, validated view used for field checks. */
  payload: AttestationPayload;
  /**
   * The raw parsed JSON object. Canonicalization for signature verification MUST
   * operate on this (minus `signature`), not the typed view — otherwise IDSP
   * fields outside our schema would be dropped and break the signature.
   */
  raw: Record<string, unknown>;
}

/** Parse and structurally validate an attestation payload (no crypto/policy). */
export function parseAttestation(body: Buffer): ParsedAttestation {
  let json: unknown;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch {
    throw new VerificationError("attestation_malformed", "attestation is not valid JSON");
  }
  if (!isObject(json)) {
    throw new VerificationError("attestation_malformed", "attestation must be a JSON object");
  }

  const level = json["level"];
  if (typeof level !== "number" || !Number.isInteger(level) || level < 0 || level > 3) {
    throw new VerificationError("attestation_malformed", "level must be an integer 0..3");
  }
  if (!isObject(json["claim_value"])) {
    throw new VerificationError("attestation_malformed", "claim_value must be an object");
  }
  const md = json["method_disclosure"];
  if (!isObject(md) || !Array.isArray(md["methods"]) || !md["methods"].every((m) => typeof m === "string")) {
    throw new VerificationError("attestation_malformed", "method_disclosure.methods must be an array of strings");
  }

  const payload: AttestationPayload = {
    schema_version: reqString(json, "schema_version"),
    subject: reqString(json, "subject"),
    claim_type: reqString(json, "claim_type"),
    claim_value: json["claim_value"] as Record<string, unknown>,
    level,
    idsp: reqString(json, "idsp"),
    issued_at: reqString(json, "issued_at"),
    expires_at: reqString(json, "expires_at"),
    method_disclosure: md as unknown as MethodDisclosure,
    endpoint_url: reqString(json, "endpoint_url"),
    revocation_endpoint: reqString(json, "revocation_endpoint"),
    signing_key_id: reqString(json, "signing_key_id"),
    signature: reqString(json, "signature"),
  };
  if (typeof json["jurisdiction"] === "string") payload.jurisdiction = json["jurisdiction"];
  if (typeof json["framework"] === "string") payload.framework = json["framework"];
  if (isObject(json["short_lived_token"])) payload.short_lived_token = json["short_lived_token"];
  return { payload, raw: json };
}
