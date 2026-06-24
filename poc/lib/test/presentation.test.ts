import { test } from "node:test";
import assert from "node:assert/strict";

import { verifyAgentRequest } from "../src/verify.ts";
import type { VerifyAgentRequestOptions, GroundmarkVerdict } from "../src/verify.ts";
import type { NonceStore } from "../src/verifyRequest.ts";
import type { AuditLogger, FailOpenAuditEntry } from "../src/revocation/revocation.ts";
import type { VerifyFailureReason } from "../src/errors.ts";
import { fixtureResolver, fixtureFetcher, readPoc } from "./helpers.ts";

const IDSP = "idsp.groundmark-poc.example";
const OV_REF = `https://${IDSP}/a/vr7Z_bv-gKX0q0cz3wFgug`;
// The composite presentation vector was signed at this instant (created=...).
const PRES_NOW = 1747654321;

function newNonceStore(): NonceStore {
  const seen = new Set<string>();
  return { has: (n) => seen.has(n), add: (n) => void seen.add(n) };
}

function noopLogger(): AuditLogger {
  return { failOpen: (_e: FailOpenAuditEntry) => void 0 };
}

/** Standard presentation-profile verification options (one fresh nonce store each). */
function presentationOpts(over: Partial<VerifyAgentRequestOptions> = {}): VerifyAgentRequestOptions {
  return {
    resolver: fixtureResolver(),
    fetcher: fixtureFetcher(),
    now: PRES_NOW,
    policy: { levelFloor: 1, requiredClaimTypes: ["operator-verified"] },
    logger: noopLogger(),
    transactionId: "txn-presentation",
    requireGroundmarkClaim: true,
    requireNonce: true,
    nonceStore: newNonceStore(),
    ...over,
  };
}

function readPres(name: string): Buffer {
  return readPoc("fixtures", "presentation", name);
}

/** Assert the request layer rejected with a specific reason. */
function assertRequestFail(v: GroundmarkVerdict, reason: VerifyFailureReason) {
  assert.equal(v.ok, false, `expected request failure ${reason}, got ${JSON.stringify(v)}`);
  assert.equal(v.request.ok, false);
  if (v.request.ok === false) assert.equal(v.request.reason, reason);
}

test("good composite presentation: request verifies, claim bound, policy satisfied", async () => {
  const v = await verifyAgentRequest(readPres("presentation.http"), presentationOpts());
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.request.ok, true);
  if (v.request.ok) {
    // the signature-covered Groundmark-Claim was parsed and surfaced
    assert.deepEqual(v.request.groundmarkClaim, { claimType: "operator-verified", ref: OV_REF });
  }
  assert.equal(v.attestations?.policySatisfied, true);
  assert.equal(v.attestations?.binding?.ok, true);
  assert.equal(v.attestations?.binding?.claimType, "operator-verified");
});

test("adversarial: Groundmark-Claim header absent -> groundmark_claim_missing", async () => {
  const v = await verifyAgentRequest(readPres("missing-groundmark-claim-header.http"), presentationOpts());
  assertRequestFail(v, "groundmark_claim_missing");
});

test("adversarial: header present but not signature-covered -> groundmark_claim_not_covered", async () => {
  const v = await verifyAgentRequest(
    readPres("groundmark-claim-not-in-covered-components.http"),
    presentationOpts(),
  );
  assertRequestFail(v, "groundmark_claim_not_covered");
});

test("adversarial: nonce parameter absent -> nonce_missing", async () => {
  const v = await verifyAgentRequest(readPres("missing-nonce.http"), presentationOpts());
  assertRequestFail(v, "nonce_missing");
});

test("adversarial: claim_type matches no _agentclaim DNS record -> groundmark_claim_dns_mismatch", async () => {
  const v = await verifyAgentRequest(readPres("claim-type-dns-mismatch.http"), presentationOpts());
  // request layer is fine (header present, covered, parseable); the binding fails.
  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  assert.equal(v.attestations?.binding?.ok, false);
  assert.equal(v.attestations?.binding?.reason, "groundmark_claim_dns_mismatch");
});

test("adversarial: ref does not match the attestation endpoint_url -> groundmark_claim_ref_mismatch", async () => {
  const v = await verifyAgentRequest(readPres("ref-attestation-mismatch.http"), presentationOpts());
  assert.equal(v.request.ok, true);
  assert.equal(v.ok, false);
  assert.equal(v.attestations?.binding?.ok, false);
  assert.equal(v.attestations?.binding?.reason, "groundmark_claim_ref_mismatch");
});

test("adversarial: replayed presentation reusing a single-use nonce -> nonce_replayed", async () => {
  // One nonce store shared across both presentations, simulating the RP's replay state.
  const store = newNonceStore();
  const first = await verifyAgentRequest(readPres("presentation.http"), presentationOpts({ nonceStore: store }));
  assert.equal(first.ok, true, JSON.stringify(first));

  // nonce-replay.http is byte-identical to the good case: same single-use nonce.
  const replay = await verifyAgentRequest(readPres("nonce-replay.http"), presentationOpts({ nonceStore: store }));
  assertRequestFail(replay, "nonce_replayed");
});
